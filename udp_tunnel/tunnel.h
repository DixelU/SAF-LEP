#pragma once

#ifndef SAF_LEP_P2P_TUNNEL_H
#define SAF_LEP_P2P_TUNNEL_H

#include <array>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/version.hpp>
#include <chrono>
#include <functional>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../lep/encryption.h"
#include "../lep/low_entropy_protocol.h"

#ifdef _WIN32
#include "windows_tap.h"
#elif defined(__ANDROID__)
#include "android_tun.h"
#else
#include "linux_tun.h"
#endif

namespace dixelu
{
namespace udp
{

// Forward declaration
class p2p_tunnel;

// Callback types
using packet_received_callback = std::function<void(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from)>;
using connection_callback = std::function<void(const boost::asio::ip::udp::endpoint& peer)>;

// the data cover up encoding scheme
enum class encode_scheme
{
	lep_v0,
	lep_v1,
	raw,
};

// packet data for long term storage
struct packet_storage
{
	std::vector<uint8_t> data;
	std::chrono::steady_clock::time_point tp;
};

// Packet event types for watchscreen
enum class packet_event_type
{
	received,
	sent,
	lost,
	retransmit_requested,
	retransmitted,
	fragment_received,
	reassembled
};

// Single packet event for tracking
struct packet_event
{
	packet_event_type type;
	uint32_t packet_id;
	size_t bytes;
	std::chrono::steady_clock::time_point timestamp;
	std::string peer_info;
};

// Tunnel statistics for watchscreen
struct tunnel_stats
{
	std::atomic<uint64_t> bytes_sent{0};
	std::atomic<uint64_t> bytes_received{0};
	std::atomic<uint64_t> packets_sent{0};
	std::atomic<uint64_t> packets_received{0};
	std::atomic<uint64_t> packets_lost{0};
	std::atomic<uint64_t> retransmit_requests{0};

	// Diagnostics for the "8 MB/s on the wire, ~nothing on the socket" gap.
	// tap_bytes_in/out are measured at the TAP/TUN boundary (vpn_interface), which
	// the UDP socket counters above never see; broadcast_drops counts packets read
	// from the adapter that were discarded because no peer was connected.
	std::atomic<uint64_t> tap_bytes_in{0};
	std::atomic<uint64_t> tap_bytes_out{0};
	std::atomic<uint64_t> broadcast_drops{0};

	mutable std::mutex events_mutex;
	std::deque<packet_event> recent_events;
	static constexpr size_t MAX_EVENTS = 10;

	mutable std::mutex log_mutex;
	std::deque<std::string> log_lines;
	static constexpr size_t MAX_LOG_LINES = 8;

	void add_event(packet_event_type type, uint32_t packet_id, size_t bytes, const std::string& peer)
	{
		std::lock_guard<std::mutex> lock(events_mutex);
		recent_events.push_back({type, packet_id, bytes, std::chrono::steady_clock::now(), peer});
		while (recent_events.size() > MAX_EVENTS)
			recent_events.pop_front();
	}

	void add_log(const std::string& line)
	{
		std::lock_guard<std::mutex> lock(log_mutex);
		log_lines.push_back(line);
		while (log_lines.size() > MAX_LOG_LINES)
			log_lines.pop_front();
	}

	std::vector<packet_event> get_events() const
	{
		std::lock_guard<std::mutex> lock(events_mutex);
		return {recent_events.begin(), recent_events.end()};
	}

	std::vector<std::string> get_logs() const
	{
		std::lock_guard<std::mutex> lock(log_mutex);
		return {log_lines.begin(), log_lines.end()};
	}
};

struct fragment_assembly
{
	std::vector<uint8_t> data;
	size_t received_bytes = 0;
	size_t total_expected_bytes = 0;
	uint8_t total_frags = 0;
	uint8_t received_frags_count = 0;
	std::vector<uint8_t> received_frags_mask;
	std::chrono::steady_clock::time_point first_frag_time;
	std::chrono::steady_clock::time_point last_request_time;
	uint8_t request_count = 0;
};

// Connection state for a peer
struct peer_connection
{
	boost::asio::ip::udp::endpoint endpoint;
	uint32_t next_send_index = 0;
	uint32_t last_received_index = 0;
	std::mutex mutex;
	std::chrono::steady_clock::time_point last_seen = std::chrono::steady_clock::now();
	std::chrono::steady_clock::time_point last_probe_time = std::chrono::steady_clock::time_point{};
	std::map<uint32_t, std::vector<packet_storage>> storage;

	// Reassembly state (per peer)
	std::unordered_map<uint32_t, fragment_assembly> reassembly_buffer;
	std::set<uint32_t> reassembly_in_progress;
	std::set<uint32_t> late_reassembly;

	bool is_connected = false;
	// True for explicitly configured targets (connect_to_peer). Persistent peers
	// keep probing to reconnect and are never evicted; learned peers (discovered
	// from inbound datagrams) are evicted once silent so a NAT rebind or stray
	// packet cannot leave an immortal entry that re-probes forever.
	bool persistent = false;
};

// Base interface for all tunnel implementations
class tunnel_interface
{
public:
	virtual ~tunnel_interface() = default;
	virtual void start() = 0;
	virtual void stop() = 0;
	virtual void broadcast(const std::vector<uint8_t>& data) = 0;
	virtual void set_packet_received_callback(packet_received_callback cb) = 0;
	virtual tunnel_stats& get_stats() = 0;
	virtual const tunnel_stats& get_stats() const = 0;
	virtual void set_encryption_key(const std::string& key) = 0;
	virtual std::vector<boost::asio::ip::udp::endpoint> get_connected_peers() const = 0;
	virtual size_t get_peer_count() const = 0;
};

// P2P Tunnel class - handles UDP communication with LEP encoding
class p2p_tunnel : public tunnel_interface, public std::enable_shared_from_this<p2p_tunnel>
{
public:
	explicit p2p_tunnel(uint16_t local_port, encode_scheme scheme);
	~p2p_tunnel() override;

	p2p_tunnel(const p2p_tunnel&) = delete;
	p2p_tunnel& operator=(const p2p_tunnel&) = delete;

	// Start the tunnel (async operations)
	void start() override;
	void stop() override;

	// Run the IO context (blocking)
	void run();
	void run_in_thread();

	// Send data to a specific peer (with LEP encoding)
	void send_to_peer_async(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& peer);

	// Broadcast to all connected peers
	void broadcast(const std::vector<uint8_t>& data) override;

	// Connect to a peer (for P2P establishment)
	void connect_to_peer(const std::string& address, const std::string& port);
	void connect_to_peer(const boost::asio::ip::udp::endpoint& endpoint);

	// Get local endpoint
	boost::asio::ip::udp::endpoint get_local_endpoint() const;

#if defined(__ANDROID__)
	int get_socket_fd();
#endif

	// Set callbacks
	void set_packet_received_callback(packet_received_callback cb) override;
	void set_connection_callback(connection_callback cb);

	// Set encryption key from seed string
	void set_encryption_key(const std::string& seed_key) override;

	// Get connected peers
	std::vector<boost::asio::ip::udp::endpoint> get_connected_peers() const override;

	// Total peer_connection entries (connected + lingering). A gap between this and
	// the connected count reveals zombie/rebind churn.
	size_t get_peer_count() const override;

	// Check if peer is connected
	bool is_peer_connected(const boost::asio::ip::udp::endpoint& peer) const;

	// Get statistics for watchscreen
	tunnel_stats& get_stats() override { return stats_; }
	const tunnel_stats& get_stats() const override { return stats_; }

	static constexpr uint8_t PAC_RRQ = 19; // packet re-request
	static constexpr uint8_t PAC_LTR = 37; // packet less-than (that index was) recieved
	static constexpr uint8_t PAC_IWA = 45; // packet index wraparound (high index packet drop request)
	static constexpr uint8_t PAC_LST = 72; // packet was lost - (answer to RRQ)

private:
	void start_receive();
	void start_maintenance();
	void handle_receive(const boost::system::error_code& error, std::size_t bytes_transferred);
	void handle_maintenance(const boost::system::error_code& error);
	void handle_send(const boost::system::error_code& error, std::size_t bytes_transferred,
		std::shared_ptr<std::vector<uint8_t>> buffer, const boost::asio::ip::udp::endpoint& target);

	void handle_fragmentation(peer_connection& peer, dixelu::lep::packet& decoded);
	void handle_control_packet(peer_connection& peer, dixelu::lep::packet& decoded);
	void send_control_packet(peer_connection& peer, uint8_t type, const std::vector<uint8_t>& extra_data = {});
	void send_raw_control(peer_connection& peer, std::vector<uint8_t> payload);
	void handle_long_control_packet(peer_connection& peer, dixelu::lep::packet& decoded);

	void internal_cleanup_procedure(peer_connection& peer);
	void run_peer_maintenance(peer_connection& peer);
	void reset_peer_session_locked(peer_connection& peer);
	
	// Refactoring helpers
	void process_packet_gap(peer_connection& peer, uint32_t packet_id);
	void send_fragments(peer_connection& peer_conn, uint32_t packet_id, const std::vector<uint8_t>& data);
	
	peer_connection& get_or_create_peer(const boost::asio::ip::udp::endpoint& endpoint);
	void update_peer_activity(const boost::asio::ip::udp::endpoint& endpoint);

	const encode_scheme scheme_;

	boost::asio::io_context io_context_;
	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::resolver resolver_;
	boost::asio::steady_timer maintenance_timer_;
	boost::asio::ip::udp::endpoint local_endpoint_;

	std::array<uint8_t, 65507> receive_buffer_;
	boost::asio::ip::udp::endpoint remote_endpoint_;

	mutable std::recursive_mutex peers_mutex_;
	std::unordered_map<std::string, std::shared_ptr<peer_connection>> peers_;

	packet_received_callback packet_callback_;
	connection_callback connection_callback_;

	std::atomic<bool> running_{false};
	std::thread io_thread_;

	std::atomic<uint32_t> next_packet_id_{0};
	uint32_t reassembly_timeout_{10};
	uint32_t max_reassembly_lifetime_{45};
	uint32_t peer_silence_timeout_{15};
	uint32_t reconnect_probe_interval_{5};
	uint32_t peer_eviction_timeout_{60}; // drop silent, non-persistent peers after this many seconds

	static constexpr size_t MAX_FRAGMENT_SIZE = 150;

	static std::string endpoint_to_string(const boost::asio::ip::udp::endpoint& ep);

	// Encryption key (derived from seed)
	std::array<uint8_t, lep::crypto::KEY_SIZE> encryption_key_{};

	// Statistics for watchscreen
	tunnel_stats stats_;
};

// VPN-like interface for packet forwarding
class vpn_interface
{
public:
	explicit vpn_interface(std::shared_ptr<tunnel_interface> tunnel);
	~vpn_interface();

	// Start the VPN interface (desktop platforms)
	bool start(const std::string& ip, const std::string& mask, const std::string& gateway = "");

#if defined(__ANDROID__)
	// Start the VPN interface with pre-opened TUN file descriptor (Android)
	// @param tun_fd File descriptor from VpnService.Builder.establish()
	// @return true if successful
	bool start_android(int tun_fd);
#endif

	void stop();

private:
	std::shared_ptr<tunnel_interface> tunnel_;
#ifdef _WIN32
	std::unique_ptr<TapAdapter> tap_adapter_;
	boost::asio::ip::address_v4 local_ip_;
#elif defined(__ANDROID__)
	std::unique_ptr<AndroidTunAdapter> tun_adapter_;
#else
	std::unique_ptr<TunAdapter> tun_adapter_;
#endif
	std::atomic<bool> running_{false};
	std::thread read_thread_;

	void read_from_tap();
	void handle_tunnel_packet(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from);

	void handle_arp(const std::vector<uint8_t>& packet);

};

} // namespace udp
} // namespace dixelu

#endif //SAF_LEP_P2P_TUNNEL_H
