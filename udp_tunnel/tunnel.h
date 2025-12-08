#pragma once

#ifndef SAF_LEP_P2P_TUNNEL_H
#define SAF_LEP_P2P_TUNNEL_H

#include <boost/asio.hpp>
#include <boost/version.hpp>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <array>
#include <map>
#include <string>
#include <chrono>

#include "../lep/low_entropy_protocol.h"

#ifdef _WIN32
#include "windows_tap.h"
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

// packet data for long term storage
struct packet_storage
{
	std::vector<uint8_t> data;
	std::chrono::steady_clock::time_point tp;
};

// Connection state for a peer
struct peer_connection
{
	boost::asio::ip::udp::endpoint endpoint;
	uint32_t next_send_index = 0;
	uint32_t last_received_index = 0;
	std::mutex mutex;
	std::chrono::steady_clock::time_point last_seen = std::chrono::steady_clock::now();
	std::map<uint32_t, packet_storage> storage;

	bool is_connected = false;
};

// P2P Tunnel class - handles UDP communication with LEP encoding
class p2p_tunnel : public std::enable_shared_from_this<p2p_tunnel>
{
public:
	explicit p2p_tunnel(uint16_t local_port = 0);
	~p2p_tunnel();

	p2p_tunnel(const p2p_tunnel&) = delete;
	p2p_tunnel& operator=(const p2p_tunnel&) = delete;

	// Start the tunnel (async operations)
	void start();
	void stop();

	// Run the IO context (blocking)
	void run();
	void run_in_thread();

	// Send data to a specific peer (with LEP encoding)
	void send_to_peer_async(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& peer);

	// Broadcast to all connected peers
	void broadcast(const std::vector<uint8_t>& data);

	// Connect to a peer (for P2P establishment)
	void connect_to_peer(const std::string& address, const std::string& port);
	void connect_to_peer(const boost::asio::ip::udp::endpoint& endpoint);

	// Get local endpoint
	boost::asio::ip::udp::endpoint get_local_endpoint() const;

	// Set callbacks
	void set_packet_received_callback(packet_received_callback cb);
	void set_connection_callback(connection_callback cb);

	// Get connected peers
	std::vector<boost::asio::ip::udp::endpoint> get_connected_peers() const;

	// Check if peer is connected
	bool is_peer_connected(const boost::asio::ip::udp::endpoint& peer) const;

	static constexpr uint8_t PAC_RRQ = 19; // packet re-request
	static constexpr uint8_t PAC_LTR = 37; // packet less-than (that index was) recieved
	static constexpr uint8_t PAC_IWA = 45; // packet index wraparound (high index packet drop request)

private:
	void start_receive();
	void handle_receive(const boost::system::error_code& error, std::size_t bytes_transferred);
	void handle_send(const boost::system::error_code& error, std::size_t bytes_transferred,
		std::shared_ptr<std::vector<uint8_t>> buffer, const boost::asio::ip::udp::endpoint& target);

	void handle_fragmentation(peer_connection& peer, dixelu::lep::packet& decoded);
	void handle_control_packet(peer_connection& peer, dixelu::lep::packet& decoded);
	void send_control_packet(peer_connection& peer, uint8_t type, const std::vector<uint8_t>& extra_data = {});
	
	// Refactoring helpers
	void process_packet_gap(peer_connection& peer, uint32_t packet_id);
	void send_fragments(peer_connection& peer_conn, uint32_t packet_id, const std::vector<uint8_t>& data);
	
	peer_connection& get_or_create_peer(const boost::asio::ip::udp::endpoint& endpoint);
	void update_peer_activity(const boost::asio::ip::udp::endpoint& endpoint);

	boost::asio::io_context io_context_;
	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::resolver resolver_;
	boost::asio::ip::udp::endpoint local_endpoint_;

	std::array<uint8_t, 65507> receive_buffer_;
	boost::asio::ip::udp::endpoint remote_endpoint_;

	mutable std::recursive_mutex peers_mutex_;
	std::unordered_map<std::string, std::shared_ptr<peer_connection>> peers_;

	packet_received_callback packet_callback_;
	connection_callback connection_callback_;

	std::atomic<bool> running_{false};
	std::thread io_thread_;

	// Fragmentation support
	struct fragment_assembly
	{
		std::vector<uint8_t> data;
		size_t received_bytes = 0;
		size_t total_expected_bytes = 0;
		uint8_t total_frags = 0;
		uint8_t received_frags_count = 0;
		std::vector<uint8_t> received_frags_mask;
		std::chrono::steady_clock::time_point first_frag_time;
	};

	std::mutex reassembly_mutex_;
	std::unordered_map<std::string, fragment_assembly> reassembly_buffer_;
	std::atomic<uint32_t> next_packet_id_{0};

	static constexpr size_t MAX_FRAGMENT_SIZE = 150;

	static std::string endpoint_to_string(const boost::asio::ip::udp::endpoint& ep);
};

// VPN-like interface for packet forwarding
class vpn_interface
{
public:
	explicit vpn_interface(std::shared_ptr<p2p_tunnel> tunnel);
	~vpn_interface();

	// Start the VPN interface
	bool start(const std::string& ip, const std::string& mask, const std::string& gateway = "");
	void stop();

private:
	std::shared_ptr<p2p_tunnel> tunnel_;
#ifdef _WIN32
	std::unique_ptr<TapAdapter> tap_adapter_;
	boost::asio::ip::address_v4 local_ip_;
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