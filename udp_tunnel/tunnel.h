#pragma once

#ifndef SAF_LEP_P2P_TUNNEL_H
#define SAF_LEP_P2P_TUNNEL_H

#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <array>
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

// Connection state for a peer
struct peer_connection
{
	boost::asio::ip::udp::endpoint endpoint;
	uint16_t next_send_index = 0;
	uint16_t expected_receive_index = 0;
	std::mutex mutex;
	std::chrono::steady_clock::time_point last_seen = std::chrono::steady_clock::now();
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
	void send_to_peer(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& peer);
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

private:
	void start_receive();
	void handle_receive(const boost::system::error_code& error, std::size_t bytes_transferred);
	void handle_send(const boost::system::error_code& error, std::size_t bytes_transferred,
		std::shared_ptr<std::vector<uint8_t>> buffer, const boost::asio::ip::udp::endpoint& target);

	peer_connection& get_or_create_peer(const boost::asio::ip::udp::endpoint& endpoint);
	void update_peer_activity(const boost::asio::ip::udp::endpoint& endpoint);

	boost::asio::io_service io_context_; // Changed from io_context to io_service for Boost 1.65 compatibility
	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::resolver resolver_;
	boost::asio::ip::udp::endpoint local_endpoint_;

	std::array<uint8_t, 65507> receive_buffer_;
	boost::asio::ip::udp::endpoint remote_endpoint_;

	mutable std::mutex peers_mutex_;
	std::unordered_map<std::string, std::shared_ptr<peer_connection>> peers_;

	packet_received_callback packet_callback_;
	connection_callback connection_callback_;

	std::atomic<bool> running_{false};
	std::thread io_thread_;

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
#else
	std::unique_ptr<TunAdapter> tun_adapter_;
#endif
	std::atomic<bool> running_{false};
	std::thread read_thread_;

	void read_from_tap();
	void handle_tunnel_packet(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from);
};

} // namespace udp
} // namespace dixelu

#endif //SAF_LEP_P2P_TUNNEL_H