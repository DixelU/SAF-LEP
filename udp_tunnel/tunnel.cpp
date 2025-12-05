#include "tunnel.h"
#include <chrono>
#include <algorithm>
#include <print>

namespace dixelu
{
namespace udp
{

std::string p2p_tunnel::endpoint_to_string(const boost::asio::ip::udp::endpoint& ep)
{
	return ep.address().to_string() + ":" + std::to_string(ep.port());
}

p2p_tunnel::p2p_tunnel(uint16_t local_port)
	: socket_(io_context_)
	, resolver_(io_context_)
	, local_endpoint_(boost::asio::ip::udp::v4(), local_port)
{
	boost::system::error_code ec;
	socket_.open(boost::asio::ip::udp::v4(), ec);
	if (ec)
	{
		std::println(stderr, "Failed to open socket: {}", ec.message());
		return;
	}

	socket_.bind(local_endpoint_, ec);
	if (ec)
	{
		std::println(stderr, "Failed to bind socket: {}", ec.message());
		return;
	}

	local_endpoint_ = socket_.local_endpoint();
}

p2p_tunnel::~p2p_tunnel()
{
	stop();
}

void p2p_tunnel::start()
{
	if (running_.exchange(true))
		return;

	start_receive();
}

void p2p_tunnel::stop()
{
	if (!running_.exchange(false))
		return;

	boost::system::error_code ec;
	socket_.cancel(ec);
	socket_.close(ec);

	if (io_thread_.joinable())
	{
		io_context_.stop();
		io_thread_.join();
	}
}

void p2p_tunnel::run()
{
	io_context_.run();
}

void p2p_tunnel::run_in_thread()
{
	if (io_thread_.joinable())
		return;

	io_thread_ = std::thread([this]() {
		io_context_.run();
	});
}

void p2p_tunnel::start_receive()
{
	if (!running_)
		return;

	socket_.async_receive_from(
		boost::asio::buffer(receive_buffer_),
		remote_endpoint_,
		[this](const boost::system::error_code& error, std::size_t bytes_transferred) {
			handle_receive(error, bytes_transferred);
		});
}

void p2p_tunnel::handle_receive(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (error)
	{
		if (error != boost::asio::error::operation_aborted && running_)
		{
			std::println(stderr, "Receive error: {}", error.message());
		}
		return;
	}

	if (bytes_transferred == 0)
	{
		start_receive();
		return;
	}

	// Update peer activity
	update_peer_activity(remote_endpoint_);

	// Decode LEP packet
	try
	{
		auto decoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::decode(
			receive_buffer_.data(), bytes_transferred);

		// Check if this is a new connection
		auto& peer = get_or_create_peer(remote_endpoint_);
		{
			std::lock_guard<std::mutex> lock(peer.mutex);
			if (!peer.is_connected)
			{
				peer.is_connected = true;
				if (connection_callback_)
				{
					connection_callback_(remote_endpoint_);
				}
			}
		}

		// Call packet callback
		if (packet_callback_ && !decoded.data.empty())
		{
			packet_callback_(decoded.data, remote_endpoint_);
		}
	}
	catch (const std::exception& e)
	{
		std::println(stderr, "LEP decode error: {}", e.what());
	}

	// Continue receiving
	start_receive();
}

void p2p_tunnel::send_to_peer(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& peer)
{
	if (data.empty())
		return;

	// Get or create peer connection
	auto& peer_conn = get_or_create_peer(peer);

	// Encode with LEP
	uint16_t index;
	{
		std::lock_guard<std::mutex> lock(peer_conn.mutex);
		index = peer_conn.next_send_index++;
	}

	auto encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::encode(
		data.data(), data.size(), index);

	if (encoded.empty())
	{
		std::println(stderr, "LEP encode failed");
		return;
	}

	// Send synchronously
	boost::system::error_code ec;
	socket_.send_to(boost::asio::buffer(encoded), peer, 0, ec);
	if (ec)
	{
		std::println(stderr, "Send error: {}", ec.message());
	}
}

void p2p_tunnel::send_to_peer_async(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& peer)
{
	if (data.empty())
		return;

	// Get or create peer connection
	auto& peer_conn = get_or_create_peer(peer);

	// Encode with LEP
	uint16_t index;
	{
		std::lock_guard<std::mutex> lock(peer_conn.mutex);
		index = peer_conn.next_send_index++;
	}

	auto encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::encode(
		data.data(), data.size(), index);

	if (encoded.empty())
	{
		std::println(stderr, "LEP encode failed");
		return;
	}

	// Create shared buffer for async operation
	auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(encoded));

	socket_.async_send_to(
		boost::asio::buffer(*buffer),
		peer,
		[this, buffer, peer](const boost::system::error_code& error, std::size_t bytes_transferred) {
			handle_send(error, bytes_transferred, buffer, peer);
		});
}

void p2p_tunnel::handle_send(const boost::system::error_code& error, std::size_t bytes_transferred,
	std::shared_ptr<std::vector<uint8_t>> buffer, const boost::asio::ip::udp::endpoint& target)
{
	if (error)
	{
		std::println(stderr, "Async send error to {}: {}", endpoint_to_string(target), error.message());
	}
}

void p2p_tunnel::broadcast(const std::vector<uint8_t>& data)
{
	std::lock_guard<std::mutex> lock(peers_mutex_);
	for (const auto& [key, peer] : peers_)
	{
		if (peer->is_connected)
		{
			send_to_peer_async(data, peer->endpoint);
		}
	}
}

void p2p_tunnel::connect_to_peer(const std::string& address, const std::string& port)
{
	resolver_.async_resolve(
		boost::asio::ip::udp::v4(),
		address,
		port,
		[this](const boost::system::error_code& ec, boost::asio::ip::udp::resolver::results_type results) {
			if (ec)
			{
				std::println(stderr, "Resolve error: {}", ec.message());
				return;
			}

			if (results.empty())
			{
				std::println(stderr, "No endpoints resolved");
				return;
			}

			connect_to_peer(*results.begin());
		});
}

void p2p_tunnel::connect_to_peer(const boost::asio::ip::udp::endpoint& endpoint)
{
	// Create peer entry
	auto& peer = get_or_create_peer(endpoint);
	{
		std::lock_guard<std::mutex> lock(peer.mutex);
		peer.is_connected = true;
		peer.last_seen = std::chrono::steady_clock::now();
	}

	// Send a connection packet (empty data to establish connection)
	std::vector<uint8_t> connection_packet = {0x00}; // Connection handshake
	send_to_peer_async(connection_packet, endpoint);

	if (connection_callback_)
	{
		connection_callback_(endpoint);
	}
}

boost::asio::ip::udp::endpoint p2p_tunnel::get_local_endpoint() const
{
	return local_endpoint_;
}

void p2p_tunnel::set_packet_received_callback(packet_received_callback cb)
{
	packet_callback_ = std::move(cb);
}

void p2p_tunnel::set_connection_callback(connection_callback cb)
{
	connection_callback_ = std::move(cb);
}

std::vector<boost::asio::ip::udp::endpoint> p2p_tunnel::get_connected_peers() const
{
	std::lock_guard<std::mutex> lock(peers_mutex_);
	std::vector<boost::asio::ip::udp::endpoint> result;
	for (const auto& [key, peer] : peers_)
	{
		if (peer->is_connected)
		{
			result.push_back(peer->endpoint);
		}
	}
	return result;
}

bool p2p_tunnel::is_peer_connected(const boost::asio::ip::udp::endpoint& peer) const
{
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto key = endpoint_to_string(peer);
	auto it = peers_.find(key);
	return it != peers_.end() && it->second->is_connected;
}

peer_connection& p2p_tunnel::get_or_create_peer(const boost::asio::ip::udp::endpoint& endpoint)
{
	std::lock_guard<std::mutex> lock(peers_mutex_);
	auto key = endpoint_to_string(endpoint);
	auto it = peers_.find(key);
	if (it == peers_.end())
	{
		auto peer = std::make_shared<peer_connection>();
		peer->endpoint = endpoint;
		peer->last_seen = std::chrono::steady_clock::now();
		peers_[key] = peer;
		return *peer;
	}
	return *(it->second);
}

void p2p_tunnel::update_peer_activity(const boost::asio::ip::udp::endpoint& endpoint)
{
	auto& peer = get_or_create_peer(endpoint);
	std::lock_guard<std::mutex> lock(peer.mutex);
	peer.last_seen = std::chrono::steady_clock::now();
	if (!peer.is_connected)
	{
		peer.is_connected = true;
	}
}

// VPN Interface Implementation
vpn_interface::vpn_interface(std::shared_ptr<p2p_tunnel> tunnel)
	: tunnel_(std::move(tunnel))
{
}

vpn_interface::~vpn_interface()
{
	stop();
}

void vpn_interface::start()
{
	if (running_.exchange(true))
		return;

	// Set up tunnel callback to forward packets to network interface
	tunnel_->set_packet_received_callback(
		[this](const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from) {
			handle_tunnel_packet(data, from);
		});
}

void vpn_interface::stop()
{
	if (!running_.exchange(false))
		return;
}

void vpn_interface::inject_packet(const std::vector<uint8_t>& packet)
{
	if (!running_ || !tunnel_)
		return;

	// Forward packet through tunnel to all connected peers
	tunnel_->broadcast(packet);
}

void vpn_interface::set_packet_output_callback(std::function<void(const std::vector<uint8_t>&)> cb)
{
	output_callback_ = std::move(cb);
}

void vpn_interface::handle_tunnel_packet(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from)
{
	if (!running_ || !output_callback_)
		return;

	// Forward decrypted packet to network interface
	output_callback_(data);
}

} // namespace udp
} // namespace dixelu

