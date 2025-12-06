#include "tunnel.h"

#include <chrono>
#include <algorithm>
#include <iostream>
#include <cstring>

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
		std::cerr << "Failed to open socket: " << ec.message() << std::endl;
		return;
	}

	socket_.bind(local_endpoint_, ec);
	if (ec)
	{
		std::cerr << "Failed to bind socket: " << ec.message() << std::endl;
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
			std::cerr << "Receive error: " << error.message() << std::endl;
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

	std::cout << "[Tunnel] Received " << bytes_transferred << " bytes from " << endpoint_to_string(remote_endpoint_) << std::endl;

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
		if (!decoded.data.empty())
		{
			// Parse header: [PacketID(2)][FragIndex(1)][TotalFrags(1)]
			if (decoded.data.size() < 4)
			{
				// Treat as legacy/handshake if size 1 and 0x00?
				if (decoded.data.size() == 1 && decoded.data[0] == 0x00)
				{
					// Handshake, pass through
				}
			}
			else
			{
				uint16_t packet_id = (decoded.data[0] << 8) | decoded.data[1];
				uint8_t frag_index = decoded.data[2];
				uint8_t total_frags = decoded.data[3];
				
				// Payload starts at offset 4
				size_t payload_size = decoded.data.size() - 4;

				if (total_frags <= 1)
				{
					// Single fragment, pass directly
					if (packet_callback_)
					{
						std::vector<uint8_t> payload(decoded.data.begin() + 4, decoded.data.end());
						packet_callback_(payload, remote_endpoint_);
					}
				}
				else
				{
					// Reassembly needed
					std::lock_guard<std::mutex> lock(reassembly_mutex_);
					std::string key = endpoint_to_string(remote_endpoint_) + ":" + std::to_string(packet_id);
					
					auto& assembly = reassembly_buffer_[key];
					if (assembly.total_frags == 0)
					{
						// New assembly
						assembly.total_frags = total_frags;
						assembly.received_frags_mask.resize(total_frags, false);
						assembly.first_frag_time = std::chrono::steady_clock::now();
					}

					if (frag_index < total_frags && !assembly.received_frags_mask[frag_index])
					{
						size_t offset = frag_index * MAX_FRAGMENT_SIZE;
						if (assembly.data.size() < offset + payload_size)
						{
							assembly.data.resize(offset + payload_size);
						}
						
						std::memcpy(assembly.data.data() + offset, decoded.data.data() + 4, payload_size);
						assembly.received_frags_mask[frag_index] = true;
						assembly.received_frags_count++;

						if (assembly.received_frags_count == total_frags)
						{
							// Complete!
							if (packet_callback_)
							{
								packet_callback_(assembly.data, remote_endpoint_);
							}
							reassembly_buffer_.erase(key);
						}
					}
				}
			}
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << "LEP decode error: " << e.what() << std::endl;
	}

	// Continue receiving
	start_receive();
}

void p2p_tunnel::send_to_peer(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& peer)
{
	if (data.empty())
		return;

	// Calculate fragments
	size_t total_size = data.size();
	size_t num_frags = (total_size + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;
	
	if (num_frags > 255)
	{
		std::cerr << "Packet too large to fragment (max 255 fragments)" << std::endl;
		return;
	}

	uint16_t packet_id = next_packet_id_++;
	uint8_t total_frags_u8 = static_cast<uint8_t>(num_frags);

	for (size_t i = 0; i < num_frags; ++i)
	{
		size_t offset = i * MAX_FRAGMENT_SIZE;
		size_t chunk_size = std::min(MAX_FRAGMENT_SIZE, total_size - offset);

		// Prepare payload with header: [PacketID(2)][FragIndex(1)][TotalFrags(1)][Data...]
		std::vector<uint8_t> payload;
		payload.reserve(4 + chunk_size);
		payload.push_back((packet_id >> 8) & 0xFF);
		payload.push_back(packet_id & 0xFF);
		payload.push_back(static_cast<uint8_t>(i));
		payload.push_back(total_frags_u8);
		payload.insert(payload.end(), data.begin() + offset, data.begin() + offset + chunk_size);

		// Get or create peer connection
		auto& peer_conn = get_or_create_peer(peer);

		// Encode with LEP
		uint16_t index;
		{
			std::lock_guard<std::mutex> lock(peer_conn.mutex);
			index = peer_conn.next_send_index++;
		}

		auto encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::encode(
			payload.data(), payload.size(), index);

		if (encoded.empty())
		{
			std::cerr << "LEP encode failed" << std::endl;
			continue;
		}

		// Send synchronously
		boost::system::error_code ec;
		socket_.send_to(boost::asio::buffer(encoded), peer, 0, ec);
		if (ec)
		{
			std::cerr << "Send error: " << ec.message() << std::endl;
		}
	}
}

void p2p_tunnel::send_to_peer_async(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& peer)
{
	if (data.empty())
		return;

	// Calculate fragments
	size_t total_size = data.size();
	size_t num_frags = (total_size + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;

	if (num_frags > 255)
	{
		std::cerr << "Packet too large to fragment (max 255 fragments)" << std::endl;
		return;
	}

	uint16_t packet_id = next_packet_id_++;
	uint8_t total_frags_u8 = static_cast<uint8_t>(num_frags);

	for (size_t i = 0; i < num_frags; ++i)
	{
		size_t offset = i * MAX_FRAGMENT_SIZE;
		size_t chunk_size = std::min(MAX_FRAGMENT_SIZE, total_size - offset);

		// Prepare payload with header: [PacketID(2)][FragIndex(1)][TotalFrags(1)][Data...]
		std::vector<uint8_t> payload;
		payload.reserve(4 + chunk_size);
		payload.push_back((packet_id >> 8) & 0xFF);
		payload.push_back(packet_id & 0xFF);
		payload.push_back(static_cast<uint8_t>(i));
		payload.push_back(total_frags_u8);
		payload.insert(payload.end(), data.begin() + offset, data.begin() + offset + chunk_size);

		// Get or create peer connection
		auto& peer_conn = get_or_create_peer(peer);

		// Encode with LEP
		uint16_t index;
		{
			std::lock_guard<std::mutex> lock(peer_conn.mutex);
			index = peer_conn.next_send_index++;
		}

		auto encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::encode(
			payload.data(), payload.size(), index);

		if (encoded.empty())
		{
			std::cerr << "LEP encode failed" << std::endl;
			continue;
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
}

void p2p_tunnel::handle_send(const boost::system::error_code& error, std::size_t bytes_transferred,
	std::shared_ptr<std::vector<uint8_t>> buffer, const boost::asio::ip::udp::endpoint& target)
{
	if (error)
	{
		std::cerr << "Async send error to " << endpoint_to_string(target) << ": " << error.message() << std::endl;
	}
}

void p2p_tunnel::broadcast(const std::vector<uint8_t>& data)
{
	std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
	int sent_count = 0;

	for (const auto& [key, peer] : peers_)
	{
		if (peer->is_connected)
		{
			send_to_peer_async(data, peer->endpoint);
			std::cout << "[Tunnel] Broadcasting " << data.size() << " bytes to " << peer->endpoint << std::endl;
			sent_count++;
		}
	}
}

void p2p_tunnel::connect_to_peer(const std::string& address, const std::string& port)
{
#if BOOST_VERSION >= 106600
	resolver_.async_resolve(
		address, port,
		[this](const boost::system::error_code& ec, boost::asio::ip::udp::resolver::results_type results) {
			if (ec)
			{
				std::cerr << "Resolve error: " << ec.message() << std::endl;
				return;
			}

			if (results.empty())
			{
				std::cerr << "No endpoints resolved" << std::endl;
				return;
			}

			connect_to_peer(*results.begin());
		});
#else
	boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), address, port);
	resolver_.async_resolve(
		query,
		[this](const boost::system::error_code& ec, boost::asio::ip::udp::resolver::iterator iterator) {
			if (ec)
			{
				std::cerr << "Resolve error: " << ec.message() << std::endl;
				return;
			}

			if (iterator == boost::asio::ip::udp::resolver::iterator())
			{
				std::cerr << "No endpoints resolved" << std::endl;
				return;
			}

			connect_to_peer(*iterator);
		});
#endif
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

// ... (rest of p2p_tunnel methods unchanged) ...

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
	std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
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
	std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
	auto key = endpoint_to_string(peer);
	auto it = peers_.find(key);
	return it != peers_.end() && it->second->is_connected;
}

peer_connection& p2p_tunnel::get_or_create_peer(const boost::asio::ip::udp::endpoint& endpoint)
{
	std::lock_guard<std::recursive_mutex> lock(peers_mutex_);
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
#ifdef _WIN32
	, tap_adapter_(std::make_unique<TapAdapter>())
#else
	, tun_adapter_(std::make_unique<TunAdapter>())
#endif
{
}

vpn_interface::~vpn_interface()
{
	stop();
}

bool vpn_interface::start(const std::string& ip, const std::string& mask, const std::string& gateway)
{
	if (running_.exchange(true))
		return true;

#ifdef _WIN32
	// Open TAP adapter
	if (!tap_adapter_->open())
	{
		std::cerr << "Failed to open TAP adapter" << std::endl;
		running_ = false;
		return false;
	}

	// Set status to connected (must be done before configuring routes so they bind correctly)
	if (!tap_adapter_->set_status(true))
	{
		std::cerr << "Failed to set TAP adapter status" << std::endl;
		running_ = false;
		return false;
	}

	// Give Windows a moment to recognize the link state
	std::this_thread::sleep_for(std::chrono::milliseconds(200));

	// Configure IP and Routes
	if (!tap_adapter_->configure(ip, mask, gateway))
	{
		std::cerr << "Failed to configure TAP adapter IP" << std::endl;
		running_ = false;
		return false;
	}
#else
	// Open TUN adapter
	if (!tun_adapter_->open())
	{
		std::cerr << "Failed to open TUN adapter" << std::endl;
		running_ = false;
		return false;
	}

	// Configure IP
	if (!tun_adapter_->configure(ip, mask, gateway))
	{
		std::cerr << "Failed to configure TUN adapter IP" << std::endl;
		running_ = false;
		return false;
	}
#endif

	// Set up tunnel callback to forward packets to adapter
	tunnel_->set_packet_received_callback(
		[this](const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from) {
			handle_tunnel_packet(data, from);
		});

	// Start reading from adapter
	read_thread_ = std::thread(&vpn_interface::read_from_tap, this);

	return true;
}

void vpn_interface::stop()
{
	if (!running_.exchange(false))
		return;

	if (read_thread_.joinable())
	{
		read_thread_.detach(); 
	}
}

void vpn_interface::read_from_tap()
{
	while (running_)
	{
#ifdef _WIN32
		auto packet = tap_adapter_->read();
		if (!packet.empty())
		{
			// Windows TAP returns Ethernet frames. We need to strip the header for the tunnel (Layer 3).
			// Ethernet header is 14 bytes: [Dest MAC(6)][Src MAC(6)][EtherType(2)]
			if (packet.size() > 14)
			{
				uint16_t ether_type = (packet[12] << 8) | packet[13];
				// IPv4 (0x0800) or IPv6 (0x86DD)
				if (ether_type == 0x0800 || ether_type == 0x86DD)
				{
					// Strip Ethernet header
					std::vector<uint8_t> ip_packet(packet.begin() + 14, packet.end());
					tunnel_->broadcast(ip_packet);
				}
				else if (ether_type == 0x0806) // ARP
				{
					handle_arp(packet);
				}
				else
				{
					// Log ignored packet types
					std::cout << "[VPN] Ignored packet with EtherType: 0x" << std::hex << ether_type << std::dec << std::endl;
				}
			}
		}
#else
		auto packet = tun_adapter_->read();
		if (!packet.empty())
		{
			// Broadcast to all peers (simple hub mode)
			tunnel_->broadcast(packet);
		}
#endif
	}
}

void vpn_interface::handle_arp(const std::vector<uint8_t>& packet)
{
#ifdef _WIN32
	// Packet includes Ethernet header (14 bytes) + ARP payload (28 bytes)
	if (packet.size() < 42) return;

	// Ethernet Header: [Dest(6)][Src(6)][Type(2)]
	// ARP Packet:
	// [HTYPE(2)][PTYPE(2)][HLEN(1)][PLEN(1)][OPER(2)]
	// [SHA(6)][SPA(4)][THA(6)][TPA(4)]

	const uint8_t* arp_ptr = packet.data() + 14;

	uint16_t htype = (arp_ptr[0] << 8) | arp_ptr[1];
	uint16_t ptype = (arp_ptr[2] << 8) | arp_ptr[3];
	uint16_t oper = (arp_ptr[6] << 8) | arp_ptr[7];

	if (htype == 1 && ptype == 0x0800 && oper == 1) // Ethernet, IPv4, Request
	{
		// It's a request. Let's reply.
		// We act as the gateway (or whatever IP they are asking for).
		// Since we are a tunnel, we can claim ANY IP that isn't the sender's.
		
		// Sender MAC (SHA)
		const uint8_t* sha = arp_ptr + 8;
		// Sender IP (SPA)
		const uint8_t* spa = arp_ptr + 14;
		// Target IP (TPA)
		const uint8_t* tpa = arp_ptr + 24;

		// Construct Reply
		std::vector<uint8_t> reply(42);

		// Ethernet Header
		// Dest = SHA (Sender of request)
		std::memcpy(reply.data(), sha, 6);
		// Src = Our Dummy Gateway MAC (00:00:00:00:00:01)
		uint8_t dummy_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
		std::memcpy(reply.data() + 6, dummy_mac, 6);
		// Type = ARP (0x0806)
		reply[12] = 0x08; reply[13] = 0x06;

		// ARP Payload
		uint8_t* r_ptr = reply.data() + 14;
		
		// HTYPE, PTYPE, HLEN, PLEN
		std::memcpy(r_ptr, arp_ptr, 6); 
		
		// OPER = 2 (Reply)
		r_ptr[6] = 0x00; r_ptr[7] = 0x02;

		// SHA = Dummy MAC
		std::memcpy(r_ptr + 8, dummy_mac, 6);
		// SPA = TPA (Target IP of request becomes Sender IP of reply)
		std::memcpy(r_ptr + 14, tpa, 4);
		
		// THA = SHA (Sender MAC of request)
		std::memcpy(r_ptr + 18, sha, 6);
		// TPA = SPA (Sender IP of request)
		std::memcpy(r_ptr + 24, spa, 4);

		// Send reply
		// std::cout << "[VPN] Sending ARP Reply for " 
		// 		  << (int)tpa[0] << "." << (int)tpa[1] << "." << (int)tpa[2] << "." << (int)tpa[3] << std::endl;
		tap_adapter_->write(reply);
	}
#endif
}

void vpn_interface::handle_tunnel_packet(const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from)
{
	if (!running_)
		return;

	// Filter out control packets or too small packets (min IPv4 header is 20 bytes)
	if (data.size() < 20)
	{
		// This might be a handshake packet (0x00) or other control data
		if (data.size() == 1 && data[0] == 0x00)
		{
			std::cout << "[VPN] Handshake packet received (ignored)" << std::endl;
		}
		else
		{
			std::cout << "[VPN] Dropping small packet: size=" << data.size() << std::endl;
		}
		return;
	}

#ifdef _WIN32
	// Windows TAP expects Ethernet frames. We need to add a header.
	// [Dest MAC(6)][Src MAC(6)][EtherType(2)][Payload...]
	
	std::vector<uint8_t> frame;
	frame.reserve(14 + data.size());

	// Dest MAC: The TAP adapter's MAC (so the OS accepts it)
	auto tap_mac = tap_adapter_->get_mac();
	if (tap_mac.size() == 6)
	{
		frame.insert(frame.end(), tap_mac.begin(), tap_mac.end());
	}
	else
	{
		// Fallback if we can't get MAC (shouldn't happen)
		for(int i=0; i<6; ++i) frame.push_back(0xFF);
	}

	// Src MAC: Dummy (e.g., 00:00:00:00:00:01)
	frame.push_back(0x00); frame.push_back(0x00); frame.push_back(0x00);
	frame.push_back(0x00); frame.push_back(0x00); frame.push_back(0x01);

	// EtherType
	uint8_t version = (data[0] >> 4);
	if (version == 4)
	{
		frame.push_back(0x08); frame.push_back(0x00); // IPv4
	}
	else if (version == 6)
	{
		frame.push_back(0x86); frame.push_back(0xDD); // IPv6
	}
	else
	{
		// Unknown packet type, drop
		return;
	}

	// Payload
	frame.insert(frame.end(), data.begin(), data.end());

	if (!tap_adapter_->write(frame))
	{
		std::cout << "[VPN] Failed to write packet to TAP" << std::endl;
	}
#else
	if (!tun_adapter_->write(data))
	{
		// Log failure details
		std::cout << "[VPN] Failed to write packet to TUN: size=" << data.size();
		if (!data.empty())
		{
			std::cout << " first_byte=0x" << std::hex << (int)data[0] << std::dec;
		}
		std::cout << std::endl;
	}
#endif
}

} // namespace udp
} // namespace dixelu
