#include "tunnel.h"

#include <chrono>
#include <algorithm>
#include <iostream>
#include <cstring>
#include <iomanip>
#include <numeric>
#include <ranges>

#include "global_flags.h"

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
	
	if (VERBOSE_MODE)
		std::cout << "[Tunnel] Received " << bytes_transferred << " bytes from " << endpoint_to_string(remote_endpoint_) << std::endl;

	// Decode LEP packet
	try
	{
		auto decoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::decode(
			receive_buffer_.data(), bytes_transferred);

		// Decrypt after LEP decoding (using packet index from LEP header)
		lep::crypto::transform(encryption_key_, decoded.index, decoded.data);

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
			handle_fragmentation(peer, decoded);

		internal_cleanup_procedure(peer);
	}
	catch (const std::exception& e)
	{
		std::cerr << "LEP decode error: " << e.what() << std::endl;
	}

	// Continue receiving
	start_receive();
}

void p2p_tunnel::broadcast(const std::vector<uint8_t>& data)
{
	if (data.empty())
		return;

	// Copy the list of peers effectively to avoid holding the lock while sending?
	// Actually send_to_peer_async is thread safe for global peers map access, 
	// but we need a snapshot of connected peers.
	auto connected_peers = get_connected_peers();
	for (const auto& peer : connected_peers)
		send_to_peer_async(data, peer);
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

	// Get or create peer connection
	auto& peer_conn = get_or_create_peer(peer);
	
	uint32_t packet_id;
	{
		std::lock_guard<std::mutex> lock(peer_conn.mutex);
		packet_id = peer_conn.next_send_index++;
	}

	send_fragments(peer_conn, packet_id, data);
}

void p2p_tunnel::handle_send(const boost::system::error_code& error, std::size_t bytes_transferred,
	std::shared_ptr<std::vector<uint8_t>> buffer, const boost::asio::ip::udp::endpoint& target)
{
	if (error)
		std::cerr << "Async send error to " << endpoint_to_string(target) << ": " << error.message() << std::endl;
}

static uint32_t get_u32(const std::vector<uint8_t>& value, size_t index)
{
	return (value[index + 0] << 24) | (value[index + 1] << 16) | (value[index + 2] << 8) | value[index + 3];
}

void p2p_tunnel::handle_fragmentation(peer_connection& peer, dixelu::lep::packet& decoded)
{
	// Parse header: [PacketID(2)][FragIndex(1)][TotalFrags(1)]
	if (decoded.data.size() < 6)
	{
		// Treat as legacy/handshake if size 1 and 0x00?
		// Handshake, pass through
		if (decoded.data.size() == 1 && decoded.data[0] == 0x00)
			return;

		if (decoded.data.size() >= 1)
			handle_control_packet(peer, decoded);
	}
	else
	{
		uint32_t packet_id = get_u32(decoded.data, 0);
		uint8_t frag_index = decoded.data[4];
		uint8_t total_frags = decoded.data[5];

		// Payload starts at offset 6
		size_t payload_size = decoded.data.size() - 6;
		std::vector<uint8_t> completed_packet;

		{
			std::lock_guard<std::mutex> lock(peer.mutex);

			// Gap detection
			process_packet_gap(peer, packet_id);
			
			if (packet_id > peer.last_received_index)
				peer.last_received_index = packet_id;

			if (total_frags <= 1)
			{
				// Single fragment, pass directly
				// We need to copy payload because we are under lock and callback might take time/lock
				completed_packet.assign(decoded.data.begin() + 6, decoded.data.end());
			}
			else
			{
				// Reassembly needed
				// Use packet_id directly as key (per-peer buffer)
				auto& assembly = peer.reassembly_buffer[packet_id];
				
				if (assembly.total_frags == 0)
				{
					// New assembly
					assembly.total_frags = total_frags;
					assembly.received_frags_mask.resize(total_frags, 0); // 0 = false
					assembly.first_frag_time = std::chrono::steady_clock::now();
					assembly.last_request_time = assembly.first_frag_time;
				}

				uint32_t current_frags = std::reduce(assembly.received_frags_mask.begin(), assembly.received_frags_mask.end());

				if (current_frags == total_frags)
					return;

				if (current_frags == 0)
					peer.reassembly_in_progress.insert(packet_id);

				if (frag_index < total_frags && !assembly.received_frags_mask[frag_index])
				{
					size_t offset = frag_index * MAX_FRAGMENT_SIZE;
					if (assembly.data.size() < offset + payload_size)
						assembly.data.resize(offset + payload_size);

					std::memcpy(assembly.data.data() + offset, decoded.data.data() + 6, payload_size);
					assembly.received_frags_mask[frag_index] = 1; // 1 = true
					assembly.received_frags_count++;

					if (assembly.received_frags_count == total_frags)
					{
						// Complete!
						completed_packet = std::move(assembly.data);

						// RRQ will most likely trigger recreation of this buffer
						//peer.reassembly_buffer.erase(packet_id); 

						peer.reassembly_in_progress.erase(packet_id);
						peer.late_reassembly.erase(packet_id);
					}
				}
			}
		} // Unlock peer.mutex

		// Call callback outside lock
		if (!completed_packet.empty() && packet_callback_)
		{
			packet_callback_(completed_packet, remote_endpoint_);
		}
	}
}

void p2p_tunnel::handle_control_packet(peer_connection& peer, dixelu::lep::packet& decoded)
{
	uint8_t packet_type = decoded.data[0];

	switch (packet_type)
	{
		case PAC_RRQ:
		{
			if (decoded.data.size() != 5)
				return;

			uint32_t req_id = get_u32(decoded.data, 1);
			if (VERBOSE_MODE)
				std::cout << "[Tunnel] Received RRQ for packet " << req_id << std::endl;
			
			std::lock_guard<std::mutex> lock(peer.mutex);
			auto it = peer.storage.find(req_id);
			if (it == peer.storage.end())
			{
				if (VERBOSE_MODE)
					std::cout << "[Tunnel] The request packet is missing." << std::endl;
				send_control_packet(peer, PAC_LST, decoded.data | std::views::drop(1) | std::ranges::to<std::vector>());
				return;
			}

			// Resend
			for (auto& fragment : it->second)
			{
				auto buffer = std::make_shared<std::vector<uint8_t>>(fragment.data);
				socket_.async_send_to(
					boost::asio::buffer(*buffer),
					peer.endpoint,
					[this, buffer, endpoint = peer.endpoint](const boost::system::error_code& error, std::size_t bytes_transferred)
				{
					handle_send(error, bytes_transferred, buffer, endpoint);
				});
			}
			
			break;
		}
		case PAC_IWA:
		{
			if (VERBOSE_MODE)
				std::cout << "[Tunnel] Received IWA (Index Wrap Around)" << std::endl;

			std::lock_guard<std::mutex> lock(peer.mutex);
			peer.last_received_index = 0; // Reset expectation

			if (!peer.late_reassembly.empty())
				std::cout << "[Tunnel] Late reassembly container is not empty upon wraparound!" << std::endl;

			peer.late_reassembly = std::move(peer.reassembly_in_progress);

			break;
		}
		case PAC_LTR:
		{
			if (decoded.data.size() != 5)
				return;

			std::lock_guard<std::mutex> lock(peer.mutex);

			uint32_t req_id = get_u32(decoded.data, 1);
			auto iter = peer.storage.upper_bound(req_id);
			if (iter == peer.storage.end())
				return;

			peer.storage.erase(peer.storage.begin(), iter);
		}
		case PAC_LST:
		{
			if (decoded.data.size() != 5)
				return;

			uint32_t packet_id = get_u32(decoded.data, 1);

			std::lock_guard<std::mutex> lock(peer.mutex);

			if (peer.reassembly_buffer.erase(packet_id) && VERBOSE_MODE)
				std::cout << "[Tunnel] Packet " << packet_id << " marked as lost!" << std::endl;
			
			peer.reassembly_in_progress.erase(packet_id);
			peer.late_reassembly.erase(packet_id);
		}
	}
}

void p2p_tunnel::send_control_packet(peer_connection& peer, uint8_t type, const std::vector<uint8_t>& extra_data)
{
	std::vector<uint8_t> payload;
	payload.reserve(1 + extra_data.size());
	payload.push_back(type);
	payload.insert(payload.end(), extra_data.begin(), extra_data.end());

	// Encode with next index
	uint32_t index;
	{
		// Assumes peer.mutex is ALREADY LOCKED by the caller
		// std::lock_guard<std::mutex> lock(peer.mutex);
		// Control packets consume an index sequence to keep LEP encryption synchronized
		index = peer.next_send_index++;
	}

	// Encrypt payload before LEP encoding
	lep::crypto::transform(encryption_key_, index, payload);

	auto encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::encode(
		payload.data(), payload.size(), index);
		
	if (!encoded.empty())
	{
		auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(encoded));
		socket_.async_send_to(
			boost::asio::buffer(*buffer),
			peer.endpoint,
			[this, buffer, endpoint = peer.endpoint](const boost::system::error_code& error, std::size_t bytes_transferred) {
				handle_send(error, bytes_transferred, buffer, endpoint);
			});
	}
}

void p2p_tunnel::internal_cleanup_procedure(peer_connection& peer)
{
	auto curr = std::chrono::steady_clock::now();

	constexpr auto N = 5;
	uint32_t ids[N]{};
	uint8_t size = 0;

	std::lock_guard<std::mutex> lock(peer.mutex);

	// remove all packets that have all request results satified and for which RRQs wont be sent again
	for (auto& [id, data] : peer.reassembly_buffer)
	{
		if (data.received_frags_count != data.total_frags)
			continue;

		if (std::chrono::duration_cast<std::chrono::seconds>(curr - data.last_request_time).count() <
			2 /* rerequest timeout in seconds */ * 10 )
			continue;

		// check for some REALLY lossy connection (packets are barely going through)
		if (peer.reassembly_in_progress.contains(id) || peer.late_reassembly.contains(id))
			continue;

		ids[size++] = id;
		if (size == N)
			break;
	}

	if (size > 0)
	{
		std::vector<uint8_t> req_data;
		req_data.push_back((*ids >> 24) & 0xFF);
		req_data.push_back((*ids >> 16) & 0xFF);
		req_data.push_back((*ids >> 8) & 0xFF);
		req_data.push_back(*ids & 0xFF);
		send_control_packet(peer, PAC_LTR, req_data);
	}

	while (size-- > 0)
		peer.reassembly_buffer.erase(ids[size]);
}

void p2p_tunnel::process_packet_gap(peer_connection& peer, uint32_t packet_id)
{
	// NOTE: This function is called with peer.mutex ALREADY LOCKED
	
	std::set<uint32_t> late_packets;
	auto curr_time = std::chrono::steady_clock::now();

	{
		// No need for reassembly_mutex_ anymore, everything is in peer
		
		auto packets = peer.reassembly_in_progress | std::views::take(10) | std::ranges::to<std::vector>();
		auto late_packets_view = peer.late_reassembly | std::views::take(10);
		for (auto& el : late_packets_view)
			packets.push_back(el);
		// Gather candidates: top 10 from progress + top 10 from late

		for (auto& pid: packets)
		{
			auto iter = peer.reassembly_buffer.find(pid);
			if (iter == peer.reassembly_buffer.end()) [[unlikely]]
			{
				std::cerr << "REASSEMBLY DESYNC for ID " << pid << "\n";
				peer.reassembly_in_progress.erase(pid);
				peer.late_reassembly.erase(pid);
				continue;
			}

			auto time_since_start = std::chrono::duration_cast<std::chrono::seconds>(curr_time - iter->second.first_frag_time).count();
			auto time_since_last_req = std::chrono::duration_cast<std::chrono::seconds>(curr_time - iter->second.last_request_time).count();
			
			// If it's been long enough since start, AND long enough since last request
			if (time_since_start >= reassembly_timeout_)
			{
				if (time_since_last_req >= 2) // Retry every 2 seconds
				{
					late_packets.insert(pid);
					iter->second.last_request_time = curr_time; // Update last request time
				}
			}
		}
	}
	
	for (auto& id : late_packets)
	{
		std::vector<uint8_t> req_data;
		req_data.push_back((id >> 24) & 0xFF);
		req_data.push_back((id >> 16) & 0xFF);
		req_data.push_back((id >> 8) & 0xFF);
		req_data.push_back(id & 0xFF);
		send_control_packet(peer, PAC_RRQ, req_data);

		if (VERBOSE_MODE)
			std::cout << "[Tunnel] Detected gap, requesting ID: " << id << std::endl;
	}
}

void p2p_tunnel::send_fragments(peer_connection& peer_conn, uint32_t packet_id, const std::vector<uint8_t>& data)
{
	size_t total_size = data.size();
	size_t num_frags = (total_size + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;
	uint8_t total_frags_u8 = static_cast<uint8_t>(num_frags);

	if (total_frags_u8 < num_frags)
	{
		std::cerr << "[Tunnel] Excessive fragmentation - " << num_frags << " fragments cannot be sent through the tunnel" << std::endl;
		return;
	}

	{
		std::lock_guard<std::mutex> lock(peer_conn.mutex);
		peer_conn.storage[packet_id].reserve(num_frags);
	}

	for (size_t i = 0; i < num_frags; ++i)
	{
		size_t offset = i * MAX_FRAGMENT_SIZE;
		size_t chunk_size = (std::min)(MAX_FRAGMENT_SIZE, total_size - offset);

		// Prepare payload with header: [PacketID(4)][FragIndex(1)][TotalFrags(1)][Data...]
		std::vector<uint8_t> payload;

		payload.reserve(6 + chunk_size);
		payload.push_back((packet_id >> 24) & 0xFF);
		payload.push_back((packet_id >> 16) & 0xFF);
		payload.push_back((packet_id >> 8) & 0xFF);
		payload.push_back(packet_id & 0xFF);
		payload.push_back(static_cast<uint8_t>(i));
		payload.push_back(total_frags_u8);

		payload.insert(payload.end(), data.begin() + offset, data.begin() + offset + chunk_size);

		// Encrypt payload before LEP encoding
		lep::crypto::transform(encryption_key_, packet_id, payload);

		// Encode with LEP
		auto encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::encode(
			payload.data(), payload.size(), packet_id);

		if (encoded.empty())
		{
			std::cerr << "LEP encode failed" << std::endl;
			continue;
		}
		
		// Store in cache for retransmission
		{
			std::lock_guard<std::mutex> lock(peer_conn.mutex);
			peer_conn.storage[packet_id].emplace_back(encoded, std::chrono::steady_clock::now());
			
			if (peer_conn.storage.size() > 4000)
			{
				peer_conn.storage.erase(peer_conn.storage.begin());
			}
			
			if (peer_conn.next_send_index == 0)
			{
				send_control_packet(peer_conn, PAC_IWA);
			}
		}

		auto buffer = std::make_shared<std::vector<uint8_t>>(encoded);

		socket_.async_send_to(
			boost::asio::buffer(*buffer),
			peer_conn.endpoint,
			[this, buffer, endpoint = peer_conn.endpoint](const boost::system::error_code& error, std::size_t bytes_transferred) {
				handle_send(error, bytes_transferred, buffer, endpoint);
			});
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
		std::lock_guard<std::mutex> locker(peer.mutex);
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

void p2p_tunnel::set_encryption_key(const std::string& seed_key)
{
	if (seed_key.empty())
	{
		encryption_key_ = {};
		return;
	}

	encryption_key_ = lep::crypto::derive_key(seed_key);

	if (VERBOSE_MODE)
	{
		std::cout << "[Tunnel] Encryption key set from seed (first 4 bytes: ";
		for (int i = 0; i < 4; ++i)
			std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)encryption_key_[i];
		std::cout << std::dec << "...)" << std::endl;
	}
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
#elif defined(__ANDROID__)
	, tun_adapter_(std::make_unique<AndroidTunAdapter>())
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

	// Store local IP for ARP filtering
	try 
	{
		local_ip_ = boost::asio::ip::make_address_v4(ip);
		if (VERBOSE_MODE)
			std::cout << "[VPN] Local IP set to: " << local_ip_ << std::endl;
	} 
	catch(...)
	{
		std::cerr << "Failed to parse local IP: " << ip << std::endl;
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

#if defined(__ANDROID__)
bool vpn_interface::start_android(int tun_fd)
{
	if (running_.exchange(true))
		return true;

	// Set the file descriptor from VpnService
	if (!tun_adapter_->set_fd(tun_fd))
	{
		std::cerr << "Failed to set TUN file descriptor" << std::endl;
		running_ = false;
		return false;
	}

	// Set up tunnel callback to forward packets to adapter
	tunnel_->set_packet_received_callback(
		[this](const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from) {
			handle_tunnel_packet(data, from);
		});

	// Start reading from adapter
	read_thread_ = std::thread(&vpn_interface::read_from_tap, this);

	return true;
}
#endif // __ANDROID__

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

					if (VERBOSE_MODE)
						std::cout << "[VPN] TAP -> Tunnel: IP packet size=" << ip_packet.size() << std::endl;

					tunnel_->broadcast(ip_packet);
				}
				else if (ether_type == 0x0806) // ARP
				{
					handle_arp(packet);
				}
				else
				{
					// Log ignored packet types
					if (VERBOSE_MODE)
						std::cout << "[VPN] Ignored packet with EtherType: 0x" << std::hex << ether_type << std::dec << std::endl;
				}
			}
		}
#else
		// Linux and Android both use TUN (Layer 3, raw IP packets)
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
	if (packet.size() < 42)
		return;

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
		// Sender MAC (SHA)
		const uint8_t* sha = arp_ptr + 8;
		// Sender IP (SPA)
		const uint8_t* spa = arp_ptr + 14;
		// Target IP (TPA)
		const uint8_t* tpa = arp_ptr + 24;

		if (VERBOSE_MODE)
			std::cout << "[VPN] ARP Request: Who has " 
				  << (int)tpa[0] << "." << (int)tpa[1] << "." << (int)tpa[2] << "." << (int)tpa[3] 
				  << "? Tell " 
				  << (int)spa[0] << "." << (int)spa[1] << "." << (int)spa[2] << "." << (int)spa[3] 
				  << std::endl;

		// Check for DAD (Duplicate Address Detection)
		// 1. If SPA is 0.0.0.0, it's a DAD probe.
		// 2. If TPA matches our Local IP, it's a probe for our IP.
		bool is_dad = false;
		if (spa[0] == 0 && spa[1] == 0 && spa[2] == 0 && spa[3] == 0)
		{
			is_dad = true;
		}
		else
		{
			boost::asio::ip::address_v4 target_ip(std::array<unsigned char, 4>{tpa[0], tpa[1], tpa[2], tpa[3]});
			if (target_ip == local_ip_)
			{
				is_dad = true;
			}
		}

		if (is_dad)
		{
			if (VERBOSE_MODE)
				std::cout << "[VPN] Ignoring DAD probe (SPA=0.0.0.0 or TPA=LocalIP)." << std::endl;
			return;
		}

		// It's a request for someone else (likely gateway). Let's reply.
		// We act as the gateway (or whatever IP they are asking for).

		// Construct Reply
		// Ethernet min frame size is 60 bytes (excluding FCS). 
		// ARP is 42 bytes. We must pad.
		std::vector<uint8_t> reply(60, 0);

		// Ethernet Header
		// Dest = SHA (Sender of request)
		std::memcpy(reply.data(), sha, 6);
		// Src = Our Dummy Gateway MAC
		uint8_t dummy_mac[] = {0x0E, 0x13, 0x37, 0x30, 0xBE, 0xEF};
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
		if (VERBOSE_MODE)
			std::cout << "[VPN] Sending ARP Reply for " 
				  << (int)tpa[0] << "." << (int)tpa[1] << "." << (int)tpa[2] << "." << (int)tpa[3] << std::endl;
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
			if (VERBOSE_MODE)
				std::cout << "[VPN] Handshake packet received (ignored)" << std::endl;
		}
		else
		{
			if (VERBOSE_MODE)
				std::cout << "[VPN] Dropping small packet: size=" << data.size() << std::endl;
		}
		return;
	}

	if (VERBOSE_MODE)
	{
		std::cout << "[VPN] Tunnel -> TAP: IP packet size=" << data.size() << std::endl;

		// Hex dump the first 60 bytes of the IP packet for debugging
		/*std::cout << "    Hex: ";
		for (size_t i = 0; i < std::min((size_t)60, data.size()); ++i)
		{
			std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
		}
		std::cout << std::dec << std::endl;*/
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
		for(int i = 0; i < 6; ++i)
			frame.push_back(0xFF);
	}

	// Src MAC: Dummy (Must match the one used in ARP reply!)
	// User requested: 0E-13-37-30-BE-EF
	frame.push_back(0x0E); frame.push_back(0x13); frame.push_back(0x37);
	frame.push_back(0x30); frame.push_back(0xBE); frame.push_back(0xEF);

	// EtherType
	uint8_t version = (data[0] >> 4);
	if (version == 4)
	{
		frame.push_back(0x08);
		frame.push_back(0x00); // IPv4
	}
	else if (version == 6)
	{
		frame.push_back(0x86);
		frame.push_back(0xDD); // IPv6
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
