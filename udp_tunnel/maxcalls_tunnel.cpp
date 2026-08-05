#include "maxcalls_tunnel.h"

#include "global_flags.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <numeric>
#include <algorithm>
#include <array>
#include <random>
#include <sstream>

namespace dixelu
{
namespace udp
{

namespace
{

std::string make_device_id()
{
	std::array<uint8_t, 16> bytes{};
	std::random_device rd;
	for (auto& byte : bytes)
	{
		byte = static_cast<uint8_t>(rd());
	}

	// RFC 4122 version 4 UUID. Keeping it for the lifetime of the tunnel makes
	// MAX reconnects look like the same device instead of a new login each time.
	bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0F) | 0x40);
	bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3F) | 0x80);

	std::ostringstream out;
	out << std::hex << std::setfill('0');
	for (size_t i = 0; i < bytes.size(); ++i)
	{
		if (i == 4 || i == 6 || i == 8 || i == 10)
			out << '-';
		out << std::setw(2) << static_cast<unsigned int>(bytes[i]);
	}
	return out.str();
}

} // namespace

maxcalls_tunnel::maxcalls_tunnel(const std::string& login_token, bool is_transmitter, const std::string& peer_id, encode_scheme scheme,
	const std::string& bind_address, std::function<bool(const std::string&)> prepare_transport_address)
	: login_token_(login_token), is_transmitter_(is_transmitter), peer_id_(peer_id), scheme_(scheme), bind_address_(bind_address),
	  prepare_transport_address_(std::move(prepare_transport_address)), device_id_(make_device_id())
{
	dummy_endpoint_ = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0);
}

maxcalls_tunnel::~maxcalls_tunnel()
{
	stop();
}

void maxcalls_tunnel::set_encryption_key(const std::string& seed_key)
{
	if (seed_key.empty())
	{
		if (scheme_ == encode_scheme::raw)
			throw std::invalid_argument("Raw packet encoding cannot be used without encryption");
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

void maxcalls_tunnel::start()
{
	if (scheme_ == encode_scheme::raw && !lep::crypto::has_key(encryption_key_))
		throw std::runtime_error("Raw packet encoding requires an encryption seed key");

	if (running_.exchange(true))
		return;

	receive_thread_ = std::thread(&maxcalls_tunnel::run_receive_loop, this);
	cleanup_thread_ = std::thread(&maxcalls_tunnel::run_cleanup_sweep, this);
}

void maxcalls_tunnel::stop()
{
	const bool was_running = running_.exchange(false);

	if (was_running)
	{
		{
			std::lock_guard<std::mutex> lock(connection_mutex_);
			if (connection_)
			{
				connection_->close();
			}
		}
		{
			std::lock_guard<std::mutex> lock(client_mutex_);
			if (client_)
			{
				client_->close();
			}
		}
	}

	if (receive_thread_.joinable())
		receive_thread_.join();

	if (cleanup_thread_.joinable())
		cleanup_thread_.join();
}

void maxcalls_tunnel::run_receive_loop()
{
	unsigned int retry_delay_seconds = 2;

	while (running_)
	{
		bool connection_was_established = false;
		try
		{
			maxcalls::Config cfg;
			cfg.login_token = login_token_;
			cfg.device_id = device_id_;
			cfg.bind_address = bind_address_;
			cfg.prepare_transport_address = prepare_transport_address_;
			cfg.should_stop = [this] { return !running_.load(); };
			cfg.log = [this](const std::string& msg) {
				stats_.add_log("[maxcalls] " + msg);
				if (VERBOSE_MODE)
				{
					std::cout << "[maxcalls] " << msg << std::endl;
				}
			};

			stats_.add_log("[Tunnel] Initializing maxcalls client...");
			auto new_client = std::make_unique<maxcalls::Client>(cfg);
			if (!running_)
			{
				new_client->close();
				break;
			}

			maxcalls::Client* active_client = nullptr;
			{
				std::lock_guard<std::mutex> lock(client_mutex_);
				client_ = std::move(new_client);
				active_client = client_.get();
			}

			stats_.add_log("[Tunnel] Client initialized. External user ID: " + active_client->external_user_id());
			std::cout << "[Tunnel] maxcalls external ID: " << active_client->external_user_id() << std::endl;

			maxcalls::Connection conn = [this, active_client]() {
				if (is_transmitter_)
				{
					stats_.add_log("[Tunnel] Waiting for call...");
					std::cout << "[Tunnel] Waiting for incoming maxcalls call..." << std::endl;
					return active_client->wait_for_call();
				}
				else
				{
					stats_.add_log("[Tunnel] Calling peer " + peer_id_ + "...");
					std::cout << "[Tunnel] Calling maxcalls peer: " << peer_id_ << "..." << std::endl;
					return active_client->call(peer_id_);
				}
			}();

			if (!running_)
			{
				conn.close();
				break;
			}

			{
				std::lock_guard<std::mutex> lock(connection_mutex_);
				connection_ = std::make_unique<maxcalls::Connection>(std::move(conn));
			}

			connection_was_established = true;
			retry_delay_seconds = 2;
			stats_.add_log("[Tunnel] Connection established!");
			std::cout << "[Tunnel] maxcalls connection established!" << std::endl;

			std::vector<uint8_t> buffer(65535);
			while (running_)
			{
				maxcalls::Connection* active_connection = nullptr;
				{
					std::lock_guard<std::mutex> lock(connection_mutex_);
					if (!connection_ || !connection_->is_open())
						break;
					active_connection = connection_.get();
				}

				// Blocking read. stop() closes this connection to wake the read.
				const size_t n = active_connection->read(buffer.data(), buffer.size());
				if (n == 0)
				{
					stats_.add_log("[Tunnel] Connection closed by peer.");
					std::cout << "[Tunnel] maxcalls connection closed by peer." << std::endl;
					break;
				}

				process_incoming_datagram(buffer.data(), n);
			}
		}
		catch (const std::exception& e)
		{
			if (running_)
			{
				stats_.add_log("[Tunnel] maxcalls session error: " + std::string(e.what()));
				std::cerr << "[Tunnel] maxcalls session error: " << e.what() << std::endl;
			}
		}

		std::unique_ptr<maxcalls::Connection> old_connection;
		{
			std::lock_guard<std::mutex> lock(connection_mutex_);
			old_connection = std::move(connection_);
		}
		if (old_connection)
			old_connection->close();

		std::unique_ptr<maxcalls::Client> old_client;
		{
			std::lock_guard<std::mutex> lock(client_mutex_);
			old_client = std::move(client_);
		}
		if (old_client)
			old_client->close();

		if (!running_)
			break;

		const unsigned int delay = retry_delay_seconds;
		stats_.add_log("[Tunnel] Reconnecting maxcalls in " + std::to_string(delay) + "s...");
		std::cerr << "[Tunnel] Reconnecting maxcalls in " << delay << "s..." << std::endl;
		for (unsigned int elapsed_tenths = 0; running_ && elapsed_tenths < delay * 10; ++elapsed_tenths)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

		if (!connection_was_established)
			retry_delay_seconds = (std::min)(retry_delay_seconds * 2, 16u);
	}

	running_ = false;
}

void maxcalls_tunnel::process_incoming_datagram(const uint8_t* data, size_t size)
{
	stats_.bytes_received += size;

	try
	{
		dixelu::lep::packet decoded;

		switch (scheme_)
		{
			case encode_scheme::lep_v0:
			{
				decoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::decode(data, size);
				break;
			}
			case encode_scheme::lep_v1:
			{
				decoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v1>::decode(data, size);
				break;
			}
			case encode_scheme::raw:
			{
				decoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_packet>::decode(data, size);
				break;
			}
		}

		// Decrypt after LEP decoding
		lep::crypto::transform(encryption_key_, decoded.index, decoded.data);

		if (decoded.data.size() < 6)
		{
			return; // Drop small/invalid packets
		}

		// Parse header
		uint32_t packet_id = (decoded.data[0] << 24) |
		                     (decoded.data[1] << 16) |
		                     (decoded.data[2] << 8)  |
		                     decoded.data[3];
		uint8_t frag_index = decoded.data[4];
		uint8_t total_frags = decoded.data[5];
		size_t payload_size = decoded.data.size() - 6;

		if (total_frags <= 1)
		{
			std::vector<uint8_t> completed(decoded.data.begin() + 6, decoded.data.end());
			stats_.packets_received++;
			stats_.add_event(packet_event_type::received, packet_id, completed.size(), "maxcalls_peer");
			if (packet_callback_)
			{
				packet_callback_(completed, dummy_endpoint_);
			}
		}
		else
		{
			std::lock_guard<std::mutex> lock(reassembly_mutex_);
			auto& assembly = reassembly_buffer_[packet_id];
			if (assembly.total_frags == 0)
			{
				assembly.total_frags = total_frags;
				assembly.received_frags_mask.resize(total_frags, 0);
				assembly.first_frag_time = std::chrono::steady_clock::now();
			}

			if (frag_index < total_frags && !assembly.received_frags_mask[frag_index])
			{
				size_t offset = frag_index * fragment_payload_size();
				if (assembly.data.size() < offset + payload_size)
				{
					assembly.data.resize(offset + payload_size);
				}

				std::memcpy(assembly.data.data() + offset, decoded.data.data() + 6, payload_size);
				assembly.received_frags_mask[frag_index] = 1;
				assembly.received_frags_count++;

				if (assembly.received_frags_count == total_frags)
				{
					std::vector<uint8_t> completed = std::move(assembly.data);
					reassembly_buffer_.erase(packet_id);

					stats_.packets_received++;
					stats_.add_event(packet_event_type::received, packet_id, completed.size(), "maxcalls_peer");
					if (packet_callback_)
					{
						packet_callback_(completed, dummy_endpoint_);
					}
				}
			}
		}
	}
	catch (const std::exception& e)
	{
		if (VERBOSE_MODE)
		{
			std::cerr << "[Tunnel] Packet processing error: " << e.what() << std::endl;
		}
	}
}

void maxcalls_tunnel::broadcast(const std::vector<uint8_t>& data)
{
	if (data.empty())
		return;

	{
		std::lock_guard<std::mutex> lock(connection_mutex_);
		if (!connection_ || !connection_->is_open())
		{
			stats_.broadcast_drops++;
			return;
		}
	}

	uint32_t packet_id = next_packet_id_++;
	send_fragments(packet_id, data);
}

void maxcalls_tunnel::send_fragments(uint32_t packet_id, const std::vector<uint8_t>& data)
{
	size_t total_size = data.size();
	const size_t fragment_size = fragment_payload_size();
	size_t num_frags = (total_size + fragment_size - 1) / fragment_size;
	uint8_t total_frags_u8 = static_cast<uint8_t>(num_frags);

	if (num_frags > 255)
	{
		std::cerr << "[Tunnel] Packet too large to fragment (max 255 fragments)" << std::endl;
		return;
	}

	stats_.packets_sent++;
	stats_.add_event(packet_event_type::sent, packet_id, total_size, "maxcalls_peer");

	for (size_t i = 0; i < num_frags; ++i)
	{
		size_t offset = i * fragment_size;
		size_t chunk_size = (std::min)(fragment_size, total_size - offset);

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
		std::vector<uint8_t> encoded;
		switch (scheme_)
		{
			case encode_scheme::lep_v0:
			{
				encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v0>::encode(
					payload.data(), payload.size(), packet_id);
				break;
			}
			case encode_scheme::lep_v1:
			{
				encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_lep_v1>::encode(
					payload.data(), payload.size(), packet_id);
				break;
			}
			case encode_scheme::raw:
			{
				encoded = dixelu::lep::low_entropy_protocol<dixelu::lep::raw_packet>::encode(
					payload.data(), payload.size(), packet_id);
				break;
			}
		}

		if (encoded.empty())
		{
			continue;
		}

		// Write to connection
		try
		{
			std::lock_guard<std::mutex> lock(connection_mutex_);
			if (connection_ && connection_->is_open())
			{
				connection_->write(encoded.data(), encoded.size());
				stats_.bytes_sent += encoded.size();
			}
		}
		catch (const std::exception& e)
		{
			if (VERBOSE_MODE)
			{
				std::cerr << "[Tunnel] Write failed: " << e.what() << std::endl;
			}
		}
	}
}

void maxcalls_tunnel::set_packet_received_callback(packet_received_callback cb)
{
	packet_callback_ = cb;
}

void maxcalls_tunnel::run_cleanup_sweep()
{
	while (running_)
	{
		std::this_thread::sleep_for(std::chrono::seconds(5));

		auto now = std::chrono::steady_clock::now();
		std::lock_guard<std::mutex> lock(reassembly_mutex_);
		
		for (auto it = reassembly_buffer_.begin(); it != reassembly_buffer_.end();)
		{
			auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.first_frag_time).count();
			if (age > 30) // clean up incomplete reassemblies older than 30s
			{
				stats_.packets_lost++;
				stats_.add_event(packet_event_type::lost, it->first, 0, "maxcalls_peer");
				it = reassembly_buffer_.erase(it);
			}
			else
			{
				++it;
			}
		}
	}
}

std::vector<boost::asio::ip::udp::endpoint> maxcalls_tunnel::get_connected_peers() const
{
	std::vector<boost::asio::ip::udp::endpoint> peers;
	std::lock_guard<std::mutex> lock(connection_mutex_);
	if (connection_ && connection_->is_open())
	{
		peers.push_back(dummy_endpoint_);
	}
	return peers;
}

size_t maxcalls_tunnel::get_peer_count() const
{
	std::lock_guard<std::mutex> lock(connection_mutex_);
	return (connection_ && connection_->is_open()) ? 1 : 0;
}

} // namespace udp
} // namespace dixelu
