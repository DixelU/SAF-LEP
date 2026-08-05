#pragma once

#ifndef SAF_LEP_MAXCALLS_TUNNEL_H
#define SAF_LEP_MAXCALLS_TUNNEL_H

#include <memory>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <functional>
#include <boost/asio/ip/udp.hpp>
#include "tunnel.h"
#include <maxcalls/maxcalls.hpp>

namespace dixelu
{
namespace udp
{

class maxcalls_tunnel : public tunnel_interface
{
public:
	maxcalls_tunnel(const std::string& login_token, bool is_transmitter, const std::string& peer_id, encode_scheme scheme,
		const std::string& bind_address = "",
		std::function<bool(const std::string&)> prepare_transport_address = {});
	~maxcalls_tunnel() override;

	void start() override;
	void stop() override;
	void broadcast(const std::vector<uint8_t>& data) override;
	void set_packet_received_callback(packet_received_callback cb) override;
	
	tunnel_stats& get_stats() override { return stats_; }
	const tunnel_stats& get_stats() const override { return stats_; }

	void set_encryption_key(const std::string& seed_key) override;
	std::vector<boost::asio::ip::udp::endpoint> get_connected_peers() const override;
	size_t get_peer_count() const override;

private:
	void run_receive_loop();
	void process_incoming_datagram(const uint8_t* data, size_t size);
	void send_fragments(uint32_t packet_id, const std::vector<uint8_t>& data);
	void run_cleanup_sweep();

	std::string login_token_;
	bool is_transmitter_;
	std::string peer_id_;
	encode_scheme scheme_;
	std::string bind_address_;
	std::function<bool(const std::string&)> prepare_transport_address_;
	std::string device_id_;

	std::atomic<bool> running_{false};
	std::thread receive_thread_;
	std::thread cleanup_thread_;

	std::unique_ptr<maxcalls::Client> client_;
	mutable std::mutex client_mutex_;
	std::unique_ptr<maxcalls::Connection> connection_;
	mutable std::mutex connection_mutex_;

	packet_received_callback packet_callback_;
	boost::asio::ip::udp::endpoint dummy_endpoint_;

	std::atomic<uint32_t> next_packet_id_{0};
	std::array<uint8_t, lep::crypto::KEY_SIZE> encryption_key_{};

	struct reassembly_state {
		std::vector<uint8_t> data;
		uint8_t total_frags = 0;
		uint8_t received_frags_count = 0;
		std::vector<uint8_t> received_frags_mask;
		std::chrono::steady_clock::time_point first_frag_time;
	};

	mutable std::mutex reassembly_mutex_;
	std::unordered_map<uint32_t, reassembly_state> reassembly_buffer_;

	tunnel_stats stats_;

	static constexpr size_t MAX_FRAGMENT_SIZE = 150;
	static constexpr size_t MAX_RAW_FRAGMENT_SIZE = 1200;
	// Keeps raw application datagrams below conservative ICE/TURN path MTUs
	// while avoiding LEP's ten-way fragmentation of a typical VPN packet.

	size_t fragment_payload_size() const noexcept
	{
		return scheme_ == encode_scheme::raw
			? MAX_RAW_FRAGMENT_SIZE
			: MAX_FRAGMENT_SIZE;
	}
};

} // namespace udp
} // namespace dixelu

#endif // SAF_LEP_MAXCALLS_TUNNEL_H
