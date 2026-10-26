#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "../udp_tunnel/tunnel.h"

namespace
{

using dixelu::udp::encode_scheme;
using dixelu::udp::p2p_tunnel;

bool expect(bool condition, const char* message)
{
	if (!condition)
		std::cerr << "FAILED: " << message << '\n';
	return condition;
}

bool wait_until(const std::function<bool()>& condition)
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (!condition())
	{
		if (std::chrono::steady_clock::now() >= deadline)
			return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	return true;
}

// An IPv4-looking payload large enough to need several tunnel fragments, with a
// tag the receiver can read back.
std::vector<uint8_t> tagged_packet(uint32_t tag)
{
	std::vector<uint8_t> data(600, static_cast<uint8_t>(tag));
	data[0] = 0x45;
	data[1] = (tag >> 16) & 0xFF;
	data[2] = (tag >> 8) & 0xFF;
	data[3] = tag & 0xFF;
	return data;
}

} // namespace

int main()
{
	constexpr uint32_t before_reset = 20;
	constexpr uint32_t after_reset = 40;

	auto server = std::make_shared<p2p_tunnel>(0, encode_scheme::lep_v0);
	auto client = std::make_shared<p2p_tunnel>(0, encode_scheme::lep_v0);
	server->set_encryption_key("loopback-test-key");
	client->set_encryption_key("loopback-test-key");

	std::mutex mutex;
	std::set<uint32_t> received;
	client->set_packet_received_callback([&](const std::vector<uint8_t>& data, const auto&) {
		std::lock_guard<std::mutex> lock(mutex);
		received.insert((data[1] << 16) | (data[2] << 8) | data[3]);
	});

	// The client's legacy probe establishes it on the server one round trip
	// before the challenge-response confirm resets the server's session. Traffic
	// the server sends in between uses packet ids that are numbered again from
	// zero after that reset.
	server->set_connection_callback([&](const boost::asio::ip::udp::endpoint& peer) {
		for (uint32_t i = 0; i < before_reset; ++i)
			server->send_to_peer_async(tagged_packet(1000 + i), peer);
	});

	server->start();
	server->run_in_thread();
	client->start();
	client->run_in_thread();
	client->connect_to_peer(boost::asio::ip::udp::endpoint(
		boost::asio::ip::make_address_v4("127.0.0.1"),
		server->get_local_endpoint().port()));

	bool ok = true;
	ok &= expect(wait_until([&] {
		return server->get_stats().verified_handshake_replies.load() > 0 &&
			client->get_stats().verified_handshake_replies.load() > 0;
	}), "loopback reconnect handshake should complete");

	const auto peers = server->get_connected_peers();
	ok &= expect(peers.size() == 1, "server should have exactly one connected peer");
	if (peers.size() == 1)
	{
		for (uint32_t i = 0; i < after_reset; ++i)
			server->send_to_peer_async(tagged_packet(2000 + i), peers.front());
	}

	const auto delivered = [&](uint32_t first, uint32_t count) {
		std::lock_guard<std::mutex> lock(mutex);
		uint32_t total = 0;
		for (uint32_t tag = first; tag < first + count; ++tag)
			total += received.contains(tag) ? 1 : 0;
		return total;
	};
	wait_until([&] { return delivered(2000, after_reset) == after_reset; });

	ok &= expect(delivered(1000, before_reset) == before_reset,
		"traffic sent before the handshake completed should arrive");
	ok &= expect(delivered(2000, after_reset) == after_reset,
		"packet ids reused after the verified reset must not be dropped as duplicates");

	client->stop();
	server->stop();

	if (!ok)
		return 1;

	std::cout << "Tunnel loopback tests passed\n";
	return 0;
}
