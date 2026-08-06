#include <array>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "../lep/encryption.h"
#include "../lep/low_entropy_protocol.h"
#include "../udp_tunnel/ip_routing.h"

namespace
{

bool expect(bool condition, const char* message)
{
	if (!condition)
		std::cerr << "FAILED: " << message << '\n';
	return condition;
}

} // namespace

int main()
{
	using dixelu::lep::low_entropy_protocol;
	using dixelu::lep::raw_packet;

	constexpr uint32_t packet_index = 0x1234ABCD;
	const std::vector<uint8_t> cleartext{
		0x45, 0x00, 0x00, 0x54, 0xDE, 0xAD, 0xBE, 0xEF
	};
	const auto key = dixelu::lep::crypto::derive_key("raw-mode-test-key");

	bool ok = true;
	ok &= expect(dixelu::lep::crypto::has_key(key), "derived key should enable encryption");
	ok &= expect(!dixelu::lep::crypto::has_key({}), "zero key should disable encryption");

	std::vector<uint8_t> encrypted = cleartext;
	dixelu::lep::crypto::transform(key, packet_index, encrypted);
	ok &= expect(encrypted != cleartext, "payload should be encrypted before raw framing");

	const auto wire = low_entropy_protocol<raw_packet>::encode(
		encrypted.data(), encrypted.size(), packet_index);
	ok &= expect(wire.size() == cleartext.size() + sizeof(packet_index),
		"raw framing should add only a four-byte index");
	ok &= expect(wire.size() >= 4 &&
		wire[0] == 0x12 && wire[1] == 0x34 && wire[2] == 0xAB && wire[3] == 0xCD,
		"packet index should use network byte order");

	auto decoded = low_entropy_protocol<raw_packet>::decode(wire.data(), wire.size());
	ok &= expect(decoded.index == packet_index, "raw decoder should preserve the packet index");
	ok &= expect(decoded.data == encrypted, "raw decoder should preserve the encrypted payload");

	dixelu::lep::crypto::transform(key, decoded.index, decoded.data);
	ok &= expect(decoded.data == cleartext, "decoded payload should decrypt to the original");

	const std::array<uint8_t, 3> truncated{0x12, 0x34, 0xAB};
	decoded = low_entropy_protocol<raw_packet>::decode(truncated.data(), truncated.size());
	ok &= expect(decoded.data.empty() && decoded.index == 0,
		"raw decoder should reject a truncated packet index");

	std::vector<uint8_t> ipv4(20, 0);
	ipv4[0] = 0x45;
	ipv4[3] = 20;
	ipv4[12] = 10; ipv4[15] = 7;
	ipv4[16] = 10; ipv4[19] = 9;
	auto packet = dixelu::udp::routing::inspect_ip_packet(ipv4);
	ok &= expect(packet.has_value(), "routing parser should accept a complete IPv4 packet");
	ok &= expect(packet && packet->source[3] == 7 && packet->destination[3] == 9,
		"routing parser should extract IPv4 source and destination addresses");
	ok &= expect(packet && dixelu::udp::routing::has_usable_source(*packet),
		"ordinary IPv4 source should be eligible for route learning");

	ipv4[16] = 255; ipv4[17] = 255; ipv4[18] = 255; ipv4[19] = 255;
	packet = dixelu::udp::routing::inspect_ip_packet(ipv4);
	ok &= expect(packet && dixelu::udp::routing::has_group_destination(*packet),
		"limited IPv4 broadcast should retain fan-out semantics");

	std::vector<uint8_t> ipv6(40, 0);
	ipv6[0] = 0x60;
	ipv6[23] = 7;
	ipv6[39] = 9;
	packet = dixelu::udp::routing::inspect_ip_packet(ipv6);
	ok &= expect(packet && packet->version == 6 && packet->address_size == 16,
		"routing parser should accept a complete IPv6 packet");

	const auto broadcast = dixelu::udp::routing::subnet_broadcast_key(
		"10.0.0.7", "255.255.255.0");
	const std::array<uint8_t, 4> expected_broadcast{10, 0, 0, 255};
	ok &= expect(broadcast && *broadcast == dixelu::udp::routing::address_key(
		4, expected_broadcast.data(), expected_broadcast.size()),
		"routing should derive the configured subnet broadcast address");

	using dixelu::udp::routing::learn_result;
	dixelu::udp::routing::route_bindings routes;
	const std::string address_a{"\x04\x0a\x00\x00\x02", 5};
	const std::string address_b{"\x04\x0a\x00\x00\x03", 5};
	const std::string address_v6{"\x06\x20\x01", 3};
	const std::string peer_a = "peer-a";
	const std::string peer_b = "peer-b";
	ok &= expect(routes.learn(address_a, peer_a) == learn_result::learned,
		"first VPN address claim should be learned");
	ok &= expect(routes.learn(address_a, peer_a) == learn_result::unchanged,
		"repeated matching VPN address claim should be accepted");
	ok &= expect(routes.learn(address_a, peer_b) == learn_result::address_conflict,
		"duplicate VPN address from another peer should be rejected");
	ok &= expect(routes.learn(address_b, peer_a) == learn_result::peer_conflict,
		"one peer should not claim multiple VPN addresses in one address family");
	ok &= expect(routes.learn(address_v6, peer_a) == learn_result::learned,
		"one peer may own one IPv4 and one IPv6 VPN address");
	routes.erase_peer(peer_a);
	ok &= expect(routes.learn(address_a, peer_b) == learn_result::learned,
		"a VPN address should be reusable after its stale peer is erased");

	std::mt19937 generator(0x5AFE1E50);
	for (size_t i = 0; i < 1024; ++i)
	{
		const unsigned octet = dixelu::udp::routing::random_client_host_octet(generator);
		ok &= expect(octet >= 2 && octet <= 254,
			"automatic client host octet should exclude network, server, and broadcast values");
	}

	if (!ok)
		return 1;

	std::cout << "Protocol and routing tests passed\n";
	return 0;
}
