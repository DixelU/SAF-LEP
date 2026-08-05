#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#include "../lep/encryption.h"
#include "../lep/low_entropy_protocol.h"

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

	if (!ok)
		return 1;

	std::cout << "Raw packet protocol tests passed\n";
	return 0;
}
