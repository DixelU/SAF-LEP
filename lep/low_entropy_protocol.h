#pragma once

#ifndef LOW_ENTROPY_PROTOCOL_H
#define LOW_ENTROPY_PROTOCOL_H

#include <vector>
#include <span>
#include <cstdint>

namespace dixelu
{
namespace lep
{

namespace details
{
namespace v0
{

constexpr uint8_t encode_lep(uint8_t byte, uint8_t take_bits_count, uint8_t ground_state)
{
	const uint8_t value_mask = (1 << (take_bits_count - 1)) - 1;
	const uint8_t sign_mask = 1 << (take_bits_count - 1);
	const uint8_t first_header = 1 << take_bits_count;

	const uint8_t encoded_value = (byte & value_mask) | first_header;

	const uint8_t value = (sign_mask & byte) ? ground_state + encoded_value : ground_state - encoded_value;

	return value;
}

constexpr unsigned int ones32(unsigned int x)
{
	// 32-bit recursive reduction using SWAR...
	// but the first step is mapping 2-bit values
	// into a sum of 2 1-bit values in a sneaky way

	x -= ((x >> 1) & 0x55555555);
	x = (((x >> 2) & 0x33333333) + (x & 0x33333333));
	x = (((x >> 4) + x) & 0x0f0f0f0f);
	x += (x >> 8);
	x += (x >> 16);
	return x & 0x0000003f;
}

// https://aggregate.org/MAGIC/#Log2%20of%20an%20Integer
constexpr unsigned int floor_log2(unsigned int x)
{
	x |= (x >> 1);
	x |= (x >> 2);
	x |= (x >> 4);
	x |= (x >> 8);
	x |= (x >> 16);
	return ones32(x) - 1;
}

struct lep_data { uint8_t len: 4; uint8_t data: 4; };
constexpr lep_data decode_lep(uint8_t byte, uint8_t ground_state)
{
	const int16_t signed_value =
		static_cast<int16_t>(static_cast<uint16_t>(byte)) -
		static_cast<int16_t>(static_cast<uint16_t>(ground_state));

	const bool first_bit = signed_value > 0;

	const uint8_t real_value = first_bit ? signed_value : -signed_value;
	const uint8_t take_bits_count = floor_log2(real_value);

	const uint8_t mask = take_bits_count >= 1 ? ((1 << (take_bits_count - 1)) - 1) : 0;
	const uint8_t value = (real_value & mask) | ((first_bit) << (take_bits_count - 1));

	return lep_data{ .len = take_bits_count, .data = value };
}

constexpr uint8_t embedded_test(uint8_t length)
{
	constexpr static uint8_t ground_state = 'T';
	for (uint16_t value = 0; value < (1 << length); value++)
	{
		const auto encoded_value = encode_lep(value, length, ground_state);
		const auto decoded_value = decode_lep(encoded_value, ground_state);
		if (decoded_value.len != length || decoded_value.data != value)
			return value;
	}

	return 1 << length;
}

inline constexpr auto __check = embedded_test(1);

struct lep_v0_encoder_state
{
	std::uint16_t index = 0;
	std::uint32_t g_seed = 0;

	int fastrand()
	{
		g_seed = 21401 * g_seed + 25311;
		return (g_seed >> 8) & 0xFF;
	}
};

std::vector<uint8_t> put_lep_v0(lep_v0_encoder_state &state, const uint8_t *data, std::size_t size)
{
	constexpr int header = 8;
	if (size > (1 << (24 - 2)))
		return {};

	const uint8_t ground_state = 'T' - state.fastrand() & 0x7;
	std::vector<uint8_t> encoded_data(header, 0);
	encoded_data.reserve(size * 3);

	encoded_data[0] = 0b00110000;
	//		    ^^  ^^^^
	//		version	 "hash"

	encoded_data[1] = 0b00100001;
	//		    ^
	//		burst bit;	everything else is "payload type"; 33 ~ MP2T

	encoded_data[2] = state.index >> 8;
	encoded_data[3] = state.index & 0xFF;
	state.index++;

	encoded_data[4] = ground_state ^ encoded_data[1]; // ground state bit;
	encoded_data[5] = 0;	// size
	encoded_data[6] = 0;	// size
	encoded_data[7] = 0;	// size

	const uint8_t *end_ptr = data + size;
	const uint8_t *ptr = data;

	uint8_t byte = 0;
	uint8_t bits_left = 0;
	uint8_t random_value = state.fastrand();

	while (ptr < end_ptr || bits_left > 0)
	{
		if (bits_left == 0)
		{
			bits_left = 8;
			byte = *ptr;
			ptr++;
		}

		const uint8_t take_bits_count = (random_value & 0x3) + 1;
		const uint8_t possible_bits_count = std::min(take_bits_count, bits_left);

		encoded_data.push_back(encode_lep(byte, take_bits_count, ground_state));

		random_value >>= 2;
		if (!random_value)
			random_value = state.fastrand();

		bits_left -= possible_bits_count;
	}

	encoded_data[5] = (encoded_data.size() >> 16)	& 0xFF;
	encoded_data[6] = (encoded_data.size() >> 8)	& 0xFF;
	encoded_data[7] = (encoded_data.size())		& 0xFF;

	return encoded_data;
}

} // namespace v0

} // namespace details

struct voip_v0;
struct htm_v0;

template<typename tag>
struct low_entropy_protocol
{
	static constexpr std::vector<std::uint8_t> encode(const std::uint8_t *data, std::size_t size);
	static constexpr std::vector<std::uint8_t> decode(const std::uint8_t *data, std::size_t size);
};

} // namespace lep
} // namespace dixelu

#endif // LOW_ENTROPY_PROTOCOL_H
