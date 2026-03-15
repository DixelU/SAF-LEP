#pragma once

#ifndef LOW_ENTROPY_PROTOCOL_H
#define LOW_ENTROPY_PROTOCOL_H

#include <vector>
#include <span>
#include <cstdint>
#include <stdexcept>

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
	static constexpr uint8_t ground_state{'T'};
	for (uint16_t value = 0; value < (1 << length); value++)
	{
		const auto encoded_value = encode_lep(static_cast<uint8_t>(value), length, ground_state);
		const auto decoded_value = decode_lep(encoded_value, ground_state);
		if (decoded_value.len != length || decoded_value.data != value)
			return static_cast<uint8_t>(value);
	}

	return 1 << length;
}

// inline constexpr auto __check_lep_integrity = embedded_test(5);

struct lep_v0_encoder_state
{
	std::uint32_t index = 0;
	std::uint32_t g_seed = 0;

	static constexpr uint8_t HEADER = 0b00110001;
	//				    ^^  ^^^^
	//			       version  "hash"

	constexpr std::uint32_t fastrand()
	{
		g_seed = 21401u * g_seed + 25311u;
		return (g_seed >> 8u) & 0xFFu;
	}
};

constexpr std::vector<uint8_t> put_lep(lep_v0_encoder_state &state, const uint8_t *data, std::size_t size)
{
	constexpr int header_size = 10;
	if (size > (1 << (24 - 2)))
		return {};

	const uint8_t ground_state = '^' - (state.fastrand() & 0x7);
	std::vector<uint8_t> encoded_data(header_size, 0);
	encoded_data.reserve(size * 3 + header_size);

	encoded_data[0] = lep_v0_encoder_state::HEADER;
	encoded_data[1] = 0b00100001;
	//		      ^
	//		burst bit;	everything else is "payload type"; 33 ~ MP2T

	encoded_data[2] = (state.index >> 8) & 0xFF;
	encoded_data[3] = state.index & 0xFF;
	encoded_data[8] = (state.index >> 16) & 0xFF ^ encoded_data[2];
	encoded_data[9] = ((state.index >> 24) & 0xFF) ^ encoded_data[3] ^ encoded_data[2];
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

		encoded_data.push_back(encode_lep(byte, possible_bits_count, ground_state));

		random_value >>= 2;
		if (!random_value)
			random_value = state.fastrand();

		bits_left -= possible_bits_count;
		byte >>= possible_bits_count;
	}

	encoded_data[5] = (encoded_data.size() >> 16)	& 0xFF;
	encoded_data[6] = (encoded_data.size() >> 8)	& 0xFF;
	encoded_data[7] = (encoded_data.size())		& 0xFF;

	return encoded_data;
}

struct lep_decoded_packet
{
	std::vector<uint8_t> data;
	uint32_t index = 0;
};

constexpr lep_decoded_packet get_lep(const uint8_t *data, std::size_t size)
{
	constexpr int header_size = 10;
	if (size <= header_size)
		return {};

	uint8_t first_header_byte = data[0];
	if (first_header_byte != lep_v0_encoder_state::HEADER)
		return {};

	lep_decoded_packet decoded_packet;
	uint8_t second_header_byte = data[1];

	decoded_packet.index = (data[2] << 8) | data[3];
	decoded_packet.index |= (data[8] ^ data[2]) << 16;
	decoded_packet.index |= (data[9] ^ data[2] ^ data[3]) << 24;

	uint8_t ground_state = second_header_byte ^ data[4];
	uint8_t bit_index = 0;
	uint8_t buffered_byte = 0;

	std::span payload(data + header_size, size - header_size);
	for (const uint8_t byte : payload)
	{
		const auto decoded_value = decode_lep(byte, ground_state);
		buffered_byte |= decoded_value.data << bit_index;
		bit_index += decoded_value.len;

		if (bit_index == 8)
		{
			decoded_packet.data.push_back(buffered_byte);
			bit_index = 0;
			buffered_byte = 0;
		}
		else if (bit_index > 8)
			throw std::runtime_error("LEP decoder: bit index overflow");
	}

	return decoded_packet;
}

constexpr bool compiletime_encoder_test()
{
	lep_v0_encoder_state __state{ 0, 0xAF65423 };
	std::vector<uint8_t> values;

	for (int i = 0; i < 27; i++)
		values.push_back(__state.fastrand());

	const auto encoded_values = put_lep(__state, values.data(), values.size());
	const auto decoded_values = get_lep(encoded_values.data(), encoded_values.size());

	return decoded_values.data == values;
}

// constexpr bool __lep_v0_encoder_test = compiletime_encoder_test();

} // namespace v0

namespace crc8
{

constexpr std::uint8_t const CRC8X[] = {
    0x00, 0x31, 0x62, 0x53, 0xc4, 0xf5, 0xa6, 0x97, 0xb9, 0x88, 0xdb, 0xea, 0x7d,
    0x4c, 0x1f, 0x2e, 0x43, 0x72, 0x21, 0x10, 0x87, 0xb6, 0xe5, 0xd4, 0xfa, 0xcb,
    0x98, 0xa9, 0x3e, 0x0f, 0x5c, 0x6d, 0x86, 0xb7, 0xe4, 0xd5, 0x42, 0x73, 0x20,
    0x11, 0x3f, 0x0e, 0x5d, 0x6c, 0xfb, 0xca, 0x99, 0xa8, 0xc5, 0xf4, 0xa7, 0x96,
    0x01, 0x30, 0x63, 0x52, 0x7c, 0x4d, 0x1e, 0x2f, 0xb8, 0x89, 0xda, 0xeb, 0x3d,
    0x0c, 0x5f, 0x6e, 0xf9, 0xc8, 0x9b, 0xaa, 0x84, 0xb5, 0xe6, 0xd7, 0x40, 0x71,
    0x22, 0x13, 0x7e, 0x4f, 0x1c, 0x2d, 0xba, 0x8b, 0xd8, 0xe9, 0xc7, 0xf6, 0xa5,
    0x94, 0x03, 0x32, 0x61, 0x50, 0xbb, 0x8a, 0xd9, 0xe8, 0x7f, 0x4e, 0x1d, 0x2c,
    0x02, 0x33, 0x60, 0x51, 0xc6, 0xf7, 0xa4, 0x95, 0xf8, 0xc9, 0x9a, 0xab, 0x3c,
    0x0d, 0x5e, 0x6f, 0x41, 0x70, 0x23, 0x12, 0x85, 0xb4, 0xe7, 0xd6, 0x7a, 0x4b,
    0x18, 0x29, 0xbe, 0x8f, 0xdc, 0xed, 0xc3, 0xf2, 0xa1, 0x90, 0x07, 0x36, 0x65,
    0x54, 0x39, 0x08, 0x5b, 0x6a, 0xfd, 0xcc, 0x9f, 0xae, 0x80, 0xb1, 0xe2, 0xd3,
    0x44, 0x75, 0x26, 0x17, 0xfc, 0xcd, 0x9e, 0xaf, 0x38, 0x09, 0x5a, 0x6b, 0x45,
    0x74, 0x27, 0x16, 0x81, 0xb0, 0xe3, 0xd2, 0xbf, 0x8e, 0xdd, 0xec, 0x7b, 0x4a,
    0x19, 0x28, 0x06, 0x37, 0x64, 0x55, 0xc2, 0xf3, 0xa0, 0x91, 0x47, 0x76, 0x25,
    0x14, 0x83, 0xb2, 0xe1, 0xd0, 0xfe, 0xcf, 0x9c, 0xad, 0x3a, 0x0b, 0x58, 0x69,
    0x04, 0x35, 0x66, 0x57, 0xc0, 0xf1, 0xa2, 0x93, 0xbd, 0x8c, 0xdf, 0xee, 0x79,
    0x48, 0x1b, 0x2a, 0xc1, 0xf0, 0xa3, 0x92, 0x05, 0x34, 0x67, 0x56, 0x78, 0x49,
    0x1a, 0x2b, 0xbc, 0x8d, 0xde, 0xef, 0x82, 0xb3, 0xe0, 0xd1, 0x46, 0x77, 0x24,
    0x15, 0x3b, 0x0a, 0x59, 0x68, 0xff, 0xce, 0x9d, 0xac};

constexpr std::uint8_t crc8x_fast(std::uint8_t crc, std::uint8_t const* data, std::size_t len)
{
	if (data == nullptr)
		return 0xff;

	crc &= 0xff;
	while (len--)
		crc = CRC8X[crc ^ *data++];

	return crc;
}

constexpr std::uint8_t crc8x(std::uint8_t const* data, std::size_t len)
{
	constexpr std::uint8_t nullval = crc8x_fast(0, nullptr, 0);
	return crc8x_fast(nullval, data, len);
}

} // crc8

namespace v1
{

constexpr std::vector<uint8_t> put_lep(v0::lep_v0_encoder_state& state, const uint8_t* data, std::size_t size)
{
	if (size > (1 << (24 - 2)))
		return {};

	const uint8_t ground_state = '_' - (state.fastrand() & 0x7);
	std::vector<uint8_t> encoded_data;
	encoded_data.reserve(size * 3);

	const uint8_t* end_ptr = data + size;
	const uint8_t* ptr = data;

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

		encoded_data.push_back(v0::encode_lep(byte, possible_bits_count, ground_state));

		random_value >>= 2;
		if (!random_value)
			random_value = state.fastrand();

		bits_left -= possible_bits_count;
		byte >>= possible_bits_count;
	}

	auto crc = crc8::crc8x(encoded_data.data(), encoded_data.size());
	uint8_t enc_ground_state = crc ^ ground_state;

	std::uint8_t index_split[] = { 
		static_cast<std::uint8_t>(state.index & 0xFF),
		static_cast<std::uint8_t>((state.index >> 8) & 0xFF),
		static_cast<std::uint8_t>((state.index >> 16) & 0xFF),
		static_cast<std::uint8_t>((state.index >> 24) & 0xFF)
	};

	state.index++;

	encoded_data.push_back(crc);
	encoded_data.push_back(enc_ground_state);
	encoded_data.push_back((enc_ground_state ^ index_split[0]) ^ (crc >> 4));
	encoded_data.push_back((enc_ground_state ^ index_split[1]) ^ (crc + enc_ground_state));
	encoded_data.push_back(enc_ground_state ^ index_split[2]);
	encoded_data.push_back(enc_ground_state ^ index_split[3]);

	return encoded_data;
}

constexpr v0::lep_decoded_packet get_lep(const uint8_t* data, std::size_t size)
{
	constexpr int tail_control_size = 6;
	if (size <= tail_control_size)
		return {};

	const uint8_t* packet_meta = data + size - tail_control_size;

	uint8_t crc = crc8::crc8x(data, size - tail_control_size);
	if (crc != packet_meta[0])
		return {};

	uint8_t enc_ground_state = packet_meta[1];
	uint8_t ground_state = crc ^ enc_ground_state;

	std::uint8_t index_split[] = {
		static_cast<std::uint8_t>(packet_meta[2] ^ enc_ground_state ^ (crc >>  4)),
		static_cast<std::uint8_t>(packet_meta[3] ^ enc_ground_state ^ (crc + enc_ground_state)),
		static_cast<std::uint8_t>(packet_meta[4] ^ enc_ground_state),
		static_cast<std::uint8_t>(packet_meta[5] ^ enc_ground_state)
	};

	v0::lep_decoded_packet decoded_packet;

	decoded_packet.index = index_split[0] | (index_split[1] << 8);
	decoded_packet.index |= (index_split[2] << 16) | (index_split[3] << 24);

	uint8_t bit_index = 0;
	uint8_t buffered_byte = 0;

	std::span payload(data, packet_meta - data);
	for (const uint8_t byte : payload)
	{
		const auto decoded_value = v0::decode_lep(byte, ground_state);
		buffered_byte |= decoded_value.data << bit_index;
		bit_index += decoded_value.len;

		if (bit_index == 8)
		{
			decoded_packet.data.push_back(buffered_byte);
			bit_index = 0;
			buffered_byte = 0;
		}
		else if (bit_index > 8)
			throw std::runtime_error("LEP decoder: bit index overflow");
	}

	return decoded_packet;
}

constexpr bool compiletime_encoder_test()
{
	v0::lep_v0_encoder_state __state{0, 0xAF65423};
	std::vector<uint8_t> values;

	for (int i = 0; i < 44; i++)
	{
		values.push_back(__state.fastrand());

		const auto encoded_values = v1::put_lep(__state, values.data(), values.size());
		const auto decoded_values = v1::get_lep(encoded_values.data(), encoded_values.size());

		if (values != decoded_values.data || __state.index != decoded_values.index + 1)
			return false;
	}

	return true;
}

constexpr bool asdf = compiletime_encoder_test();

} // namespace v1

} // namespace details

struct raw_lep_v0;
struct raw_lep_v1;

struct packet
{
	std::vector<std::uint8_t> data;
	uint32_t index = 0;
};

template<typename tag>
struct low_entropy_protocol
{
	static constexpr std::vector<std::uint8_t>
		encode(const std::uint8_t *data, std::size_t size, uint32_t index = 0);

	static constexpr packet
		decode(const std::uint8_t *data, std::size_t size);
};

template <>
constexpr std::vector<std::uint8_t> low_entropy_protocol<raw_lep_v0>::encode(
	const std::uint8_t* data, std::size_t size, uint32_t index)
{
	details::v0::lep_v0_encoder_state encoder;
	encoder.index = index;

	if consteval
	{
		encoder.g_seed = index ^ size;
	}
	else
	{
		encoder.g_seed = static_cast<uint32_t>(reinterpret_cast<std::intptr_t>(data) ^ index);
	}

	return details::v0::put_lep(encoder, data, size);
}

template <>
constexpr packet low_entropy_protocol<raw_lep_v0>::decode(const std::uint8_t* data, std::size_t size)
{
	auto packet_data = details::v0::get_lep(data, size);

	return packet{.data = packet_data.data, .index = packet_data.index};
}

template <>
constexpr std::vector<std::uint8_t> low_entropy_protocol<raw_lep_v1>::encode(
	const std::uint8_t* data, std::size_t size, uint32_t index)
{
	details::v0::lep_v0_encoder_state encoder;
	encoder.index = index;

	if consteval
	{
		encoder.g_seed = index ^ size;
	}
	else
	{
		encoder.g_seed = static_cast<uint32_t>(reinterpret_cast<std::intptr_t>(data) ^ index);
	}

	return details::v1::put_lep(encoder, data, size);
}

template <>
constexpr packet low_entropy_protocol<raw_lep_v1>::decode(const std::uint8_t* data, std::size_t size)
{
	auto packet_data = details::v1::get_lep(data, size);

	return packet{.data = packet_data.data, .index = packet_data.index};
}

} // namespace lep
} // namespace dixelu

#endif // LOW_ENTROPY_PROTOCOL_H
