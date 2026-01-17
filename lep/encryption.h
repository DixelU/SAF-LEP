#pragma once

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <cstdint>
#include <string>
#include <array>
#include <cstring>

namespace dixelu
{
namespace lep
{
namespace crypto
{

// Key size for the encryption (256 bits)
constexpr size_t KEY_SIZE = 32;

// Simple hash-based key derivation from seed string
// Uses a variant of DJB2 hash combined with mixing to produce KEY_SIZE bytes
inline std::array<uint8_t, KEY_SIZE> derive_key(const std::string& seed)
{
	std::array<uint8_t, KEY_SIZE> key{};

	if (seed.empty())
		return key;

	// Initial hash using DJB2 variant
	uint64_t hash1 = 5381;
	uint64_t hash2 = 0x9e3779b97f4a7c15ULL; // Golden ratio fractional bits

	for (size_t i = 0; i < seed.size(); ++i)
	{
		hash1 = ((hash1 << 5) + hash1) ^ static_cast<uint8_t>(seed[i]);
		hash2 = ((hash2 << 7) ^ (hash2 >> 3)) + static_cast<uint8_t>(seed[i]) * (i + 1);
	}

	// Fill key bytes using hash mixing
	uint64_t state1 = hash1;
	uint64_t state2 = hash2;

	for (size_t i = 0; i < KEY_SIZE; i += 8)
	{
		// Mix the states
		state1 = state1 * 6364136223846793005ULL + 1442695040888963407ULL;
		state2 ^= state1;
		state2 = (state2 << 17) | (state2 >> 47);
		state2 *= 0xbf58476d1ce4e5b9ULL;

		// Extract bytes
		for (size_t j = 0; j < 8 && (i + j) < KEY_SIZE; ++j)
		{
			key[i + j] = static_cast<uint8_t>((state2 >> (j * 8)) & 0xFF);
		}

		state1 ^= state2;
	}

	return key;
}

// Stream cipher state for generating keystream
struct cipher_state
{
	std::array<uint8_t, KEY_SIZE> key{};
	uint64_t state[4]{};

	cipher_state() = default;

	explicit cipher_state(const std::array<uint8_t, KEY_SIZE>& k) : key(k)
	{
	}

	// Initialize state for a specific packet (using packet index for uniqueness)
	void init_for_packet(uint32_t packet_index)
	{
		// Load key into state
		std::memcpy(&state[0], key.data(), 8);
		std::memcpy(&state[1], key.data() + 8, 8);
		std::memcpy(&state[2], key.data() + 16, 8);
		std::memcpy(&state[3], key.data() + 24, 8);

		// Mix in packet index for per-packet uniqueness
		state[0] ^= static_cast<uint64_t>(packet_index);
		state[1] ^= static_cast<uint64_t>(packet_index) << 32;
		state[2] ^= ~static_cast<uint64_t>(packet_index);
		state[3] ^= static_cast<uint64_t>(packet_index) * 0x9e3779b97f4a7c15ULL;

		// Initial mixing rounds
		for (int i = 0; i < 4; ++i)
		{
			mix_state();
		}
	}

	// Generate next keystream byte
	uint8_t next_byte()
	{
		// Simplified xorshift-based PRNG with mixing
		uint64_t t = state[1] << 17;

		state[2] ^= state[0];
		state[3] ^= state[1];
		state[1] ^= state[2];
		state[0] ^= state[3];

		state[2] ^= t;
		state[3] = (state[3] << 45) | (state[3] >> 19);

		return static_cast<uint8_t>((state[0] + state[3]) >> 56);
	}

private:
	void mix_state()
	{
		uint64_t t = state[1] << 17;
		state[2] ^= state[0];
		state[3] ^= state[1];
		state[1] ^= state[2];
		state[0] ^= state[3];
		state[2] ^= t;
		state[3] = (state[3] << 45) | (state[3] >> 19);
	}
};

// Encrypt/decrypt data in place (XOR is symmetric)
// packet_index provides per-packet uniqueness
inline void transform(
	const std::array<uint8_t, KEY_SIZE>& key,
	uint32_t packet_index,
	uint8_t* data,
	size_t size)
{
	if (size == 0)
		return;

	// Check if key is all zeros (no encryption)
	bool has_key = false;
	for (size_t i = 0; i < KEY_SIZE; ++i)
	{
		if (key[i] != 0)
		{
			has_key = true;
			break;
		}
	}

	if (!has_key)
		return;

	cipher_state state(key);
	state.init_for_packet(packet_index);

	for (size_t i = 0; i < size; ++i)
	{
		data[i] ^= state.next_byte();
	}
}

// Convenience overload for vectors
inline void transform(
	const std::array<uint8_t, KEY_SIZE>& key,
	uint32_t packet_index,
	std::vector<uint8_t>& data)
{
	transform(key, packet_index, data.data(), data.size());
}

// Encrypt and return new vector
inline std::vector<uint8_t> encrypt(
	const std::array<uint8_t, KEY_SIZE>& key,
	uint32_t packet_index,
	const uint8_t* data,
	size_t size)
{
	std::vector<uint8_t> result(data, data + size);
	transform(key, packet_index, result);
	return result;
}

// Decrypt and return new vector (same as encrypt due to XOR symmetry)
inline std::vector<uint8_t> decrypt(
	const std::array<uint8_t, KEY_SIZE>& key,
	uint32_t packet_index,
	const uint8_t* data,
	size_t size)
{
	return encrypt(key, packet_index, data, size);
}

} // namespace crypto
} // namespace lep
} // namespace dixelu

#endif // ENCRYPTION_H
