#pragma once

#ifndef STRONG_ENCRYPTION_H
#define STRONG_ENCRYPTION_H

#include "encryption.h"

#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <algorithm>

namespace dixelu
{
namespace lep
{
namespace crypto
{
namespace strong
{

// ChaCha20-Poly1305 AEAD (RFC 8439) + legacy XOR transform as outer obfuscation.
// Same 32-byte key derived by derive_key() in encryption.h.
// Nonce is built from packet_index (96-bit, little-endian, zero-padded).
//
// Wire format produced by strong_encrypt:
//   [ciphertext (size bytes)][poly1305 tag (16 bytes)]
// then legacy crypto::transform() XOR is applied across the whole buffer.

constexpr size_t TAG_SIZE = 16;
constexpr size_t NONCE_SIZE = 12;

namespace detail
{

inline uint32_t load_le32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void store_le32(uint8_t* p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

inline void store_le64(uint8_t* p, uint64_t v)
{
	store_le32(p, (uint32_t)v);
	store_le32(p + 4, (uint32_t)(v >> 32));
}

inline uint32_t rotl32(uint32_t x, int n)
{
	return (x << n) | (x >> (32 - n));
}

inline void chacha20_quarterround(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
	a += b; d ^= a; d = rotl32(d, 16);
	c += d; b ^= c; b = rotl32(b, 12);
	a += b; d ^= a; d = rotl32(d,  8);
	c += d; b ^= c; b = rotl32(b,  7);
}

inline void chacha20_block(
	const uint8_t key[32], const uint8_t nonce[12],
	uint32_t counter, uint8_t out[64])
{
	uint32_t state[16];
	state[0] = 0x61707865; state[1] = 0x3320646e;
	state[2] = 0x79622d32; state[3] = 0x6b206574;
	for (int i = 0; i < 8; ++i)
		state[4 + i] = load_le32(key + 4 * i);
	state[12] = counter;
	state[13] = load_le32(nonce + 0);
	state[14] = load_le32(nonce + 4);
	state[15] = load_le32(nonce + 8);

	uint32_t w[16];
	std::memcpy(w, state, sizeof(state));

	for (int i = 0; i < 10; ++i)
	{
		chacha20_quarterround(w[0], w[4], w[ 8], w[12]);
		chacha20_quarterround(w[1], w[5], w[ 9], w[13]);
		chacha20_quarterround(w[2], w[6], w[10], w[14]);
		chacha20_quarterround(w[3], w[7], w[11], w[15]);
		chacha20_quarterround(w[0], w[5], w[10], w[15]);
		chacha20_quarterround(w[1], w[6], w[11], w[12]);
		chacha20_quarterround(w[2], w[7], w[ 8], w[13]);
		chacha20_quarterround(w[3], w[4], w[ 9], w[14]);
	}

	for (int i = 0; i < 16; ++i)
		store_le32(out + 4 * i, w[i] + state[i]);
}

inline void chacha20_xor(
	const uint8_t key[32], const uint8_t nonce[12],
	uint32_t counter, uint8_t* data, size_t size)
{
	uint8_t block[64];
	size_t offset = 0;
	while (offset < size)
	{
		chacha20_block(key, nonce, counter, block);
		const size_t n = std::min<size_t>(64, size - offset);
		for (size_t i = 0; i < n; ++i)
			data[offset + i] ^= block[i];
		offset += n;
		++counter;
	}
}

// poly1305-donna-32: 130-bit math with 26-bit limbs
struct poly1305_state
{
	uint32_t r[5];
	uint32_t h[5];
	uint32_t pad[4];
	size_t leftover;
	uint8_t buffer[16];
	uint8_t final_flag;
};

inline void poly1305_init(poly1305_state& st, const uint8_t key[32])
{
	st.r[0] = (load_le32(key +  0)     ) & 0x3ffffff;
	st.r[1] = (load_le32(key +  3) >> 2) & 0x3ffff03;
	st.r[2] = (load_le32(key +  6) >> 4) & 0x3ffc0ff;
	st.r[3] = (load_le32(key +  9) >> 6) & 0x3f03fff;
	st.r[4] = (load_le32(key + 12) >> 8) & 0x00fffff;

	for (int i = 0; i < 5; ++i) st.h[i] = 0;

	st.pad[0] = load_le32(key + 16);
	st.pad[1] = load_le32(key + 20);
	st.pad[2] = load_le32(key + 24);
	st.pad[3] = load_le32(key + 28);

	st.leftover = 0;
	st.final_flag = 0;
}

inline void poly1305_blocks(poly1305_state& st, const uint8_t* m, size_t bytes)
{
	const uint32_t hibit = st.final_flag ? 0u : (1u << 24);

	uint32_t r0 = st.r[0], r1 = st.r[1], r2 = st.r[2], r3 = st.r[3], r4 = st.r[4];
	uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	uint32_t h0 = st.h[0], h1 = st.h[1], h2 = st.h[2], h3 = st.h[3], h4 = st.h[4];

	while (bytes >= 16)
	{
		// h += m
		h0 += (load_le32(m +  0)     ) & 0x3ffffff;
		h1 += (load_le32(m +  3) >> 2) & 0x3ffffff;
		h2 += (load_le32(m +  6) >> 4) & 0x3ffffff;
		h3 += (load_le32(m +  9) >> 6) & 0x3ffffff;
		h4 += (load_le32(m + 12) >> 8) | hibit;

		// h *= r
		uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
		uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
		uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
		uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
		uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

		// partial reduction mod 2^130 - 5
		uint32_t c;
		c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
		d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
		d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
		d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
		d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
		h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
		h1 += c;

		m += 16;
		bytes -= 16;
	}

	st.h[0] = h0; st.h[1] = h1; st.h[2] = h2; st.h[3] = h3; st.h[4] = h4;
}

inline void poly1305_update(poly1305_state& st, const uint8_t* m, size_t bytes)
{
	if (st.leftover)
	{
		size_t want = 16 - st.leftover;
		if (want > bytes) want = bytes;
		std::memcpy(st.buffer + st.leftover, m, want);
		bytes -= want;
		m += want;
		st.leftover += want;
		if (st.leftover < 16) return;
		poly1305_blocks(st, st.buffer, 16);
		st.leftover = 0;
	}

	if (bytes >= 16)
	{
		size_t want = bytes & ~(size_t)15;
		poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	if (bytes)
	{
		std::memcpy(st.buffer + st.leftover, m, bytes);
		st.leftover += bytes;
	}
}

inline void poly1305_finish(poly1305_state& st, uint8_t mac[16])
{
	if (st.leftover)
	{
		size_t i = st.leftover;
		st.buffer[i++] = 1;
		for (; i < 16; ++i) st.buffer[i] = 0;
		st.final_flag = 1;
		poly1305_blocks(st, st.buffer, 16);
	}

	uint32_t h0 = st.h[0], h1 = st.h[1], h2 = st.h[2], h3 = st.h[3], h4 = st.h[4];
	uint32_t c;

	c = h1 >> 26; h1 &= 0x3ffffff;
	h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
	h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
	h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
	h1 += c;

	uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	uint32_t g4 = h4 + c - (1u << 26);

	uint32_t mask = (g4 >> 31) - 1; // 0 if h < p, 0xffffffff if h >= p
	g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	// fold to 128 bits
	h0 = ((h0      ) | (h1 << 26));
	h1 = ((h1 >>  6) | (h2 << 20));
	h2 = ((h2 >> 12) | (h3 << 14));
	h3 = ((h3 >> 18) | (h4 <<  8));

	uint64_t f;
	f = (uint64_t)h0 + st.pad[0];              h0 = (uint32_t)f;
	f = (uint64_t)h1 + st.pad[1] + (f >> 32);  h1 = (uint32_t)f;
	f = (uint64_t)h2 + st.pad[2] + (f >> 32);  h2 = (uint32_t)f;
	f = (uint64_t)h3 + st.pad[3] + (f >> 32);  h3 = (uint32_t)f;

	store_le32(mac +  0, h0);
	store_le32(mac +  4, h1);
	store_le32(mac +  8, h2);
	store_le32(mac + 12, h3);
}

inline bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t n)
{
	uint8_t diff = 0;
	for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
	return diff == 0;
}

// Build 12-byte nonce from 32-bit packet index.
// Per-peer packet_index is monotonic, so (key, nonce) pairs don't repeat
// as long as a key isn't shared across peers.
inline void build_nonce(uint32_t packet_index, uint8_t nonce[12])
{
	std::memset(nonce, 0, 12);
	store_le32(nonce, packet_index);
}

// Compute Poly1305 over (ciphertext || pad16 || len(0) || len(ct)) per RFC 8439.
// No AAD — we don't use it.
inline void aead_tag(
	const uint8_t poly_key[32],
	const uint8_t* ciphertext, size_t ct_size,
	uint8_t tag[16])
{
	poly1305_state st;
	poly1305_init(st, poly_key);

	poly1305_update(st, ciphertext, ct_size);
	// pad ciphertext to 16-byte boundary
	size_t rem = ct_size & 15;
	if (rem)
	{
		uint8_t zeros[16] = {0};
		poly1305_update(st, zeros, 16 - rem);
	}

	// len(AAD)=0, len(ciphertext) as little-endian u64s
	uint8_t lens[16];
	store_le64(lens + 0, 0);
	store_le64(lens + 8, (uint64_t)ct_size);
	poly1305_update(st, lens, 16);

	poly1305_finish(st, tag);
}

} // namespace detail

// Encrypt in place: appends 16-byte tag, then applies legacy XOR over the
// whole (ciphertext||tag). Grows `data` by TAG_SIZE.
inline void strong_transform_encrypt(
	const std::array<uint8_t, KEY_SIZE>& key,
	uint32_t packet_index,
	std::vector<uint8_t>& data)
{
	// No-key passthrough matches the legacy transform() behavior.
	bool has_key = false;
	for (size_t i = 0; i < KEY_SIZE; ++i) if (key[i]) { has_key = true; break; }
	if (!has_key) return;

	uint8_t nonce[12];
	detail::build_nonce(packet_index, nonce);

	// Derive one-time Poly1305 key from ChaCha20 block counter 0.
	uint8_t poly_key_block[64];
	detail::chacha20_block(key.data(), nonce, 0, poly_key_block);

	// Encrypt plaintext with counter starting at 1.
	const size_t pt_size = data.size();
	if (pt_size > 0)
		detail::chacha20_xor(key.data(), nonce, 1, data.data(), pt_size);

	// Compute tag over ciphertext.
	uint8_t tag[TAG_SIZE];
	detail::aead_tag(poly_key_block, data.data(), pt_size, tag);

	// Append tag.
	data.insert(data.end(), tag, tag + TAG_SIZE);

	// Outer obfuscation layer: legacy XOR keystream over ciphertext||tag.
	transform(key, packet_index, data);
}

// Decrypt in place: reverses legacy XOR, verifies tag, shrinks `data` by TAG_SIZE.
// Returns true on success. On failure, `data` is left in an unspecified state
// (cleared to empty to avoid leaking unauthenticated bytes).
[[nodiscard]] inline bool strong_transform_decrypt(
	const std::array<uint8_t, KEY_SIZE>& key,
	uint32_t packet_index,
	std::vector<uint8_t>& data)
{
	bool has_key = false;
	for (size_t i = 0; i < KEY_SIZE; ++i) if (key[i]) { has_key = true; break; }
	if (!has_key) return true;

	if (data.size() < TAG_SIZE)
	{
		data.clear();
		return false;
	}

	// Undo outer XOR obfuscation.
	transform(key, packet_index, data);

	uint8_t nonce[12];
	detail::build_nonce(packet_index, nonce);

	uint8_t poly_key_block[64];
	detail::chacha20_block(key.data(), nonce, 0, poly_key_block);

	const size_t ct_size = data.size() - TAG_SIZE;
	uint8_t expected_tag[TAG_SIZE];
	detail::aead_tag(poly_key_block, data.data(), ct_size, expected_tag);

	if (!detail::constant_time_equal(expected_tag, data.data() + ct_size, TAG_SIZE))
	{
		data.clear();
		return false;
	}

	// Auth OK, decrypt ciphertext.
	if (ct_size > 0)
		detail::chacha20_xor(key.data(), nonce, 1, data.data(), ct_size);

	data.resize(ct_size);
	return true;
}

} // namespace strong
} // namespace crypto
} // namespace lep
} // namespace dixelu

#endif // STRONG_ENCRYPTION_H
