#pragma once

#ifndef SAF_LEP_RECONNECT_HANDSHAKE_H
#define SAF_LEP_RECONNECT_HANDSHAKE_H

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace dixelu
{
namespace udp
{
namespace reconnect
{

constexpr size_t NONCE_SIZE = 16;
using nonce = std::array<uint8_t, NONCE_SIZE>;

enum class message_type : uint8_t
{
	request = 91,
	challenge = 92,
	confirm = 93,
	accepted = 94,
};

struct message
{
	message_type type{};
	nonce request_nonce{};
	nonce challenge_nonce{};
};

// Long-control reconnect packets use an explicit magic prefix so random data or
// another long-control extension cannot be mistaken for a session transition.
constexpr std::array<uint8_t, 4> MAGIC{'S', 'L', 'R', 'P'};
constexpr size_t HEADER_SIZE = MAGIC.size() + 2; // magic + type + long-control marker

inline bool is_reconnect_type(uint8_t value)
{
	return value >= static_cast<uint8_t>(message_type::request) &&
		value <= static_cast<uint8_t>(message_type::accepted);
}

inline bool has_reconnect_prefix(const std::vector<uint8_t>& data)
{
	return data.size() >= HEADER_SIZE &&
		std::equal(MAGIC.begin(), MAGIC.end(), data.begin()) &&
		is_reconnect_type(data[4]) && data[5] == 0;
}

inline bool is_legacy_handshake(const std::vector<uint8_t>& data)
{
	if (data.size() == 1)
		return data[0] == 0;

	// Normal tunnel framing: [packet id:4][fragment:1][fragment count:1][payload].
	// A one-byte zero payload is the legacy connection probe.
	return data.size() == 7 && data[4] == 0 && data[5] == 1 && data[6] == 0;
}

inline bool legacy_handshake_may_establish(bool is_connected)
{
	// Legacy probes have no challenge proof. They may recover a peer that has
	// already timed out, but must never reset or refresh an active session.
	return !is_connected;
}

inline std::vector<uint8_t> encode(const message& value)
{
	std::vector<uint8_t> result;
	const bool has_challenge = value.type == message_type::challenge ||
		value.type == message_type::confirm;
	result.reserve(HEADER_SIZE + NONCE_SIZE + (has_challenge ? NONCE_SIZE : 0));
	result.insert(result.end(), MAGIC.begin(), MAGIC.end());
	result.push_back(static_cast<uint8_t>(value.type));
	result.push_back(0);
	result.insert(result.end(), value.request_nonce.begin(), value.request_nonce.end());
	if (has_challenge)
		result.insert(result.end(), value.challenge_nonce.begin(), value.challenge_nonce.end());
	return result;
}

inline std::optional<message> decode(const std::vector<uint8_t>& data)
{
	if (!has_reconnect_prefix(data))
		return std::nullopt;

	message result;
	result.type = static_cast<message_type>(data[4]);
	const bool has_challenge = result.type == message_type::challenge ||
		result.type == message_type::confirm;
	const size_t expected_size = HEADER_SIZE + NONCE_SIZE +
		(has_challenge ? NONCE_SIZE : 0);
	if (data.size() != expected_size)
		return std::nullopt;

	std::copy_n(data.begin() + HEADER_SIZE, NONCE_SIZE, result.request_nonce.begin());
	if (has_challenge)
		std::copy_n(data.begin() + HEADER_SIZE + NONCE_SIZE, NONCE_SIZE,
			result.challenge_nonce.begin());
	return result;
}

enum class request_action
{
	issue_challenge,
	resend_challenge,
	resend_accepted,
	reject,
};

struct request_result
{
	request_action action = request_action::reject;
	nonce challenge_nonce{};
};

class state
{
public:
	using clock = std::chrono::steady_clock;

	void begin_outbound(const nonce& request, clock::time_point now)
	{
		outbound_ = outbound_request{request, now};
	}

	bool has_outbound() const
	{
		return outbound_.has_value();
	}

	std::optional<nonce> outbound_nonce() const
	{
		if (!outbound_)
			return std::nullopt;
		return outbound_->request;
	}

	bool outbound_expired(clock::time_point now, clock::duration lifetime) const
	{
		return outbound_ && now - outbound_->started >= lifetime;
	}

	bool expects_challenge(const nonce& request) const
	{
		return outbound_ && outbound_->request == request;
	}

	bool accept_outbound(const nonce& request)
	{
		if (!outbound_ || outbound_->request != request)
			return false;
		outbound_.reset();
		return true;
	}

	request_result receive_request(const nonce& request, const nonce& new_challenge,
		clock::time_point now, clock::duration challenge_lifetime,
		clock::duration accepted_lifetime)
	{
		expire(now, challenge_lifetime, accepted_lifetime);

		if (accepted_ && accepted_->request == request)
			return {request_action::resend_accepted, {}};

		if (inbound_)
		{
			if (inbound_->request == request)
				return {request_action::resend_challenge, inbound_->challenge};
			return {request_action::reject, {}};
		}

		inbound_ = inbound_challenge{request, new_challenge, now};
		return {request_action::issue_challenge, new_challenge};
	}

	bool confirm_inbound(const nonce& request, const nonce& challenge,
		clock::time_point now, clock::duration challenge_lifetime)
	{
		if (!inbound_ || now - inbound_->started >= challenge_lifetime ||
			inbound_->request != request || inbound_->challenge != challenge)
		{
			if (inbound_ && now - inbound_->started >= challenge_lifetime)
				inbound_.reset();
			return false;
		}

		inbound_.reset();
		return true;
	}

	void remember_accepted(const nonce& request, clock::time_point now)
	{
		accepted_ = accepted_request{request, now};
	}

	void clear()
	{
		outbound_.reset();
		inbound_.reset();
		accepted_.reset();
	}

	void clear_outbound()
	{
		outbound_.reset();
	}

private:
	struct outbound_request
	{
		nonce request{};
		clock::time_point started{};
	};

	struct inbound_challenge
	{
		nonce request{};
		nonce challenge{};
		clock::time_point started{};
	};

	struct accepted_request
	{
		nonce request{};
		clock::time_point accepted_at{};
	};

	void expire(clock::time_point now, clock::duration challenge_lifetime,
		clock::duration accepted_lifetime)
	{
		if (inbound_ && now - inbound_->started >= challenge_lifetime)
			inbound_.reset();
		if (accepted_ && now - accepted_->accepted_at >= accepted_lifetime)
			accepted_.reset();
	}

	std::optional<outbound_request> outbound_;
	std::optional<inbound_challenge> inbound_;
	std::optional<accepted_request> accepted_;
};

} // namespace reconnect
} // namespace udp
} // namespace dixelu

#endif // SAF_LEP_RECONNECT_HANDSHAKE_H
