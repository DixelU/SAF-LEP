#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace dixelu::udp::routing
{

struct ip_packet_info
{
	uint8_t version = 0;
	uint8_t address_size = 0;
	std::array<uint8_t, 16> source{};
	std::array<uint8_t, 16> destination{};
};

inline std::string address_key(uint8_t version, const uint8_t* bytes, size_t size)
{
	std::string key;
	key.reserve(size + 1);
	key.push_back(static_cast<char>(version));
	key.append(reinterpret_cast<const char*>(bytes), size);
	return key;
}

inline std::string source_key(const ip_packet_info& packet)
{
	return address_key(packet.version, packet.source.data(), packet.address_size);
}

inline std::string destination_key(const ip_packet_info& packet)
{
	return address_key(packet.version, packet.destination.data(), packet.address_size);
}

inline std::optional<ip_packet_info> inspect_ip_packet(std::span<const uint8_t> data)
{
	if (data.empty())
		return std::nullopt;

	ip_packet_info result;
	result.version = data[0] >> 4;
	if (result.version == 4)
	{
		if (data.size() < 20)
			return std::nullopt;

		const size_t header_size = static_cast<size_t>(data[0] & 0x0F) * 4;
		const size_t total_size = (static_cast<size_t>(data[2]) << 8) | data[3];
		if (header_size < 20 || header_size > data.size() || total_size < header_size || total_size > data.size())
			return std::nullopt;

		result.address_size = 4;
		for (size_t i = 0; i < 4; ++i)
		{
			result.source[i] = data[12 + i];
			result.destination[i] = data[16 + i];
		}
		return result;
	}

	if (result.version == 6)
	{
		if (data.size() < 40)
			return std::nullopt;

		const size_t payload_size = (static_cast<size_t>(data[4]) << 8) | data[5];
		if (40 + payload_size > data.size())
			return std::nullopt;

		result.address_size = 16;
		for (size_t i = 0; i < 16; ++i)
		{
			result.source[i] = data[8 + i];
			result.destination[i] = data[24 + i];
		}
		return result;
	}

	return std::nullopt;
}

inline bool has_usable_source(const ip_packet_info& packet)
{
	if (packet.version == 4)
	{
		const bool unspecified = packet.source[0] == 0 && packet.source[1] == 0 &&
			packet.source[2] == 0 && packet.source[3] == 0;
		const bool multicast = packet.source[0] >= 224 && packet.source[0] <= 239;
		const bool limited_broadcast = packet.source[0] == 255 && packet.source[1] == 255 &&
			packet.source[2] == 255 && packet.source[3] == 255;
		return !unspecified && !multicast && !limited_broadcast;
	}

	if (packet.version == 6)
	{
		bool unspecified = true;
		for (size_t i = 0; i < packet.address_size; ++i)
			unspecified = unspecified && packet.source[i] == 0;
		return !unspecified && packet.source[0] != 0xFF;
	}

	return false;
}

inline bool has_group_destination(const ip_packet_info& packet)
{
	if (packet.version == 4)
	{
		const bool multicast = packet.destination[0] >= 224 && packet.destination[0] <= 239;
		const bool limited_broadcast = packet.destination[0] == 255 && packet.destination[1] == 255 &&
			packet.destination[2] == 255 && packet.destination[3] == 255;
		return multicast || limited_broadcast;
	}
	return packet.version == 6 && packet.destination[0] == 0xFF;
}

inline std::optional<std::array<uint8_t, 4>> parse_ipv4(std::string_view text)
{
	std::array<uint8_t, 4> result{};
	size_t begin = 0;
	for (size_t octet = 0; octet < result.size(); ++octet)
	{
		const size_t end = text.find('.', begin);
		if ((end == std::string_view::npos) != (octet == result.size() - 1))
			return std::nullopt;
		const size_t length = (end == std::string_view::npos ? text.size() : end) - begin;
		if (length == 0 || length > 3)
			return std::nullopt;

		unsigned value = 0;
		for (size_t i = begin; i < begin + length; ++i)
		{
			if (text[i] < '0' || text[i] > '9')
				return std::nullopt;
			value = value * 10 + static_cast<unsigned>(text[i] - '0');
		}
		if (value > 255)
			return std::nullopt;
		result[octet] = static_cast<uint8_t>(value);
		begin = end == std::string_view::npos ? text.size() : end + 1;
	}
	return result;
}

inline std::optional<std::string> subnet_broadcast_key(std::string_view address, std::string_view mask)
{
	const auto parsed_address = parse_ipv4(address);
	const auto parsed_mask = parse_ipv4(mask);
	if (!parsed_address || !parsed_mask)
		return std::nullopt;

	std::array<uint8_t, 4> broadcast{};
	for (size_t i = 0; i < broadcast.size(); ++i)
		broadcast[i] = static_cast<uint8_t>((*parsed_address)[i] | static_cast<uint8_t>(~(*parsed_mask)[i]));
	return address_key(4, broadcast.data(), broadcast.size());
}

template <class UniformRandomBitGenerator>
uint8_t random_client_host_octet(UniformRandomBitGenerator& generator)
{
	std::uniform_int_distribution<unsigned> distribution(2, 254);
	return static_cast<uint8_t>(distribution(generator));
}

enum class learn_result
{
	learned,
	unchanged,
	address_conflict,
	peer_conflict,
};

class route_bindings
{
public:
	learn_result learn(const std::string& address, const std::string& peer)
	{
		if (address.empty())
			return learn_result::peer_conflict;

		const auto address_it = address_to_peer_.find(address);
		if (address_it != address_to_peer_.end())
			return address_it->second == peer ? learn_result::unchanged : learn_result::address_conflict;

		const auto family = static_cast<uint8_t>(address.front());
		const auto peer_it = peer_to_addresses_.find(peer);
		if (peer_it != peer_to_addresses_.end())
		{
			const auto family_it = peer_it->second.find(family);
			if (family_it != peer_it->second.end())
				return family_it->second == address ? learn_result::unchanged : learn_result::peer_conflict;
		}

		address_to_peer_[address] = peer;
		peer_to_addresses_[peer][family] = address;
		return learn_result::learned;
	}

	std::optional<std::string> peer_for(const std::string& address) const
	{
		const auto it = address_to_peer_.find(address);
		if (it == address_to_peer_.end())
			return std::nullopt;
		return it->second;
	}

	void erase_peer(const std::string& peer)
	{
		const auto peer_it = peer_to_addresses_.find(peer);
		if (peer_it == peer_to_addresses_.end())
			return;
		for (const auto& [_, address] : peer_it->second)
			address_to_peer_.erase(address);
		peer_to_addresses_.erase(peer_it);
	}

private:
	std::unordered_map<std::string, std::string> address_to_peer_;
	std::unordered_map<std::string, std::unordered_map<uint8_t, std::string>> peer_to_addresses_;
};

} // namespace dixelu::udp::routing
