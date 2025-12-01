#pragma once

#ifndef SAF_LEP_P2P_TUNNEL_H
#define SAF_LEP_P2P_TUNNEL_H

#include <boost/asio.hpp>

#include "../lep/low_entropy_protocol.h"

namespace dixelu
{
namespace udp
{

struct tunnel
{
	boost::asio::io_context io_context;
	boost::asio::ip::udp::socket socket;
	boost::asio::ip::udp::resolver resolver;
	boost::asio::ip::udp::endpoint endpoint;

	tunnel():
		socket(io_context), resolver(io_context)
	{}

	~tunnel() = default;

	tunnel(const tunnel&) = delete;
	tunnel& operator=(const tunnel&) = delete;

	auto resolve(std::string address, std::string port)
	{
		return resolver.resolve(address, port);
	}

	void set_endpoint(boost::asio::ip::udp::endpoint endpoint)
	{
		this->endpoint = endpoint;
	}

	size_t send_sync(const std::vector<uint8_t>& data)
	{
		return socket.send_to(boost::asio::buffer(data), endpoint);
	}

	void send_async(const std::vector<uint8_t>& data)
	{
		socket.async_send_to(
			boost::asio::buffer(data),
			endpoint,
			[](boost::system::error_code ec, std::size_t bytes_transferred) {});
	}

	// todo fill the rest
};

}

}

#endif //SAF_LEP_P2P_TUNNEL_H