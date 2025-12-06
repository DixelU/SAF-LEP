#include "lep/low_entropy_protocol.h"
#include "udp_tunnel/tunnel.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>

using namespace dixelu::udp;

void print_usage(const char* program_name)
{
	std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
	std::cout << "Options:" << std::endl;
	std::cout << "  -p, --port PORT          Local UDP port (default: 0 = auto)" << std::endl;
	std::cout << "  -c, --connect HOST:PORT  Connect to peer" << std::endl;
	std::cout << "  --ip IP                  VPN IP address (e.g. 10.0.0.1)" << std::endl;
	std::cout << "  --mask MASK              VPN Subnet mask (default: 255.255.255.0)" << std::endl;
	std::cout << "  --gw GATEWAY             VPN Gateway (optional)" << std::endl;
	std::cout << "  -h, --help               Show this help message" << std::endl;
	std::cout << "\nExamples:" << std::endl;
	std::cout << "  " << program_name << " -p 5000 --ip 10.0.0.1                    # Run as server/peer 1" << std::endl;
	std::cout << "  " << program_name << " -c 127.0.0.1:5000 --ip 10.0.0.2          # Connect to peer 1" << std::endl;
}

int main(int argc, char* argv[])
{
	uint16_t local_port = 0;
	std::string connect_to;
	std::string vpn_ip;
	std::string vpn_mask = "255.255.255.0";
	std::string vpn_gw;

	// Parse command line arguments
	for (int i = 1; i < argc; ++i)
	{
		std::string arg = argv[i];
		if (arg == "-h" || arg == "--help")
		{
			print_usage(argv[0]);
			return 0;
		}
		else if (arg == "-p" || arg == "--port")
		{
			if (i + 1 < argc) local_port = static_cast<uint16_t>(std::stoi(argv[++i]));
		}
		else if (arg == "-c" || arg == "--connect")
		{
			if (i + 1 < argc) connect_to = argv[++i];
		}
		else if (arg == "--ip")
		{
			if (i + 1 < argc) vpn_ip = argv[++i];
		}
		else if (arg == "--mask")
		{
			if (i + 1 < argc) vpn_mask = argv[++i];
		}
		else if (arg == "--gw")
		{
			if (i + 1 < argc) vpn_gw = argv[++i];
		}
	}

	if (vpn_ip.empty())
	{
		std::cerr << "Error: --ip is required" << std::endl;
		print_usage(argv[0]);
		return 1;
	}

	try
	{
		// Create P2P tunnel
		auto tunnel = std::make_shared<p2p_tunnel>(local_port);
		
		// Create VPN interface
		auto vpn = std::make_shared<vpn_interface>(tunnel);

		// Set up tunnel callbacks
		tunnel->set_connection_callback([](const boost::asio::ip::udp::endpoint& peer) {
			std::cout << "[Tunnel] Connected to peer: " << peer.address().to_string() << ":" << peer.port() << std::endl;
		});

		// Start tunnel
		tunnel->start();
		tunnel->run_in_thread();

		// Start VPN interface
		std::cout << "[VPN] Starting VPN interface on " << vpn_ip << "..." << std::endl;
		if (!vpn->start(vpn_ip, vpn_mask, vpn_gw))
		{
			std::cerr << "Failed to start VPN interface. Make sure you have Administrator privileges (Windows) or root (Linux)." << std::endl;
			return 1;
		}

		// Get local endpoint
		auto local_ep = tunnel->get_local_endpoint();
		std::cout << "[Tunnel] Listening on " << local_ep.address().to_string() << ":" << local_ep.port() << std::endl;

		// Connect to peer if specified
		if (!connect_to.empty())
		{
			std::string host, port;
			size_t colon_pos = connect_to.find(':');
			if (colon_pos != std::string::npos)
			{
				host = connect_to.substr(0, colon_pos);
				port = connect_to.substr(colon_pos + 1);
			}
			else
			{
				std::cerr << "Error: Invalid format for -c. Use HOST:PORT" << std::endl;
				return 1;
			}

			std::cout << "[Tunnel] Connecting to " << host << ":" << port << "..." << std::endl;
			tunnel->connect_to_peer(host, port);
		}

		std::cout << "\n[System] VPN is running. Press Enter to stop..." << std::endl;
		std::cin.get();

		// Stop everything
		vpn->stop();
		tunnel->stop();

		std::cout << "[System] Shutting down..." << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
