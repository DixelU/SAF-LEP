#include "lep/low_entropy_protocol.h"
#include "udp_tunnel/tunnel.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <print>
#include <vector>
#include <sstream>

using namespace dixelu::udp;

void print_usage(const char* program_name)
{
	std::println("Usage: {} [OPTIONS]", program_name);
	std::println("Options:");
	std::println("  -p, --port PORT          Local UDP port (default: 0 = auto)");
	std::println("  -c, --connect HOST:PORT  Connect to peer");
	std::println("  -s, --server             Run as server (listen mode)");
	std::println("  -h, --help               Show this help message");
	std::println("\nExamples:");
	std::println("  {} -s -p 5000                    # Run as server on port 5000", program_name);
	std::println("  {} -c 192.168.1.100:5000        # Connect to peer", program_name);
	std::println("  {} -p 5001 -c 192.168.1.100:5000 # Run on port 5001 and connect", program_name);
}

void simulate_packet_injection(std::shared_ptr<vpn_interface> vpn, bool& running)
{
	// Simulate packets being injected from network interface
	int packet_counter = 0;
	while (running)
	{
		std::this_thread::sleep_for(std::chrono::seconds(5));
		
		// Create a simulated IP packet
		std::vector<uint8_t> packet = {
			0x45, 0x00, 0x00, 0x28,  // IP header
			0x00, 0x01, 0x00, 0x00,
			0x40, 0x06, 0x00, 0x00,
			0xc0, 0xa8, 0x01, 0x01,  // Source IP
			0xc0, 0xa8, 0x01, 0x02,  // Dest IP
			// Payload
			'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r',
			'o', 'm', ' ', 'p', 'a', 'c', 'k', 'e',
			't', ' ', '#', static_cast<uint8_t>('0' + (packet_counter % 10))
		};

		vpn->inject_packet(packet);
		std::println("[VPN] Injected packet #{} ({} bytes)", packet_counter++, packet.size());
	}
}

int main(int argc, char* argv[])
{
	uint16_t local_port = 0;
	std::string connect_to;
	bool server_mode = false;

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
			if (i + 1 < argc)
			{
				local_port = static_cast<uint16_t>(std::stoi(argv[++i]));
			}
			else
			{
				std::println(stderr, "Error: -p requires a port number");
				return 1;
			}
		}
		else if (arg == "-c" || arg == "--connect")
		{
			if (i + 1 < argc)
			{
				connect_to = argv[++i];
			}
			else
			{
				std::println(stderr, "Error: -c requires HOST:PORT");
				return 1;
			}
		}
		else if (arg == "-s" || arg == "--server")
		{
			server_mode = true;
		}
		else
		{
			std::println(stderr, "Unknown option: {}", arg);
			print_usage(argv[0]);
			return 1;
		}
	}

	try
	{
		// Create P2P tunnel
		auto tunnel = std::make_shared<p2p_tunnel>(local_port);
		
		// Create VPN interface
		auto vpn = std::make_shared<vpn_interface>(tunnel);

		// Set up packet output callback (simulated network interface output)
		vpn->set_packet_output_callback([](const std::vector<uint8_t>& packet) {
			std::println("[VPN] Received packet from tunnel ({} bytes)", packet.size());
			// In a real implementation, this would write to TUN/TAP interface
		});

		// Set up tunnel callbacks
		tunnel->set_connection_callback([](const boost::asio::ip::udp::endpoint& peer) {
			std::println("[Tunnel] Connected to peer: {}:{}", peer.address().to_string(), peer.port());
		});

		tunnel->set_packet_received_callback([](const std::vector<uint8_t>& data, const boost::asio::ip::udp::endpoint& from) {
			std::println("[Tunnel] Received {} bytes from {}:{}", 
				data.size(), from.address().to_string(), from.port());
		});

		// Start tunnel
		tunnel->start();
		tunnel->run_in_thread();

		// Start VPN interface
		vpn->start();

		// Get local endpoint
		auto local_ep = tunnel->get_local_endpoint();
		std::println("[Tunnel] Listening on {}:{}", local_ep.address().to_string(), local_ep.port());

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
				std::println(stderr, "Error: Invalid format for -c. Use HOST:PORT");
				return 1;
			}

			std::println("[Tunnel] Connecting to {}:{}...", host, port);
			tunnel->connect_to_peer(host, port);
			
			// Wait a bit for connection
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		}

		// Start packet injection simulation
		bool running = true;
		std::thread injection_thread;
		
		if (server_mode || !connect_to.empty())
		{
			injection_thread = std::thread([&vpn, &running]() {
				simulate_packet_injection(vpn, running);
			});
		}

		std::println("\n[System] P2P VPN tunnel is running. Press Enter to stop...");
		std::cin.get();

		// Stop everything
		running = false;
		if (injection_thread.joinable())
		{
			injection_thread.join();
		}

		vpn->stop();
		tunnel->stop();

		std::println("[System] Shutting down...");
	}
	catch (const std::exception& e)
	{
		std::println(stderr, "Error: {}", e.what());
		return 1;
	}

	return 0;
}
