#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <iomanip>
#include <sstream>
#include <atomic>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>
#endif

#include "lep/low_entropy_protocol.h"

#include "udp_tunnel/tunnel.h"
#include "udp_tunnel/global_flags.h"

using namespace dixelu::udp;

void print_usage(const char* program_name)
{
	std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
	std::cout << "Options:" << std::endl;
	std::cout << "  -p, --port PORT               Local UDP port (default: 0 = auto)" << std::endl;
	std::cout << "  -c, --connect HOST:PORT       Connect to peer" << std::endl;
	std::cout << "  -v, --verbose                 Enable verbose logging" << std::endl;
	std::cout << "  -w, --watchscreen             Enable live stats watchscreen" << std::endl;
	std::cout << "      --ip IP                   VPN IP address (e.g. 10.0.0.1)" << std::endl;
	std::cout << "      --mask MASK               VPN Subnet mask (default: 255.255.255.0)" << std::endl;
	std::cout << "      --gw GATEWAY              VPN Gateway (optional)" << std::endl;
	std::cout << "  -k, --seed-key KEY            Encryption seed key (optional)" << std::endl;
	std::cout << "  -h, --help                    Show this help message" << std::endl;
	std::cout << "\nExamples:" << std::endl;

	std::cout << "  " << program_name <<
		" -p 5000 --ip 10.0.0.1               # Run as server/peer 1" << std::endl;
	std::cout << "  " << program_name <<
		" -c 127.0.0.1:5000 --ip 10.0.0.2     # Connect to peer 1" << std::endl;
	std::cout << "  " << program_name <<
		" -w -c 127.0.0.1:5000 --ip 10.0.0.2  # With live watchscreen" << std::endl;
}

// Format bytes to human readable
std::string format_bytes(uint64_t bytes)
{
	const char* units[] = {"B", "KB", "MB", "GB"};
	int unit_index = 0;
	double value = static_cast<double>(bytes);

	while (value >= 1024.0 && unit_index < 3)
	{
		value /= 1024.0;
		unit_index++;
	}

	std::ostringstream oss;
	oss << std::fixed << std::setprecision(1) << value << " " << units[unit_index];
	return oss.str();
}

// Format throughput
std::string format_throughput(uint64_t bytes_per_sec)
{
	return format_bytes(bytes_per_sec) + "/s";
}

// Get packet event type name
const char* event_type_name(packet_event_type type)
{
	switch (type)
	{
		case packet_event_type::received: return "RECV";
		case packet_event_type::sent: return "SENT";
		case packet_event_type::lost: return "LOST";
		case packet_event_type::retransmit_requested: return "RRQ ";
		case packet_event_type::retransmitted: return "RTXM";
		case packet_event_type::fragment_received: return "FRAG";
		case packet_event_type::reassembled: return "RASM";
		default: return "????";
	}
}

// Check if key was pressed (non-blocking)
bool key_pressed()
{
#ifdef _WIN32
	return _kbhit() != 0;
#else
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds);

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	return select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0;
#endif
}

// Clear screen
void clear_screen()
{
#ifdef _WIN32
	system("cls");
#else
	std::cout << "\033[2J\033[H";
#endif
}

// Watchscreen display function
void run_watchscreen(std::shared_ptr<p2p_tunnel> tunnel, std::atomic<bool>& running)
{
	uint64_t last_bytes_sent = 0;
	uint64_t last_bytes_received = 0;
	auto last_time = std::chrono::steady_clock::now();

	while (running)
	{
		auto now = std::chrono::steady_clock::now();
		auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time).count();

		if (elapsed_ms < 500) // Update every 500ms
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			if (key_pressed())
			{
				running = false;
				break;
			}
			continue;
		}

		auto& stats = tunnel->get_stats();

		// Calculate throughput
		uint64_t curr_sent = stats.bytes_sent.load();
		uint64_t curr_recv = stats.bytes_received.load();

		double elapsed_sec = elapsed_ms / 1000.0;
		uint64_t send_rate = static_cast<uint64_t>((curr_sent - last_bytes_sent) / elapsed_sec);
		uint64_t recv_rate = static_cast<uint64_t>((curr_recv - last_bytes_received) / elapsed_sec);

		last_bytes_sent = curr_sent;
		last_bytes_received = curr_recv;
		last_time = now;

		// Clear and redraw
		clear_screen();

		std::cout << "====== SAF-LEP VPN Watchscreen ======" << std::endl;
		std::cout << "Press any key to stop..." << std::endl;
		std::cout << std::endl;

		// Connection info
		auto peers = tunnel->get_connected_peers();
		std::cout << "[ Peers: " << peers.size() << " ]" << std::endl;
		for (const auto& peer : peers)
		{
			std::cout << "  - " << peer.address().to_string() << ":" << peer.port() << std::endl;
		}
		std::cout << std::endl;

		// Throughput
		std::cout << "[ Throughput ]" << std::endl;
		std::cout << "  TX: " << std::setw(12) << format_throughput(send_rate)
		          << "  (total: " << format_bytes(curr_sent) << ")" << std::endl;
		std::cout << "  RX: " << std::setw(12) << format_throughput(recv_rate)
		          << "  (total: " << format_bytes(curr_recv) << ")" << std::endl;
		std::cout << std::endl;

		// Stats summary
		std::cout << "[ Packets ]" << std::endl;
		std::cout << "  Sent: " << stats.packets_sent.load()
		          << "  |  Recv: " << stats.packets_received.load()
		          << "  |  Lost: " << stats.packets_lost.load()
		          << "  |  RRQ: " << stats.retransmit_requests.load() << std::endl;
		std::cout << std::endl;

		// Recent packet events
		std::cout << "[ Recent Packets ]" << std::endl;
		auto events = stats.get_events();
		if (events.empty())
		{
			std::cout << "  (no packets yet)" << std::endl;
		}
		else
		{
			for (const auto& evt : events)
			{
				auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - evt.timestamp).count();
				std::cout << "  [" << event_type_name(evt.type) << "] "
				          << "ID:" << std::setw(8) << evt.packet_id << "  "
				          << std::setw(6) << evt.bytes << "B  "
				          << std::setw(6) << age_ms << "ms ago  "
				          << evt.peer_info << std::endl;
			}
		}
		std::cout << std::endl;

		// Log lines
		auto logs = stats.get_logs();
		if (!logs.empty())
		{
			std::cout << "[ Logs ]" << std::endl;
			for (const auto& line : logs)
			{
				std::cout << "  " << line << std::endl;
			}
		}

		std::cout.flush();
	}
}

int main(int argc, char* argv[])
{
	uint16_t local_port = 0;
	std::string connect_to;
	std::string vpn_ip;
	std::string vpn_mask = "255.255.255.0";
	std::string vpn_gw;
	std::string seed_key;
	bool watchscreen_mode = false;

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
		else if (arg == "-v" || arg == "--verbose")
		{
			VERBOSE_MODE = true;
		}
		else if (arg == "-w" || arg == "--watchscreen")
		{
			watchscreen_mode = true;
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
		else if (arg == "-k" || arg == "--seed-key")
		{
			if (i + 1 < argc) seed_key = argv[++i];
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

		// Set encryption key if provided
		if (!seed_key.empty())
		{
			tunnel->set_encryption_key(seed_key);
			std::cout << "[Tunnel] Encryption enabled with seed key" << std::endl;
		}

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

		if (watchscreen_mode)
		{
			std::cout << "\n[System] VPN is running with watchscreen. Starting..." << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(500));

			std::atomic<bool> watchscreen_running{true};
			run_watchscreen(tunnel, watchscreen_running);
		}
		else
		{
			std::cout << "\n[System] VPN is running. Press Enter to stop..." << std::endl;
			std::cin.get();
		}

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
