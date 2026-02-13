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
#include "udp_tunnel/auto_setup.h"

using namespace dixelu::udp;
using namespace dixelu::udp::autosetup;

void print_usage(const char* program_name)
{
	std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;

	std::cout << "\nQuick start (auto-setup):" << std::endl;
	std::cout << "  " << program_name << " -s -p PORT -k KEY          # Server (Linux)" << std::endl;
	std::cout << "  " << program_name << " -c HOST:PORT -k KEY        # Client" << std::endl;

	std::cout << "\nManual mode (legacy):" << std::endl;
	std::cout << "  " << program_name << " --ip IP -p PORT            # Manual IP config" << std::endl;
	std::cout << "  " << program_name << " -c HOST:PORT --ip IP --gw GW  # Manual client" << std::endl;

	std::cout << "\nOptions:" << std::endl;
	std::cout << "  -s, --server                  Server mode (auto-setup NAT, Linux only)" << std::endl;
	std::cout << "  -c, --connect HOST:PORT       Client mode / connect to peer" << std::endl;
	std::cout << "  -p, --port PORT               Local UDP port (required for server)" << std::endl;
	std::cout << "  -k, --seed-key KEY            Encryption seed key (recommended)" << std::endl;
	std::cout << "  -v, --verbose                 Enable verbose logging" << std::endl;
	std::cout << "  -w, --watchscreen             Enable live stats watchscreen" << std::endl;
	std::cout << "      --ip IP                   VPN IP address (legacy manual mode)" << std::endl;
	std::cout << "      --mask MASK               VPN Subnet mask (default: 255.255.255.0)" << std::endl;
	std::cout << "      --gw GATEWAY              VPN Gateway (legacy manual mode)" << std::endl;
	std::cout << "  -h, --help                    Show this help message" << std::endl;
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
				          << "ID:" << std::setw(15) << evt.packet_id << "  "
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
		else if (arg == "-s" || arg == "--server")
		{
			server_mode = true;
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

	// ---------------------------------------------------------------
	// Determine run mode
	// ---------------------------------------------------------------
	run_mode mode;
	setup_state auto_state;

	if (!vpn_ip.empty())
	{
		// Legacy mode: --ip was explicitly provided, behave exactly as before
		mode = run_mode::legacy;
	}
	else if (server_mode)
	{
		mode = run_mode::server;
		vpn_ip = "10.0.0.1";
		vpn_mask = "255.255.255.0";
		// Gateway stays empty for server
	}
	else if (!connect_to.empty())
	{
		mode = run_mode::client;
		vpn_ip = "10.0.0.2";
		vpn_mask = "255.255.255.0";
		vpn_gw = "10.0.0.1";
	}
	else
	{
		std::cerr << "Error: Must specify -s (server), -c HOST:PORT (client), "
		          << "or --ip (legacy manual mode)" << std::endl;
		print_usage(argv[0]);
		return 1;
	}

	// Validate server mode requirements
	if (mode == run_mode::server && local_port == 0)
	{
		std::cerr << "Error: Server mode requires an explicit port (-p PORT)" << std::endl;
		return 1;
	}

	// Warn if no encryption key
	if (seed_key.empty())
	{
		std::cerr << "[Warning] No encryption seed key (-k) provided. "
		          << "Traffic will NOT be encrypted." << std::endl;
	}

	// ---------------------------------------------------------------
	// Parse host:port from -c argument (needed early for DNS resolution)
	// ---------------------------------------------------------------
	std::string server_host, server_port;
	if (!connect_to.empty())
	{
		size_t colon_pos = connect_to.find(':');
		if (colon_pos != std::string::npos)
		{
			server_host = connect_to.substr(0, colon_pos);
			server_port = connect_to.substr(colon_pos + 1);
		}
		else
		{
			std::cerr << "Error: Invalid format for -c. Use HOST:PORT" << std::endl;
			return 1;
		}
	}

	// ---------------------------------------------------------------
	// Client auto-mode: resolve DNS BEFORE any VPN setup
	// ---------------------------------------------------------------
	if (mode == run_mode::client)
	{
		std::cout << "[AutoSetup] Resolving server: " << server_host << "..." << std::endl;
		auto_state.server_public_ip = resolve_hostname_sync(server_host);
		if (auto_state.server_public_ip.empty())
		{
			std::cerr << "Error: Could not resolve server hostname: " << server_host << std::endl;
			return 1;
		}
		std::cout << "[AutoSetup] Resolved server: " << server_host
		          << " -> " << auto_state.server_public_ip << std::endl;
	}

	// ---------------------------------------------------------------
	// Auto-setup: configure system networking BEFORE starting VPN
	// ---------------------------------------------------------------
	if (mode == run_mode::server)
	{
		if (!server_setup(auto_state))
		{
			std::cerr << "Error: Server auto-setup failed" << std::endl;
			return 1;
		}
	}
	else if (mode == run_mode::client)
	{
		if (!client_setup(auto_state))
		{
			std::cerr << "Error: Client auto-setup failed" << std::endl;
			return 1;
		}
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
			std::cerr << "Failed to start VPN interface. Make sure you have "
			          << "Administrator privileges (Windows) or root (Linux)." << std::endl;
			// Teardown auto-setup before exiting
			if (mode == run_mode::server) server_teardown(auto_state);
			else if (mode == run_mode::client) client_teardown(auto_state);
			return 1;
		}

		// Get local endpoint
		auto local_ep = tunnel->get_local_endpoint();
		std::cout << "[Tunnel] Listening on " << local_ep.address().to_string()
		          << ":" << local_ep.port() << std::endl;

		// Connect to peer if specified
		if (!connect_to.empty())
		{
			std::cout << "[Tunnel] Connecting to " << server_host << ":" << server_port << "..." << std::endl;

			if (mode == run_mode::client)
			{
				// Use pre-resolved IP directly (skip async DNS)
				boost::asio::ip::udp::endpoint server_ep(
					boost::asio::ip::make_address_v4(auto_state.server_public_ip),
					static_cast<unsigned short>(std::stoi(server_port))
				);
				tunnel->connect_to_peer(server_ep);
			}
			else
			{
				// Legacy mode: use async DNS resolution
				tunnel->connect_to_peer(server_host, server_port);
			}
		}

		// -----------------------------------------------------------
		// Install signal handlers and wait for shutdown
		// -----------------------------------------------------------
		std::atomic<bool> shutdown_requested{false};

		if (watchscreen_mode)
		{
			std::atomic<bool> watchscreen_running{true};
			install_signal_handlers([&shutdown_requested, &watchscreen_running]() {
				shutdown_requested = true;
				watchscreen_running = false;
			});

			std::cout << "\n[System] VPN is running with watchscreen. Starting..." << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			run_watchscreen(tunnel, watchscreen_running);
		}
		else
		{
			install_signal_handlers([&shutdown_requested]() {
				shutdown_requested = true;
			});

			std::cout << "\n[System] VPN is running. Press Ctrl+C to stop..." << std::endl;
			while (!shutdown_requested)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
			}
		}

		// -----------------------------------------------------------
		// Cleanup
		// -----------------------------------------------------------
		std::cout << "\n[System] Shutting down..." << std::endl;

		vpn->stop();
		tunnel->stop();

		if (mode == run_mode::server)
			server_teardown(auto_state);
		else if (mode == run_mode::client)
			client_teardown(auto_state);
	}
	catch (const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;

		// Best-effort teardown on exception
		if (mode == run_mode::server)
			server_teardown(auto_state);
		else if (mode == run_mode::client)
			client_teardown(auto_state);

		return 1;
	}

	return 0;
}
