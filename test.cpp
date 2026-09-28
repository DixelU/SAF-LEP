#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <iomanip>
#include <sstream>
#include <atomic>
#include <charconv>
#include <cstdlib>
#include <optional>
#include <random>
#include <string_view>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
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

#ifndef _WIN32
bool is_valid_tun_name(const std::string& name)
{
	if (name.empty() || name.size() > 15)
		return false;

	for (const unsigned char c : name)
	{
		const bool alpha_numeric = (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
		if (!alpha_numeric && c != '_' && c != '-' && c != '.')
			return false;
	}
	return true;
}
#endif

// Accepts a full decimal string in 0-65535; anything else is rejected rather
// than truncated or thrown out of std::stoi.
std::optional<uint16_t> parse_port(std::string_view text)
{
	unsigned int value = 0;
	const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
	if (ec != std::errc{} || end != text.data() + text.size() || text.empty() || value > 65535)
		return std::nullopt;
	return static_cast<uint16_t>(value);
}

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
	std::cout << "      --lepv1                   Enable experimental LEP::v1 encoder" << std::endl;
	std::cout << "      --raw                     Minimal framing (4-byte packet index; requires -k)" << std::endl;
	std::cout << "      --ip IP                   VPN IP address (legacy manual mode)" << std::endl;
	std::cout << "      --mask MASK               VPN Subnet mask (default: 255.255.255.0)" << std::endl;
	std::cout << "      --gw GATEWAY              VPN Gateway (legacy manual mode)" << std::endl;
	std::cout << "      --forwarding MODE         hub (compatible default) or route (per-peer IP routing)" << std::endl;
#ifdef _WIN32
	std::cout << "      --tap-guid GUID           Use a specific TAP-Windows adapter (default: first TAP)" << std::endl;
#else
	std::cout << "      --tun-name NAME           Use a specific TUN device (default: tun0)" << std::endl;
#endif
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

// When true, clear via ANSI escapes instead of spawning a process. Set in main()
// once the Windows VT terminal is enabled. The old system("cls") spawned cmd.exe
// twice a second — tens of thousands of processes over a multi-hour session.
static bool g_use_ansi_clear = false;

// Clear screen
void clear_screen()
{
	if (g_use_ansi_clear)
	{
		std::cout << "\033[2J\033[H";
		return;
	}
#ifdef _WIN32
	system("cls");
#else
	std::cout << "\033[2J\033[H";
#endif
}

// Watchscreen display function
void run_watchscreen(std::shared_ptr<tunnel_interface> tunnel, std::atomic<bool>& running)
{
	uint64_t last_bytes_sent = 0;
	uint64_t last_bytes_received = 0;
	uint64_t last_tap_in = 0;
	uint64_t last_tap_out = 0;
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
		uint64_t curr_tap_in = stats.tap_bytes_in.load();
		uint64_t curr_tap_out = stats.tap_bytes_out.load();

		double elapsed_sec = elapsed_ms / 1000.0;
		uint64_t send_rate = static_cast<uint64_t>((curr_sent - last_bytes_sent) / elapsed_sec);
		uint64_t recv_rate = static_cast<uint64_t>((curr_recv - last_bytes_received) / elapsed_sec);
		uint64_t tap_in_rate = static_cast<uint64_t>((curr_tap_in - last_tap_in) / elapsed_sec);
		uint64_t tap_out_rate = static_cast<uint64_t>((curr_tap_out - last_tap_out) / elapsed_sec);

		last_bytes_sent = curr_sent;
		last_bytes_received = curr_recv;
		last_tap_in = curr_tap_in;
		last_tap_out = curr_tap_out;
		last_time = now;

		// Clear and redraw
		clear_screen();

		std::cout << "====== SAF-LEP VPN Watchscreen ======" << std::endl;
		std::cout << "Press any key to stop..." << std::endl;
		std::cout << std::endl;

		// Connection info
		auto peers = tunnel->get_connected_peers();
		std::cout << "[ Peers: " << peers.size() << " connected / " << tunnel->get_peer_count() << " total ]" << std::endl;
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

		// Adapter-boundary throughput. If these dwarf the socket TX/RX above, the
		// flood is looping at the TAP/TUN and never reaching the UDP socket — which
		// is exactly the "8 MB/s on the NIC, ~nothing on the app meter" signature.
		std::cout << "[ TAP/TUN boundary ]" << std::endl;
		std::cout << "  In : " << std::setw(12) << format_throughput(tap_in_rate)
		          << "  (total: " << format_bytes(curr_tap_in) << ")" << std::endl;
		std::cout << "  Out: " << std::setw(12) << format_throughput(tap_out_rate)
		          << "  (total: " << format_bytes(curr_tap_out) << ")" << std::endl;
		std::cout << "  Broadcast drops (no peer): " << stats.broadcast_drops.load() << std::endl;
		std::cout << "  Route drops / conflicts: " << stats.route_drops.load()
		          << " / " << stats.route_conflicts.load() << std::endl;
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
#ifdef _WIN32
	{
		HANDLE h_out = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD console_mode = 0;
		if (h_out != INVALID_HANDLE_VALUE && GetConsoleMode(h_out, &console_mode))
			g_use_ansi_clear = SetConsoleMode(h_out, console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
	}
#else
	g_use_ansi_clear = true;
#endif

	uint16_t local_port = 0;
	std::string connect_to;
	std::string vpn_ip;
	std::string vpn_mask = "255.255.255.0";
	std::string vpn_gw;
	std::string seed_key;
	std::string tun_name;
	std::string tap_guid;
	bool watchscreen_mode = false;
	bool server_mode = false;
	encode_scheme encoder = encode_scheme::lep_v0;
	forwarding_mode forwarding = forwarding_mode::hub;

	// Every value-taking option fails the same way when its value is missing,
	// instead of silently keeping the default.
	auto next_value = [argc, argv](int& i, const std::string& option, const char* what) -> const char* {
		if (i + 1 < argc)
			return argv[++i];
		std::cerr << "Error: " << option << " requires " << what << std::endl;
		return nullptr;
	};

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
			const char* value = next_value(i, arg, "a port number");
			if (!value) return 1;
			const auto port = parse_port(value);
			if (!port)
			{
				std::cerr << "Error: " << arg << " must be a port number (0-65535)" << std::endl;
				return 1;
			}
			local_port = *port;
		}
		else if (arg == "-c" || arg == "--connect")
		{
			const char* value = next_value(i, arg, "HOST:PORT");
			if (!value) return 1;
			connect_to = value;
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
			const char* value = next_value(i, arg, "an IPv4 address");
			if (!value) return 1;
			vpn_ip = value;
		}
		else if (arg == "--mask")
		{
			const char* value = next_value(i, arg, "a subnet mask");
			if (!value) return 1;
			vpn_mask = value;
		}
		else if (arg == "--gw")
		{
			const char* value = next_value(i, arg, "a gateway address");
			if (!value) return 1;
			vpn_gw = value;
		}
		else if (arg == "--forwarding")
		{
			const char* value = next_value(i, arg, "hub or route");
			if (!value) return 1;
			const std::string mode_name = value;
			if (mode_name == "hub")
				forwarding = forwarding_mode::hub;
			else if (mode_name == "route")
				forwarding = forwarding_mode::route;
			else
			{
				std::cerr << "Error: --forwarding must be hub or route" << std::endl;
				return 1;
			}
		}
		else if (arg == "--tun-name")
		{
			const char* value = next_value(i, arg, "a device name");
			if (!value) return 1;
			tun_name = value;
		}
		else if (arg == "--tap-guid")
		{
			const char* value = next_value(i, arg, "an adapter GUID");
			if (!value) return 1;
			tap_guid = value;
		}
		else if (arg == "-k" || arg == "--seed-key")
		{
			const char* value = next_value(i, arg, "a key");
			if (!value) return 1;
			seed_key = value;
		}
		else if (arg == "--lepv1")
		{
			encoder = encode_scheme::lep_v1;
		}
		else if (arg == "--raw")
		{
			encoder = encode_scheme::raw;
		}
		else
		{
			std::cerr << "[Warning] Ignoring unknown option: " << arg << std::endl;
		}
	}

#ifdef _WIN32
	if (!tun_name.empty())
	{
		std::cerr << "Error: --tun-name is only available on Linux" << std::endl;
		return 1;
	}
#else
	if (!tap_guid.empty())
	{
		std::cerr << "Error: --tap-guid is only available on Windows" << std::endl;
		return 1;
	}
	if (tun_name.empty())
		tun_name = "tun0";
	if (!is_valid_tun_name(tun_name))
	{
		std::cerr << "Error: --tun-name must contain 1-15 letters, digits, '.', '_' or '-'"
		          << std::endl;
		return 1;
	}
#endif

	// ---------------------------------------------------------------
	// Determine run mode
	// ---------------------------------------------------------------
	run_mode mode;
	setup_state auto_state;
	std::string adapter_identifier;

#ifdef _WIN32
	adapter_identifier = tap_guid;
#else
	adapter_identifier = tun_name;
	auto_state.tun_interface = tun_name;
#endif

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
		std::random_device generator;
		const auto host_octet = routing::random_client_host_octet(generator);
		vpn_ip = "10.0.0." + std::to_string(host_octet);
		vpn_mask = "255.255.255.0";
		vpn_gw = "10.0.0.1";
		std::cout << "[AutoSetup] Selected client VPN address: " << vpn_ip << std::endl;
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

	// Raw framing exposes the packet payload directly, so fail closed rather
	// than accidentally starting an unencrypted tunnel.
	if (encoder == encode_scheme::raw && seed_key.empty())
	{
		std::cerr << "Error: Raw packet encoding requires an encryption seed key (-k)." << std::endl;
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
	std::string server_host;
	uint16_t server_port = 0;
	if (!connect_to.empty())
	{
		const size_t colon_pos = connect_to.find(':');
		std::optional<uint16_t> port;
		if (colon_pos != std::string::npos && colon_pos > 0)
			port = parse_port(std::string_view(connect_to).substr(colon_pos + 1));

		if (!port || *port == 0)
		{
			std::cerr << "Error: Invalid format for -c. Use HOST:PORT (port 1-65535)" << std::endl;
			return 1;
		}
		server_host = connect_to.substr(0, colon_pos);
		server_port = *port;
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

	auto teardown_auto_setup = [&mode, &auto_state]() {
		if (mode == run_mode::server)
			server_teardown(auto_state);
		else if (mode == run_mode::client)
			client_teardown(auto_state);
	};

	try
	{
		// Create P2P tunnel
		auto tunnel = std::make_shared<p2p_tunnel>(local_port, encoder);

		// Set encryption key if provided
		if (!seed_key.empty())
		{
			tunnel->set_encryption_key(seed_key);
			std::cout << "[Tunnel] Encryption enabled with seed key" << std::endl;
		}

		// Create VPN interface. Only the listening side learns which peer owns
		// each VPN address; a connecting client has a single upstream peer.
		const bool learn_peer_routes = server_mode || connect_to.empty();
		auto vpn = std::make_shared<vpn_interface>(
			tunnel, adapter_identifier, forwarding, learn_peer_routes);

		// Set up tunnel callbacks
		tunnel->set_connection_callback([](const boost::asio::ip::udp::endpoint& peer) {
			std::cout << "[Tunnel] Connected to peer: " << peer.address().to_string() << ":" << peer.port() << std::endl;
		});

		// Configure the VPN interface before starting the transport. On Windows
		// this also removes full-tunnel routes left on the selected TAP by an
		// interrupted run, so the legacy-mode peer lookup is not trapped in them.
		std::cout << "[VPN] Starting VPN interface on " << vpn_ip
		          << " with " << (forwarding == forwarding_mode::route ? "routed" : "hub")
		          << " forwarding";
#ifdef _WIN32
		if (!tap_guid.empty())
			std::cout << " using TAP " << tap_guid;
#else
		std::cout << " using TUN " << tun_name;
#endif
		std::cout << "..." << std::endl;
		if (!vpn->start(vpn_ip, vpn_mask, vpn_gw))
		{
			std::cerr << "Failed to start VPN interface. Make sure you have "
			          << "Administrator privileges (Windows) or root (Linux)." << std::endl;
			// Teardown auto-setup before exiting
			teardown_auto_setup();
			return 1;
		}

		// Start tunnel
		tunnel->start();
		tunnel->run_in_thread();

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
					server_port
				);
				tunnel->connect_to_peer(server_ep);
			}
			else
			{
				// Legacy mode: use async DNS resolution
				tunnel->connect_to_peer(server_host, std::to_string(server_port));
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
			std::cout << "[System] Periodic stats every 5s (redirect stdout to a file for a long run)." << std::endl;

			auto start_time = std::chrono::steady_clock::now();
			auto last_stat = start_time;
			uint64_t l_tx = 0, l_rx = 0, l_ti = 0, l_to = 0;
			while (!shutdown_requested)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(200));

				auto now = std::chrono::steady_clock::now();
				auto since_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stat).count();
				if (since_ms < 5000)
					continue;

				auto& s = tunnel->get_stats();
				uint64_t tx = s.bytes_sent.load();
				uint64_t rx = s.bytes_received.load();
				uint64_t ti = s.tap_bytes_in.load();
				uint64_t to = s.tap_bytes_out.load();
				double dt = since_ms / 1000.0;
				auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

				// A large tap_in with a tiny sock_tx (and climbing drops) localizes the
				// flood to the adapter loop; if sock_tx tracks the NIC, it's the socket.
				std::cout << "[Stats +" << uptime << "s] "
				          << "sock_tx=" << format_throughput(static_cast<uint64_t>((tx - l_tx) / dt))
				          << " sock_rx=" << format_throughput(static_cast<uint64_t>((rx - l_rx) / dt))
				          << " | tap_in=" << format_throughput(static_cast<uint64_t>((ti - l_ti) / dt))
				          << " tap_out=" << format_throughput(static_cast<uint64_t>((to - l_to) / dt))
				          << " | drops=" << s.broadcast_drops.load()
				          << "/" << s.route_drops.load()
				          << " conflicts=" << s.route_conflicts.load()
				          << " peers=" << tunnel->get_connected_peers().size()
				          << "/" << tunnel->get_peer_count()
				          << std::endl;

				l_tx = tx; l_rx = rx; l_ti = ti; l_to = to;
				last_stat = now;
			}
		}

		// -----------------------------------------------------------
		// Cleanup
		// -----------------------------------------------------------
		std::cout << "\n[System] Shutting down..." << std::endl;

		vpn->stop();
		tunnel->stop();

		teardown_auto_setup();
	}
	catch (const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;

		// Best-effort teardown on exception
		teardown_auto_setup();

		return 1;
	}

	return 0;
}
