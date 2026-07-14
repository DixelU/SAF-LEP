#include "auto_setup.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <csignal>
#include <cstdlib>
#endif

#include <iostream>
#include <cstring>
#include <cstdio>

#include <boost/asio.hpp>

namespace dixelu {
namespace udp {
namespace autosetup {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

std::function<void()> g_shutdown_callback;
std::atomic<bool> g_shutdown_called{false};

#ifndef _WIN32
// Read a single line from a popen() command. Returns empty on failure.
std::string popen_read_line(const char* cmd)
{
	FILE* fp = popen(cmd, "r");
	if (!fp) return "";

	char buf[512];
	std::string result;
	if (fgets(buf, sizeof(buf), fp))
	{
		result = buf;
		// Trim trailing newline
		while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
			result.pop_back();
	}
	pclose(fp);
	return result;
}

// Extract a token that follows a keyword in a string.
// e.g. extract_after("default via 1.2.3.4 dev eth0", "via ") returns "1.2.3.4"
std::string extract_after(const std::string& line, const std::string& keyword)
{
	auto pos = line.find(keyword);
	if (pos == std::string::npos) return "";
	auto start = pos + keyword.size();
	auto end = line.find(' ', start);
	if (end == std::string::npos) end = line.size();
	return line.substr(start, end - start);
}
#endif

} // anonymous namespace

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

std::string detect_default_gateway()
{
#ifdef _WIN32
	MIB_IPFORWARDROW row;
	memset(&row, 0, sizeof(row));
	DWORD ret = GetBestRoute(0, 0, &row);
	if (ret != NO_ERROR) return "";

	struct in_addr addr;
	addr.s_addr = static_cast<unsigned long>(row.dwForwardNextHop);
	char buf[64];
	if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
		return std::string(buf);
	return "";
#else
	std::string line = popen_read_line("ip route show default 2>/dev/null");
	if (line.empty()) return "";
	return extract_after(line, "via ");
#endif
}

std::string detect_wan_interface()
{
#ifdef _WIN32
	// Not needed on Windows (server auto-setup is Linux only)
	return "";
#else
	std::string line = popen_read_line("ip route show default 2>/dev/null");
	if (line.empty()) return "";
	return extract_after(line, "dev ");
#endif
}

std::string detect_wan_local_ip()
{
#ifdef _WIN32
	// Not needed on Windows (maxcalls policy routing is Linux only)
	return "";
#else
	// "ip route get" resolves the actual source address the kernel would use
	// for an internet destination over the current physical default route.
	std::string line = popen_read_line("ip route get 1.1.1.1 2>/dev/null");
	if (line.empty()) return "";
	return extract_after(line, "src ");
#endif
}

// ---------------------------------------------------------------------------
// DNS resolution
// ---------------------------------------------------------------------------

std::string resolve_hostname_sync(const std::string& hostname)
{
	try
	{
		boost::asio::io_context io;
		boost::asio::ip::udp::resolver resolver(io);
		auto results = resolver.resolve(boost::asio::ip::udp::v4(), hostname, "0");
		for (const auto& entry : results)
			return entry.endpoint().address().to_string();
		return "";
	}
	catch (const std::exception& e)
	{
		std::cerr << "[AutoSetup] DNS resolution failed: " << e.what() << std::endl;
		return "";
	}
}

// ---------------------------------------------------------------------------
// Server setup / teardown (Linux only)
// ---------------------------------------------------------------------------

#ifndef _WIN32

bool server_setup(setup_state& state)
{
	state.mode = run_mode::server;

	// 1. Detect WAN interface
	state.wan_interface = detect_wan_interface();
	if (state.wan_interface.empty())
	{
		std::cerr << "[AutoSetup] Could not detect WAN interface. "
		          << "Make sure a default route exists." << std::endl;
		return false;
	}
	std::cout << "[AutoSetup] Detected WAN interface: " << state.wan_interface << std::endl;

	// 2. Enable IP forwarding if not already enabled
	{
		FILE* fp = fopen("/proc/sys/net/ipv4/ip_forward", "r");
		if (fp)
		{
			int c = fgetc(fp);
			fclose(fp);
			if (c == '0')
			{
				std::cout << "[AutoSetup] Enabling IP forwarding..." << std::endl;
				if (system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1") == 0)
					state.enabled_ip_forward = true;
				else
					std::cerr << "[AutoSetup] WARNING: Failed to enable IP forwarding" << std::endl;
			}
			else
			{
				std::cout << "[AutoSetup] IP forwarding already enabled" << std::endl;
			}
		}
		else
		{
			std::cerr << "[AutoSetup] WARNING: Could not read /proc/sys/net/ipv4/ip_forward" << std::endl;
		}
	}

	// 3. Add iptables rules
	// Rule bodies stored WITHOUT -A/-D so we can use either prefix.
	std::vector<std::string> rules = {
		"-t nat POSTROUTING -o " + state.wan_interface + " -j MASQUERADE",
		"FORWARD -i " + state.tun_interface + " -o " + state.wan_interface + " -j ACCEPT",
		"FORWARD -i " + state.wan_interface + " -o " + state.tun_interface +
			" -m state --state RELATED,ESTABLISHED -j ACCEPT",
		"-t mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
	};

	for (const auto& rule : rules)
	{
		// Delete stale rule first (ignore failure — may not exist)
		std::string del_cmd = "iptables -D " + rule + " 2>/dev/null";
		system(del_cmd.c_str());

		// Add rule
		std::string add_cmd = "iptables -A " + rule;
		std::cout << "[AutoSetup] " << add_cmd << std::endl;
		if (system(add_cmd.c_str()) != 0)
			std::cerr << "[AutoSetup] WARNING: iptables rule may have failed: " << add_cmd << std::endl;

		state.iptables_rules_added.push_back(rule);
	}

	return true;
}

void server_teardown(const setup_state& state)
{
	if (state.mode != run_mode::server) return;

	std::cout << "[AutoSetup] Cleaning up server configuration..." << std::endl;

	// Remove iptables rules in reverse order
	for (auto it = state.iptables_rules_added.rbegin();
	     it != state.iptables_rules_added.rend(); ++it)
	{
		std::string del_cmd = "iptables -D " + *it + " 2>/dev/null";
		std::cout << "[AutoSetup] " << del_cmd << std::endl;
		system(del_cmd.c_str());
	}

	// Restore ip_forward if we changed it
	if (state.enabled_ip_forward)
	{
		std::cout << "[AutoSetup] Restoring IP forwarding to disabled" << std::endl;
		system("sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1");
	}
}

#else // _WIN32

bool server_setup(setup_state& /*state*/)
{
	std::cerr << "[AutoSetup] Server auto-setup (-s) is only supported on Linux." << std::endl;
	std::cerr << "            On Windows, use manual mode with --ip and configure NAT yourself." << std::endl;
	return false;
}

void server_teardown(const setup_state& /*state*/)
{
	// No-op on Windows
}

#endif // _WIN32

// ---------------------------------------------------------------------------
// Client setup / teardown (cross-platform)
// ---------------------------------------------------------------------------

bool client_setup(setup_state& state)
{
	state.mode = run_mode::client;

	if (state.server_public_ip.empty())
	{
		std::cerr << "[AutoSetup] Server IP not resolved" << std::endl;
		return false;
	}

	// 1. Detect local gateway
	state.local_gateway_ip = detect_default_gateway();
	if (state.local_gateway_ip.empty())
	{
		std::cerr << "[AutoSetup] Could not detect local gateway. "
		          << "Make sure a default route exists." << std::endl;
		return false;
	}
	std::cout << "[AutoSetup] Detected local gateway: " << state.local_gateway_ip << std::endl;

#ifndef _WIN32
	state.local_gateway_iface = detect_wan_interface();
	if (state.local_gateway_iface.empty())
	{
		std::cerr << "[AutoSetup] WARNING: Could not detect WAN interface name" << std::endl;
	}
#endif

	// 2. Add static route to server IP via local gateway
	//    This prevents the VPN tunnel's 0.0.0.0/1 route from capturing
	//    the UDP traffic to the server itself (routing loop prevention).
#ifdef _WIN32
	std::string cmd = "route add " + state.server_public_ip +
	                  " mask 255.255.255.255 " + state.local_gateway_ip + " metric 1";
#else
	std::string cmd = "ip route add " + state.server_public_ip +
	                  "/32 via " + state.local_gateway_ip;
	if (!state.local_gateway_iface.empty())
		cmd += " dev " + state.local_gateway_iface;
#endif

	std::cout << "[AutoSetup] Adding static route: " << cmd << std::endl;
	if (system(cmd.c_str()) != 0)
	{
		std::cerr << "[AutoSetup] WARNING: Static route command returned non-zero "
		          << "(may already exist, continuing)" << std::endl;
	}
	state.static_route_added = true;

	return true;
}

void client_teardown(const setup_state& state)
{
	if (state.mode != run_mode::client) return;

	if (state.static_route_added && !state.server_public_ip.empty())
	{
		std::cout << "[AutoSetup] Removing static route to " << state.server_public_ip << std::endl;

#ifdef _WIN32
		std::string cmd = "route delete " + state.server_public_ip;
#else
		std::string cmd = "ip route delete " + state.server_public_ip + "/32 2>/dev/null";
#endif
		system(cmd.c_str());
	}
}

// ---------------------------------------------------------------------------
// maxcalls transport policy routing (Linux only)
// ---------------------------------------------------------------------------

bool maxcalls_policy_setup(setup_state& state)
{
#ifdef _WIN32
	// Windows has no source-based policy routing via route/netsh, so the
	// maxcalls full-tunnel bypass is Linux only. Callers keep Windows on
	// split-tunnel instead. Nothing to do here.
	(void)state;
	std::cerr << "[AutoSetup] maxcalls policy routing is not supported on Windows" << std::endl;
	return false;
#else
	std::string gw = detect_default_gateway();
	std::string wan = detect_wan_interface();
	state.wan_local_ip = detect_wan_local_ip();

	if (gw.empty() || wan.empty() || state.wan_local_ip.empty())
	{
		std::cerr << "[AutoSetup] Could not determine WAN gateway/interface/source IP "
		          << "for maxcalls policy routing (gw='" << gw << "' dev='" << wan
		          << "' src='" << state.wan_local_ip << "')" << std::endl;
		return false;
	}

	const std::string table = std::to_string(MAXCALLS_POLICY_TABLE);

	std::cout << "[AutoSetup] maxcalls transport pinned to " << state.wan_local_ip
	          << " via " << gw << " dev " << wan
	          << " (policy table " << table << ")" << std::endl;

	// A dedicated table carrying just the physical default. "dev <wan>" makes the
	// gateway directly reachable on that link, so this route is self-sufficient
	// even while the main table's default is overridden by the VPN /1 routes.
	system(("ip route replace default via " + gw + " dev " + wan +
	        " table " + table).c_str());

	// Steer everything sourced from the bound uplink IP into that table. The
	// maxcalls sockets bind to wan_local_ip (Config.bind_address), so their
	// packets match this rule and bypass the VPN default route.
	std::string rule = "from " + state.wan_local_ip + " table " + table;
	// Remove any stale copy first so we don't stack duplicate rules on restart.
	system(("ip rule del " + rule + " 2>/dev/null").c_str());
	if (system(("ip rule add " + rule + " priority 1000").c_str()) != 0)
	{
		std::cerr << "[AutoSetup] WARNING: 'ip rule add " << rule
		          << "' returned non-zero" << std::endl;
	}
	system("ip route flush cache 2>/dev/null");

	state.maxcalls_policy_added = true;
	return true;
#endif
}

void maxcalls_policy_teardown(const setup_state& state)
{
#ifdef _WIN32
	(void)state;
#else
	if (!state.maxcalls_policy_added) return;

	const std::string table = std::to_string(MAXCALLS_POLICY_TABLE);
	std::cout << "[AutoSetup] Removing maxcalls policy routing" << std::endl;

	if (!state.wan_local_ip.empty())
	{
		system(("ip rule del from " + state.wan_local_ip + " table " + table +
		        " 2>/dev/null").c_str());
	}
	system(("ip route flush table " + table + " 2>/dev/null").c_str());
	system("ip route flush cache 2>/dev/null");
#endif
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

#ifdef _WIN32

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
	if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT ||
	    ctrl_type == CTRL_BREAK_EVENT)
	{
		if (!g_shutdown_called.exchange(true) && g_shutdown_callback)
			g_shutdown_callback();
		return TRUE;
	}
	return FALSE;
}

void install_signal_handlers(std::function<void()> on_shutdown)
{
	g_shutdown_callback = std::move(on_shutdown);
	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
}

#else

static void signal_handler(int /*sig*/)
{
	if (!g_shutdown_called.exchange(true) && g_shutdown_callback)
		g_shutdown_callback();
}

void install_signal_handlers(std::function<void()> on_shutdown)
{
	g_shutdown_callback = std::move(on_shutdown);
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);
}

#endif

} // namespace autosetup
} // namespace udp
} // namespace dixelu
