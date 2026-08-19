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
#include <limits>
#include <vector>

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

#ifdef _WIN32
bool parse_ipv4(const std::string& text, IN_ADDR& address)
{
	return inet_pton(AF_INET, text.c_str(), &address) == 1;
}

std::string ipv4_to_string(const IN_ADDR& address)
{
	char buffer[INET_ADDRSTRLEN]{};
	return inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) ? std::string(buffer) : std::string();
}

bool needs_physical_bypass(const IN_ADDR& address)
{
	const uint32_t ip = ntohl(address.S_un.S_addr);
	const uint8_t first = static_cast<uint8_t>(ip >> 24);
	const uint8_t second = static_cast<uint8_t>((ip >> 16) & 0xFF);

	// Private, link-local and other non-routable candidates either already have
	// a more-specific connected route or must never be sent to the WAN gateway.
	if (first == 0 || first == 10 || first == 127 || first >= 224) return false;
	if (first == 100 && second >= 64 && second <= 127) return false;
	if (first == 169 && second == 254) return false;
	if (first == 172 && second >= 16 && second <= 31) return false;
	if (first == 192 && second == 168) return false;
	return true;
}

bool make_maxcalls_route(const setup_state& state, const std::string& destination,
	MIB_IPFORWARD_ROW2& row)
{
	IN_ADDR destination_address{};
	IN_ADDR gateway_address{};
	if (!parse_ipv4(destination, destination_address) ||
		!parse_ipv4(state.maxcalls_wan_gateway_ip, gateway_address))
		return false;

	InitializeIpForwardEntry(&row);
	row.InterfaceIndex = state.maxcalls_wan_interface_index;
	row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
	row.DestinationPrefix.Prefix.Ipv4.sin_addr = destination_address;
	row.DestinationPrefix.PrefixLength = 32;
	row.NextHop.Ipv4.sin_family = AF_INET;
	row.NextHop.Ipv4.sin_addr = gateway_address;
	row.Metric = 1;
	row.Protocol = MIB_IPPROTO_NETMGMT;
	return true;
}

bool find_physical_default_route(MIB_IPFORWARD_ROW2& selected)
{
	PMIB_IPFORWARD_TABLE2 table = nullptr;
	if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR || !table)
		return false;

	uint64_t best_metric = (std::numeric_limits<uint64_t>::max)();
	bool found = false;
	for (ULONG i = 0; i < table->NumEntries; ++i)
	{
		const auto& route = table->Table[i];
		if (route.DestinationPrefix.PrefixLength != 0 ||
			route.DestinationPrefix.Prefix.si_family != AF_INET ||
			route.NextHop.si_family != AF_INET ||
			route.NextHop.Ipv4.sin_addr.S_un.S_addr == 0)
			continue;

		MIB_IF_ROW2 interface_row{};
		interface_row.InterfaceIndex = route.InterfaceIndex;
		if (GetIfEntry2(&interface_row) != NO_ERROR ||
			interface_row.OperStatus != IfOperStatusUp ||
			interface_row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
			interface_row.Type == IF_TYPE_TUNNEL)
			continue;

		MIB_IPINTERFACE_ROW ip_interface{};
		InitializeIpInterfaceEntry(&ip_interface);
		ip_interface.Family = AF_INET;
		ip_interface.InterfaceIndex = route.InterfaceIndex;
		const uint64_t interface_metric =
			GetIpInterfaceEntry(&ip_interface) == NO_ERROR ? ip_interface.Metric : 0;
		const uint64_t metric = static_cast<uint64_t>(route.Metric) + interface_metric;
		if (!found || metric < best_metric)
		{
			selected = route;
			best_metric = metric;
			found = true;
		}
	}

	FreeMibTable(table);
	return found;
}
#endif

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
	SOCKADDR_INET destination{};
	destination.Ipv4.sin_family = AF_INET;
	if (inet_pton(AF_INET, "1.1.1.1", &destination.Ipv4.sin_addr) != 1)
		return false;

	MIB_IPFORWARD_ROW2 physical_default{};
	if (!find_physical_default_route(physical_default))
	{
		std::cerr << "[AutoSetup] Could not find an active physical Windows default route"
		          << std::endl;
		return false;
	}

	MIB_IPFORWARD_ROW2 best_route{};
	SOCKADDR_INET best_source{};
	const DWORD best_result = GetBestRoute2(nullptr, physical_default.InterfaceIndex,
		nullptr, &destination, 0,
		&best_route, &best_source);
	if (best_result != NO_ERROR || best_route.InterfaceIndex == 0 ||
		best_route.NextHop.si_family != AF_INET || best_source.si_family != AF_INET)
	{
		std::cerr << "[AutoSetup] Could not capture the physical Windows route before enabling the VPN"
		          << " (error " << best_result << ")" << std::endl;
		return false;
	}

	state.maxcalls_wan_interface_index = best_route.InterfaceIndex;
	state.maxcalls_wan_gateway_ip = ipv4_to_string(physical_default.NextHop.Ipv4.sin_addr);
	state.wan_local_ip = ipv4_to_string(best_source.Ipv4.sin_addr);
	if (state.maxcalls_wan_gateway_ip.empty() || state.wan_local_ip.empty())
		return false;

	state.maxcalls_policy_added = true;
	std::cout << "[AutoSetup] maxcalls transport pinned to " << state.wan_local_ip
	          << " via " << state.maxcalls_wan_gateway_ip
	          << " IF " << state.maxcalls_wan_interface_index
	          << " (dynamic Windows /32 bypass)" << std::endl;

	// Windows DNS runs outside AVTTS, so public DNS servers need their bypasses
	// before the TAP /1 routes are installed. Private/LAN DNS is already covered
	// by the physical adapter's connected route and is deliberately skipped.
	ULONG buffer_size = 16 * 1024;
	std::vector<unsigned char> buffer(buffer_size);
	PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
	ULONG result = GetAdaptersAddresses(AF_INET,
		GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, adapters, &buffer_size);
	if (result == ERROR_BUFFER_OVERFLOW)
	{
		buffer.resize(buffer_size);
		adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
		result = GetAdaptersAddresses(AF_INET,
			GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, adapters, &buffer_size);
	}
	if (result == NO_ERROR)
	{
		for (auto* adapter = adapters; adapter; adapter = adapter->Next)
		{
			if (adapter->IfIndex != state.maxcalls_wan_interface_index) continue;
			for (auto* dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next)
			{
				if (!dns->Address.lpSockaddr || dns->Address.lpSockaddr->sa_family != AF_INET) continue;
				const auto* dns_address = reinterpret_cast<const sockaddr_in*>(dns->Address.lpSockaddr);
				const std::string address = ipv4_to_string(dns_address->sin_addr);
				if (!address.empty() && !maxcalls_policy_add_transport_address(state, address))
				{
					maxcalls_policy_teardown(state);
					return false;
				}
			}
			break;
		}
	}
	else
	{
		std::cerr << "[AutoSetup] WARNING: Could not enumerate physical DNS servers (error "
		          << result << ")" << std::endl;
	}

	return true;
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

bool maxcalls_policy_add_transport_address(setup_state& state, const std::string& address)
{
#ifdef _WIN32
	IN_ADDR parsed{};
	if (!parse_ipv4(address, parsed) || !needs_physical_bypass(parsed))
		return true;
	if (!state.maxcalls_policy_added)
		return false;

	std::lock_guard<std::mutex> lock(state.maxcalls_routes_mutex);
	if (state.maxcalls_routes_added.find(address) != state.maxcalls_routes_added.end())
		return true;

	MIB_IPFORWARD_ROW2 row{};
	if (!make_maxcalls_route(state, address, row))
		return false;

	const DWORD result = CreateIpForwardEntry2(&row);
	if (result == NO_ERROR)
	{
		state.maxcalls_routes_added.insert(address);
		std::cout << "[AutoSetup] MAX bypass: " << address << "/32 via "
		          << state.maxcalls_wan_gateway_ip << " IF "
		          << state.maxcalls_wan_interface_index << std::endl;
		return true;
	}
	if (result == ERROR_OBJECT_ALREADY_EXISTS)
		return true;

	std::cerr << "[AutoSetup] Failed to add MAX bypass route for " << address
	          << " (error " << result << ")" << std::endl;
	return false;
#else
	(void)state;
	(void)address;
	return true;
#endif
}

void maxcalls_policy_teardown(setup_state& state)
{
#ifdef _WIN32
	if (!state.maxcalls_policy_added) return;

	std::lock_guard<std::mutex> lock(state.maxcalls_routes_mutex);
	for (const auto& address : state.maxcalls_routes_added)
	{
		MIB_IPFORWARD_ROW2 row{};
		if (make_maxcalls_route(state, address, row))
		{
			const DWORD result = DeleteIpForwardEntry2(&row);
			if (result != NO_ERROR && result != ERROR_NOT_FOUND)
				std::cerr << "[AutoSetup] WARNING: Failed to remove MAX bypass route for "
				          << address << " (error " << result << ")" << std::endl;
		}
	}
	state.maxcalls_routes_added.clear();
	state.maxcalls_policy_added = false;
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
	state.maxcalls_policy_added = false;
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
