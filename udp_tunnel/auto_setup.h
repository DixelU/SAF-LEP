#pragma once

#ifndef SAF_LEP_AUTO_SETUP_H
#define SAF_LEP_AUTO_SETUP_H

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <unordered_set>

namespace dixelu {
namespace udp {
namespace autosetup {

enum class run_mode { legacy, server, client };

// Captures everything done during auto-setup so teardown can reverse it exactly.
struct setup_state
{
	run_mode mode = run_mode::legacy;

	// Server (Linux only)
	bool enabled_ip_forward = false;      // Did we change ip_forward from 0 to 1?
	std::string wan_interface;             // e.g. "eth0"
	std::string tun_interface = "tun0";
	std::vector<std::string> iptables_rules_added; // Rule bodies (without -A/-D prefix)

	// Client (Linux + Windows)
	std::string server_public_ip;          // Resolved IP of server
	std::string local_gateway_ip;          // Physical gateway for static route
	std::string local_gateway_iface;       // (Linux only) e.g. "eth0"
	bool static_route_added = false;

	// maxcalls transport routing. Linux uses a source-policy table. Windows
	// snapshots the physical route before enabling the VPN and owns temporary
	// /32 routes for every dynamically discovered transport address.
	std::string wan_local_ip;              // Source IP of the physical default route
	std::string maxcalls_wan_gateway_ip;   // Windows physical next hop
	uint32_t maxcalls_wan_interface_index = 0;
	mutable std::mutex maxcalls_routes_mutex;
	std::unordered_set<std::string> maxcalls_routes_added;
	bool maxcalls_policy_added = false;
};

// Fixed routing table id used for the maxcalls transport bypass (Linux only).
// A numeric id works without an /etc/iproute2/rt_tables entry.
constexpr int MAXCALLS_POLICY_TABLE = 51821;

// --- Platform detection ---

// Returns the default gateway IP from the system routing table. Empty on failure.
std::string detect_default_gateway();

// Returns the WAN interface name (default route device). Empty on failure. Linux only.
std::string detect_wan_interface();

// Returns the local source IP the kernel uses to reach the internet over the
// physical default route (e.g. "192.168.1.50"). Empty on failure. Linux only.
std::string detect_wan_local_ip();

// --- maxcalls transport routing ---
//
// Linux installs a source-based policy rule. Windows captures the physical
// gateway/interface/source and bypasses any public DNS servers needed after the
// full-tunnel routes are installed. AVTTS then reports each dynamically chosen
// address through maxcalls_policy_add_transport_address().
bool maxcalls_policy_setup(setup_state& state);
bool maxcalls_policy_add_transport_address(setup_state& state, const std::string& address);
void maxcalls_policy_teardown(setup_state& state);

// --- DNS resolution ---

// Synchronous hostname resolution using Boost.Asio resolver.
// Must be called BEFORE VPN routes are installed.
// Returns empty string on failure.
std::string resolve_hostname_sync(const std::string& hostname);

// --- Server setup/teardown (Linux only, no-op on Windows) ---

bool server_setup(setup_state& state);
void server_teardown(const setup_state& state);

// --- Client setup/teardown (Linux + Windows) ---

bool client_setup(setup_state& state);
void client_teardown(const setup_state& state);

// --- Signal handling ---

// Installs Ctrl+C / SIGINT / SIGTERM handlers.
// The callback should set an atomic<bool> flag; teardown runs in the main thread.
void install_signal_handlers(std::function<void()> on_shutdown);

} // namespace autosetup
} // namespace udp
} // namespace dixelu

#endif // SAF_LEP_AUTO_SETUP_H
