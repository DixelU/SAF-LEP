#pragma once

#ifndef SAF_LEP_AUTO_SETUP_H
#define SAF_LEP_AUTO_SETUP_H

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <cstdint>

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

	// maxcalls transport policy routing (Linux only). Unlike the p2p tunnel the
	// maxcalls transport has no single fixed server IP to exclude, so instead we
	// bind its sockets to the physical uplink IP and steer that source out of the
	// WAN with a policy-routing rule.
	std::string wan_local_ip;              // Source IP of the physical default route
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

// --- maxcalls transport policy routing (Linux only, no-op on Windows) ---
//
// Installs a source-based policy rule so packets sent from state.wan_local_ip
// bypass the VPN's 0.0.0.0/1 + 128.0.0.0/1 override routes and egress the
// physical uplink. Pass the same source IP as maxcalls Config.bind_address so
// the transport's sockets are actually pinned to it. Detects wan_local_ip and
// the gateway/interface itself; returns false if they can't be determined.
bool maxcalls_policy_setup(setup_state& state);
void maxcalls_policy_teardown(const setup_state& state);

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
