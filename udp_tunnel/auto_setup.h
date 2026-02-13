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
};

// --- Platform detection ---

// Returns the default gateway IP from the system routing table. Empty on failure.
std::string detect_default_gateway();

// Returns the WAN interface name (default route device). Empty on failure. Linux only.
std::string detect_wan_interface();

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
