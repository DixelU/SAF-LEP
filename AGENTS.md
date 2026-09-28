# SAF-LEP Project Memory

## Project Overview
- DPI-evasion VPN tunnel using Low Entropy Protocol (LEP) encoding
- C++23, Boost.Asio, cross-platform (Windows TAP, Linux TUN, Android)
- Build: MSVC via `SAF-LEP-ExPuN.sln` (Windows), CMake (Linux)

## Key Architecture
- UDP is the only transport; the SAF-AVTTS/MaxTunnel transport was removed (2026-09-28)
- `test.cpp` - CLI entry point + watchscreen UI
- `udp_tunnel/tunnel.h/.cpp` - `p2p_tunnel` (UDP transport behind `tunnel_interface`) + `vpn_interface`
- `udp_tunnel/reconnect_handshake.h` - Challenge-response reconnect protocol
- `udp_tunnel/ip_routing.h` - Per-peer VPN address routing (`--forwarding route`)
- `udp_tunnel/auto_setup.h/.cpp` - Auto-setup/teardown for server (iptables/forwarding) and client (gateway detection, static routes)
- `udp_tunnel/windows_tap.h/.cpp` - Windows TAP adapter
- `udp_tunnel/linux_tun.h/.cpp` - Linux TUN adapter
- `udp_tunnel/android_tun.h/.cpp` + `android/` - Android VpnService client
- `lep/encryption.h` - XOR stream cipher (PoC, not secure)
- `lep/strong_encryption.h` - ChaCha20-Poly1305 draft, not wired in yet
- `lep/low_entropy_protocol.h` - LEP v0, LEP v1 and raw framing
- `tests/protocol_tests.cpp` - Protocol unit tests (ctest)

## CLI Modes
- `-s -p PORT -k KEY` — Server auto-mode (Linux only, auto-NAT/iptables)
- `-c HOST:PORT -k KEY` — Client auto-mode (auto gateway detection, static route)
- `--ip IP` — Legacy manual mode (backward compatible)

## Build on Windows
- `MSYS_NO_PATHCONV=1` needed when invoking MSBuild from Git Bash (prevents `/p:` mangling)
- Pre-existing warnings in windows_tap.cpp and low_entropy_protocol.h (size_t conversions)

## User Preferences
- Prefers backward compatibility with existing workflows
- VPN subnet: 10.0.0.0/24 (server=.1, client=.2)
- Encryption key optional with warning
