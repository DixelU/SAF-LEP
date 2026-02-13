# SAF-LEP Project Memory

## Project Overview
- DPI-evasion VPN tunnel using Low Entropy Protocol (LEP) encoding
- C++23, Boost.Asio, cross-platform (Windows TAP, Linux TUN, Android)
- Build: MSVC via `SAF-LEP-ExPuN.sln` (Windows), CMake (Linux)

## Key Architecture
- `test.cpp` - CLI entry point + watchscreen UI
- `udp_tunnel/tunnel.h/.cpp` - P2P tunnel + vpn_interface classes
- `udp_tunnel/auto_setup.h/.cpp` - Auto-setup/teardown for server (iptables/forwarding) and client (gateway detection, static routes)
- `udp_tunnel/windows_tap.h/.cpp` - Windows TAP adapter
- `udp_tunnel/linux_tun.h/.cpp` - Linux TUN adapter
- `lep/encryption.h` - XOR stream cipher (PoC, not secure)
- `lep/low_entropy_protocol.h` - LEP v0 encoding

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
