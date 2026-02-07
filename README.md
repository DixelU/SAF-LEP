# SAF-LEP (Simple/Secure AF - Low Entropy Protocol)

SAF-LEP is a Proof-of-Concept VPN tunneling tool designed to evade Deep Packet Inspection (DPI) by masquerading encrypted traffic as low-entropy "noise" or potentially mimicking unencrypted media streams (future work).

The core idea is **Low Entropy Protocol (LEP)**: instead of sending a solid block of high-entropy encrypted data (which is easily flagged by DPI as "unknown encrypted protocol" or WireGuard/OpenVPN), LEP embeds the encrypted payload into a larger, lower-entropy frame, or distributes it in a way that statistically resembles natural data.

---

## Security Notice

> **This is a Proof-of-Concept project for research and educational purposes only.**

**DO NOT use this for protecting sensitive data.** The cryptographic implementation is intentionally simplified for demonstration purposes and has known weaknesses:

- Custom stream cipher based on xorshift - **not cryptographically secure**
- Key derivation uses DJB2 hash instead of proper KDFs (PBKDF2, Argon2)
- Non-cryptographic PRNG (LCG) for ground state generation

The goal of this project is **DPI evasion**, not secure encryption. If you need actual security, use established VPNs (WireGuard, OpenVPN) or layer this tool with proper encryption.

---

## Features
- **Cross-Platform**: Runs on **Windows** (using TAP-Windows adapter) and **Linux** (using TUN interface). **Android** support is in progress.
- **P2P Architecture**: UDP-based tunneling with NAT traversal capabilities.
- **Fragmentation & Reassembly**: Custom reliability layer over UDP to handle large IP packets (MTU 1500) over smaller UDP datagrams.
- **Resiliency**: Implements packet loss detection and retransmission (ARQ) with backoff logic to prevent network flooding.
- **Live Watchscreen**: Real-time monitoring of VPN statistics, throughput, and packet events with `-w` flag.
- **DPI Evasion**:
    - **Low Entropy Encoding**: Payload is encoded to reduce statistical randomness.
    - **Jitter/Padding**: (Planned) Traffic shaping to hide packet timing signatures.

--- 

## Platform Support

### ✅ Fully Implemented
- **Windows** (TAP-Windows adapter)
- **Linux** (TUN interface)

### 🚧 In Progress
- **Android** (VpnService API) - JNI bridge and core C++ integration complete, but full app not yet finalized. See `android/` directory for bare-bones implementation.

### 📋 Planned
- **Android Server Mode** - Allow Android devices to act as VPN exit nodes
- **iOS** Support - Using NetworkExtension framework
- **macOS** Support - Using utun interface

## Near Future Plans

- **Complete Android VPN Client** - Finish the Android app with proper UI and integration
    - High priority ⭐
- Fully automatic setup (just address and mode flag, nothing more 😅)
- Containerized version (Docker)
- More encoding "modes" (currently only `raw_lep_v0` is implemented - partially VoIP/MPEG1 like headers with near-constant value fields)
    - `html`
    - `raw_text`
    - `rtsp`
    - ... whatever 💁
- Improved NAT traversal (STUN/TURN integration)

---

## Build Instructions

### Prerequisites
- **CMake** (3.10+)
- **Boost Libraries** (System, Thread, Asio)
- **C++23 Compliant Compiler** (MSVC for Windows, GCC/Clang for Linux)

### Linux
```bash
mkdir build_linux
cd build_linux
cmake ..
make
```

### Windows

#### Option 1: CMake Build
1. Open the folder in Visual Studio (or use CMake GUI).
2. Ensure `Boost_ROOT` is set if not in standard paths.
3. Build the `SAF-LEP.exe` target.

#### Option 2: Visual Studio Solution (Recommended)
Open `SAF-LEP-ExPuN.sln` in Visual Studio. Requires static Boost libraries installed via vcpkg:
```bash
# Install vcpkg globally if not already installed
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install Boost
.\vcpkg install boost:x64-windows-static
```

### Android (Work in Progress)
**Note:** Android support is currently in development.

For developers interested in contributing or testing, see the [Android README](android/README.md) for the current state and build instructions.

---

## Usage Instructions

### Command-Line Options

```
Usage: SAF-LEP [OPTIONS]

Options:
  -p, --port PORT          Local UDP port (default: 0 = auto)
  -c, --connect HOST:PORT  Connect to peer
  -v, --verbose            Enable verbose logging
  -w, --watchscreen        Enable live stats watchscreen
      --ip IP              VPN IP address (e.g. 10.0.0.1)
      --mask MASK          VPN Subnet mask (default: 255.255.255.0)
      --gw GATEWAY         VPN Gateway (optional)
  -k, --seed-key KEY       Encryption seed key (optional)
  -h, --help               Show help message
```

### 1. Server Setup (Linux)
The server acts as the exit node. It needs to forward traffic from the VPN interface (`tun0`) to the internet (`eth0` or `wlan0`).

**Enable IP Forwarding & NAT:**
```bash
# 1. Enable IP Forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Enable NAT (Masquerade) for outgoing traffic
# Replace 'eth0' with your internet interface name (check with `ip addr`)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 3. Allow Forwarding
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# 4. Enable MSS Clamping (Critical for some sites to load)
sudo iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

**Run Server:**
```bash
sudo ./SAF-LEP -p 14578 --ip 10.0.0.1
```

### 2. Client Setup

**⚠️ CRITICAL: Prevent Routing Loops ⚠️**
Before starting the client, you **MUST** add a static route to the VPN Server's *Public IP* via your *Physical Gateway*. If you don't, the encrypted VPN packets will try to go through the VPN tunnel itself, creating a loop.

#### Linux Client
```bash
# 1. Add route to server public IP via local gateway
# Example: Server=1.2.3.4, LocalGateway=192.168.1.1
sudo ip route add 1.2.3.4 via 192.168.1.1

# 2. Run Client
sudo ./SAF-LEP -c 1.2.3.4:14578 --ip 10.0.0.2 --gw 10.0.0.1
```

#### Windows Client

**⚠️ CRITICAL: TAP Adapter Name Requirements ⚠️**
The TAP-Windows adapter name **MUST contain only ASCII characters**. Non-ASCII characters (e.g., Cyrillic, Chinese, special symbols) in the adapter name will cause configuration failures because Windows `netsh` commands may not handle encoding properly.

**To rename your TAP adapter:**
1. Open **Control Panel** → **Network and Sharing Center** → **Change adapter settings**
2. Find your TAP adapter (usually named "Ethernet 2" or "TAP-Windows Adapter V9")
3. Right-click → **Rename** → Use only English letters, numbers, spaces, and basic punctuation
4. Examples of **GOOD** names: `VPN-TAP`, `SAF_LEP_Adapter`, `TAP Adapter 1`
5. Examples of **BAD** names: `VPN适配器`, `Адаптер`, `VPN⚡Adapter`

**Setup Commands:**
```bash
# 1. Add route to server public IP via local gateway
# Open Admin PowerShell/CMD
# Example: Server=1.2.3.4, LocalGateway=192.168.1.1
route add 1.2.3.4 mask 255.255.255.255 192.168.1.1 metric 1

# 2. Run Client
./SAF-LEP.exe -c 1.2.3.4:14578 --ip 10.0.0.2 --gw 10.0.0.1
```

### 3. Verification
From the Client:
```bash
# Ping the server's VPN IP
ping 10.0.0.1

# Check internet connectivity (should hop through 10.0.0.1)
tracert 8.8.8.8   # Windows
traceroute 8.8.8.8 # Linux
```

---

## Troubleshooting

### "Reassembly Desync" or Packet Loss
- Ensure both Client and Server are running the latest version.
- Check firewall on Server (allow UDP port 14578).
- Check Windows Firewall on Client (allow `SAF-LEP.exe`).

### Windows: "General Failure" on Ping
- This usually means the TAP adapter is not configured correctly or the route is missing.
- The application now attempts to force the route to the TAP interface index. Check logs for `Using Interface Index: X`.

### Windows: TAP Adapter Configuration Fails
- **Check adapter name encoding**: Ensure your TAP adapter has an **ASCII-only** name (see Windows Client Setup section above).
- **Symptoms**: Application starts but IP configuration fails, or `netsh` commands fail silently.
- **Solution**: Rename your TAP adapter to contain only English letters, numbers, and basic punctuation.

### Windows: "Unidentified Network"
- This is normal for TAP adapters without a default gateway. It does not affect functionality as long as the routes are correct.

---

## Known Limitations

### Design Limitations (By Design for PoC)

- **Weak Cryptography**: Intentionally simplified; see Security Notice above
- **No Perfect Forward Secrecy**: Static keys only
- **No Authentication**: Peers are not cryptographically authenticated
- **Hardcoded MAC Addresses**: Uses fixed dummy MAC for ARP responses

### Contributions Welcome

PRs for improvements and new encoding modes are welcome!

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│              Application Layer                      │
│     (Ping, HTTP, etc. on VPN interface)             │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│           VPN Interface Layer                       │
│    (TAP/TUN adapter - Ethernet/IP packets)          │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│       Fragmentation/Reassembly Layer                │
│       (Splits packets into 150-byte chunks)         │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│            Encryption Layer                         │
│         (XOR-based stream cipher)                   │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│    Low Entropy Protocol (LEP) Encoding              │
│   (Embeds encrypted data in low-entropy frames)     │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│           UDP/IP Layer (Boost.ASIO)                 │
│        (Sends encoded packets over UDP)             │
└─────────────────────────────────────────────────────┘
```

