# SAF-LEP (Secure AF - Low Entropy Protocol)

SAF-LEP is a Proof-of-Concept VPN tunneling tool designed to evade Deep Packet Inspection (DPI) by masquerading encrypted traffic as high-entropy "noise" or potentially mimicking unencrypted media streams (future work).

The core idea is **Low Entropy Protocol (LEP)**: instead of sending a solid block of high-entropy encrypted data (which is easily flagged by DPI as "unknown encrypted protocol" or WireGuard/OpenVPN), LEP embeds the encrypted payload into a larger, lower-entropy frame, or distributes it in a way that statistically resembles natural data.

## Features
- **Cross-Platform**: Runs on **Windows** (using TAP-Windows adapter) and **Linux** (using TUN interface).
- **P2P Architecture**: UDP-based tunneling with NAT traversal capabilities.
- **Fragmentation & Reassembly**: Custom reliability layer over UDP to handle large IP packets (MTU 1500) over smaller UDP datagrams.
- **Resiliency**: Implements packet loss detection and retransmission (ARQ) with backoff logic to prevent network flooding.
- **DPI Evasion**: 
    - **Low Entropy Encoding**: Payload is encoded to reduce statistical randomness.
    - **Jitter/Padding**: (Planned) Traffic shaping to hide packet timing signatures.

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
1. Open the folder in Visual Studio (or use CMake GUI).
2. Ensure `Boost_ROOT` is set if not in standard paths.
3. Build the `SAF-LEP.exe` target.

---

## Usage Instructions 

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

### Windows: "Unidentified Network"
- This is normal for TAP adapters without a default gateway. It does not affect functionality as long as the routes are correct.


