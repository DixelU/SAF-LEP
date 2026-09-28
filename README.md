# SAF-LEP

SAF-LEP is an experimental IPv4 VPN that moves packets from a virtual network
interface to a peer over UDP. It runs as a desktop CLI on Windows and Linux,
and as an Android VPN client.

The repository includes:

- a cross-platform C++ tunnel core;
- Windows TAP and Linux TUN adapters;
- a UDP transport with fragmentation, loss detection, and retransmission;
- an Android VpnService application;
- LEP v0, LEP v1, and low-overhead raw packet framing.

> [!WARNING]
> SAF-LEP is a research/proof-of-concept project. Its current seed-key cipher is
> custom, unauthenticated, and not cryptographically secure. Do not rely on it
> for privacy, integrity, identity authentication, or sensitive traffic. Raw
> mode requires a key to prevent accidental plaintext operation, but that
> requirement does not turn the current cipher into production-grade encryption.

## Current support

| Platform | Supported | Virtual interface | Intended role |
| --- | --- | --- | --- |
| Linux desktop | Yes | TUN | Client, peer, or exit node |
| Windows desktop | Yes | TAP-Windows | Client or manually configured peer |
| Android | Yes | Android VpnService/TUN | Client |
| macOS / iOS | No | - | Not implemented |

**Automatic exit-node setup is Linux-only.** Windows can run the tunnel, but
server-side forwarding/NAT must be configured outside SAF-LEP.

## Transport and framing

The transport is UDP. One side listens on a port; the other connects to it.
SAF-LEP adds its own acknowledgement, loss-detection, and retransmission logic
on top, and splits packets into 150-byte fragments that the reliability
protocol is tuned around. The listening side may need a public UDP port,
firewall rule, or router port-forward.

Packet framing is a separate choice. Both peers must use the same framing mode
and the same seed key.

| CLI option | Mode | Wire behaviour | Notes |
| --- | --- | --- | --- |
| none | LEP v0 | Low-entropy expansion | Default and most compatible |
| --lepv1 | LEP v1 | Experimental LEP framing with integrity checks | Both peers must opt in |
| --raw | Raw | 4-byte big-endian packet index followed by the encrypted fragment body | Requires -k |

Raw mode does not apply LEP's byte expansion. The cleartext packet index
selects the per-packet cipher stream; the fragment body, including SAF-LEP's
fragmentation metadata, is transformed before framing.

## Prerequisites

### Windows desktop

- a 64-bit C++23 toolchain;
- Visual Studio 2026 (v145 toolset) for the included solution, or CMake 3.22
  or newer;
- Boost (Asio/System). The Visual Studio project picks it up through vcpkg
  (`vcpkg integrate install`) and links statically (x64-windows-static);
- a TAP-Windows adapter;
- an elevated terminal when creating routes or configuring the adapter.

SAF-LEP uses the first TAP-Windows adapter it finds unless `--tap-guid`
selects one. Adapter names currently need to be representable by the
narrow-character netsh command path; rename the adapter to an ASCII-only name
if setup fails.

### Linux desktop

- a C++23 compiler and CMake 3.22 or newer;
- Boost (Asio/System);
- /dev/net/tun, iproute2, and iptables;
- root privileges or equivalent capabilities for TUN and route changes.

### Android

The Android application requires Android SDK Platform 36, Build Tools 36,
NDK 27.0.12077973, CMake 3.22.1, and JDK 17 or newer. It builds arm64-v8a and
x86_64 variants and supports Android API 24 or newer.

See [android/README.md](android/README.md) for SDK setup, Boost header handling,
command-line builds, installation, and the UI walkthrough.

## Building

### Linux with CMake

~~~bash
cd SAF-LEP
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
~~~

The executable is normally written to build/SAF-LEP.

### Windows with Visual Studio

Open SAF-LEP-ExPuN.sln and build x64 Release.

The root CMakeLists.txt also supports an integrated CMake build, but its current
Windows Boost hints point at D:/Progs/mingw64. Override or update those hints
for a different local toolchain.

### Android

From the android directory:

~~~powershell
.\gradlew.bat :app:assembleDebug
~~~

On Linux or macOS hosts:

~~~bash
./gradlew :app:assembleDebug
~~~

The detailed Android build notes and APK path are in
[android/README.md](android/README.md).

## Quick start

The defaults use VPN subnet 10.0.0.0/24, with 10.0.0.1 on the listening side.
An automatic client chooses a random host address from 10.0.0.2 through
10.0.0.254 and prints the choice at startup.

### Linux exit node

Run in an elevated shell:

~~~bash
sudo ./build/SAF-LEP -s -p 14578 -k "shared seed"
~~~

In automatic server mode SAF-LEP detects the outward-facing interface, enables
IPv4 forwarding if needed, and adds temporary iptables forwarding, MASQUERADE,
and TCP MSS-clamping rules. It removes the rules and restores ip_forward if it
changed it on a normal shutdown.

Allow UDP port 14578 in the host firewall. If the server is behind a router,
forward that UDP port to the server.

### Desktop client

Linux:

~~~bash
sudo ./build/SAF-LEP -c vpn.example.net:14578 -k "shared seed"
~~~

Windows, from an elevated terminal:

~~~powershell
.\SAF-LEP-ExPuN.exe -c vpn.example.net:14578 -k "shared seed"
~~~

Automatic client mode resolves the server before installing VPN routes and pins
the server's public IPv4 address to the existing physical gateway. This keeps
the transport socket out of the VPN and prevents a routing loop.

For a multi-client server, enable destination-IP routing instead of compatible
hub fan-out:

~~~bash
sudo ./build/SAF-LEP -s -p 14578 --forwarding route -k "shared seed"
~~~

On the listening side, routed mode learns each peer's inner source IP and sends
ordinary unicast only to the peer that owns the destination IP. A connecting
client continues to use its single configured peer as the upstream route.
Unknown server-side unicast and duplicate address claims are dropped; multicast
and subnet-broadcast packets still fan out. The default `--forwarding hub` mode
retains the legacy behavior. Automatically configured clients already use
randomized addresses. In manual mode, give every client a distinct `--ip`
value in the server's VPN subnet.

Add the same framing flag at both ends when changing the default. For example:

~~~bash
sudo ./build/SAF-LEP -s -p 14578 --raw -k "shared seed"
sudo ./build/SAF-LEP -c vpn.example.net:14578 --raw -k "shared seed"
~~~

Press Ctrl+C for a clean route and firewall teardown.

### Running several instances

A server can run more than one SAF-LEP process, for example with different
framing modes or seeds. Each process must own a different TUN/TAP adapter, UDP
port, and VPN subnet. On Linux, for example:

~~~bash
sudo ./build/SAF-LEP -s -p 14578 --tun-name safudp0 \
  --ip 192.44.0.1 --mask 255.255.255.0 -k "first seed"

sudo ./build/SAF-LEP -s -p 14579 --raw --tun-name safudp1 \
  --ip 192.45.0.1 --mask 255.255.255.0 -k "second seed"
~~~

Supplying `--ip` deliberately keeps both processes in legacy/manual networking
mode. Configure IPv4 forwarding, firewall policy, and NAT persistently outside
SAF-LEP for both adapters. Do not run two automatic server setups and rely on
each process to own shared MASQUERADE or MSS-clamping rules: stopping either
process could remove rules still needed by the other.

Run only one full-tunnel client at a time so their `/1` default-route
overrides do not compete. Switching between independent VPN subnets is a
reconnect and does not preserve existing TCP sessions.

On Windows, install one TAP-Windows adapter per process and pass each process
the desired adapter's interface GUID with `--tap-guid`. Windows server
forwarding and NAT remain manually administered.

## Android client

The Android application is a client. In the UI, configure:

- server hostname or IPv4 address and UDP port;
- LEP v0, LEP v1, or raw framing;
- the same seed key used by the desktop peer;
- VPN address, prefix length, and optional gateway;
- optional verbose logging.

Raw framing cannot connect without a non-empty seed key. Leaving the gateway
empty routes only the configured VPN subnet; setting a gateway requests the
full IPv4 tunnel routes.

Android protects the transport socket with VpnService.protect(), so its own UDP
connection bypasses the VPN. It cannot act as an exit node.

## Manual and split-tunnel configuration

Supplying --ip selects legacy/manual mode and bypasses the automatic desktop
server/client route setup. Use it when addresses or external routing are being
managed explicitly.

Manual listening peer:

~~~bash
sudo ./build/SAF-LEP -s -p 14578 --ip 10.20.0.1 --mask 255.255.255.0 -k "shared seed"
~~~

Manual connecting peer:

~~~bash
sudo ./build/SAF-LEP -c 203.0.113.10:14578 --ip 10.20.0.2 \
  --mask 255.255.255.0 --gw 10.20.0.1 -k "shared seed"
~~~

A non-empty --gw installs two /1 routes and captures all IPv4 traffic. Omitting
--gw leaves the existing default route in place and routes only the VPN subnet.

In manual full-tunnel mode, you are responsible for keeping the peer's UDP
endpoint reachable through the physical interface and for configuring
forwarding/NAT at the exit node.

## CLI reference

~~~text
Connection:
  -s, --server                    Listen for peers (auto-setup NAT on Linux)
  -c, --connect HOST:PORT         Connect to a peer
  -p, --port PORT                 Local UDP port; required for -s without --ip
  -k, --seed-key KEY              Shared seed for payload transformation

Framing:
      --lepv1                     Experimental LEP v1
      --raw                       Minimal 4-byte-index framing; requires -k

VPN:
      --ip IP                     VPN address; selects manual mode
      --mask MASK                 VPN subnet mask (default: 255.255.255.0)
      --gw GATEWAY                VPN gateway; non-empty means full IPv4 tunnel
      --forwarding MODE           hub (default) or route (per-peer IP routing)
      --tun-name NAME             Linux TUN device name; default: tun0
      --tap-guid GUID             Windows TAP adapter GUID; default: first TAP

Diagnostics:
  -v, --verbose                   Print packet events
  -w, --watchscreen               Show a live terminal dashboard
  -h, --help                      Show help
~~~

One of --server, --connect, or --ip is required. --raw is rejected unless -k
is non-empty. An option that takes a value exits with an error when the value
is missing; unrecognized options are ignored with a warning.

## Troubleshooting

**No peer appears**

- Confirm the listener's UDP port is allowed by the host firewall.
- Add router port-forwarding if the listener is behind NAT.
- Verify both sides use the same framing mode, key, and VPN subnet.
- Use -v to see packet events and retransmission activity.
- In routed mode, ensure every client has a unique VPN IP. Check route drop and
  conflict counters if a randomly selected automatic address collides.

**The client loses Internet access**

- The exit node must have IPv4 forwarding and NAT/masquerading.
- Automatic Linux setup is used only by -s without --ip.
- Windows server and all manual configurations need forwarding and NAT
  configured separately.
- In manual mode, ensure the peer endpoint has a physical-interface bypass
  route before enabling the VPN default routes.

**Windows cannot open the virtual adapter**

- Install TAP-Windows and run from an elevated terminal.
- Check that an adapter exists and, if necessary, give it an ASCII-only name.
- SAF-LEP selects the first matching TAP adapter unless `--tap-guid` is given.

**Android connects but no packets return**

- Confirm the server is a SAF-LEP peer listening on the configured UDP port.
- Match framing, seed, VPN address range, and gateway configuration.
- Check the Android status/log view and the desktop peer's -v output.
- Make sure the listening UDP port is reachable from the cellular or Wi-Fi
  network being tested.

## Security and protocol limitations

- The current cipher uses custom DJB2-like key derivation and a xorshift-based
  XOR stream. It has no accepted security proof.
- Packets have no cryptographic authentication or replay protection. LEP v1
  checks are not a substitute for a message authentication code.
- The raw packet index is intentionally visible on the wire.
- Reusing a seed, packet-index wraparound, or active packet modification can
  undermine confidentiality and integrity.
- IPv6 tunnelling is not implemented.
- Crash or forced termination may leave routes or firewall state that needs
  manual cleanup.

A production security design should replace the current transform with an
authenticated-encryption construction, use a real password KDF or negotiated
session keys, bind peer identity to authentication, prevent nonce reuse, and
include replay protection.
