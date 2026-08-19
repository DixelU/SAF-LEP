# SAF-LEP

SAF-LEP is an experimental IPv4 VPN that moves packets from a virtual network
interface through either a direct UDP peer or a MAX-assisted ICE connection.
It runs as a desktop CLI on Windows and Linux, and as an Android VPN client for
the direct UDP transport.

The repository includes:

- a cross-platform C++ tunnel core;
- Windows TAP and Linux TUN adapters;
- a direct UDP transport with fragmentation, loss detection, and retransmission;
- a desktop MaxTunnel transport backed by the adjacent SAF-AVTTS repository;
- an Android VpnService application for direct UDP connections;
- LEP v0, LEP v1, and low-overhead raw packet framing.

> [!WARNING]
> SAF-LEP is a research/proof-of-concept project. Its current seed-key cipher is
> custom, unauthenticated, and not cryptographically secure. Do not rely on it
> for privacy, integrity, identity authentication, or sensitive traffic. Raw
> mode requires a key to prevent accidental plaintext operation, but that
> requirement does not turn the current cipher into production-grade encryption.

## Current support

| Platform | Direct UDP | MaxTunnel | Virtual interface | Intended role |
| --- | --- | --- | --- | --- |
| Linux desktop | Yes | Yes | TUN | Client, peer, or exit node |
| Windows desktop | Yes | Yes | TAP-Windows | Client or manually configured peer |
| Android | Yes | No | Android VpnService/TUN | Client |
| macOS / iOS | No | No | - | Not implemented |

Important boundaries:

- **MaxTunnel is currently desktop-only.** Android does not build or link
  SAF-AVTTS and has no MAX authentication, call, or wait UI.
- **Automatic exit-node setup is Linux-only.** Windows can run the transport,
  but server-side forwarding/NAT must be configured outside SAF-LEP.
- The MaxTunnel datagram path only interoperates with another custom client
  using SAF-AVTTS. It does not exchange VPN data with the stock MAX app.

## Transport and framing choices

Transport and packet framing are independent choices. Both peers must use the
same framing mode and the same seed key.

### Transports

**Direct UDP**

- available on Windows, Linux, and Android;
- listens on or connects to a UDP host and port;
- includes SAF-LEP's acknowledgement, loss-detection, and retransmission logic;
- may require a public UDP port, firewall rule, or router port-forward on the
  listening side.

**MaxTunnel**

- available on Windows and Linux desktop builds;
- uses MAX for account authentication and call signaling, then carries opaque
  datagrams through the ICE path provided by SAF-AVTTS;
- supports direct, STUN-assisted, and relayed connectivity as selected by ICE;
- automatically reconnects after a dropped call;
- normally needs a different MAX account and token at each endpoint.

### Framing modes

| CLI option | Mode | Wire behaviour | Notes |
| --- | --- | --- | --- |
| none | LEP v0 | Low-entropy expansion | Default and most compatible |
| --lepv1 | LEP v1 | Experimental LEP framing with integrity checks | Both peers must opt in |
| --raw | Raw | 4-byte big-endian packet index followed by the encrypted fragment body | Requires -k |

Raw mode exists for transports that already preserve datagram boundaries. It
does not apply LEP's byte expansion. The cleartext packet index selects the
per-packet cipher stream; the fragment body, including SAF-LEP's fragmentation
metadata, is transformed before framing.

For MaxTunnel, raw mode also increases the fragment payload from 150 to 1200
bytes. A typical 1500-byte VPN packet therefore needs two MaxTunnel datagrams
instead of ten, before ICE/TURN and network-layer overhead. Direct UDP keeps its
150-byte fragments because its reliability protocol is tuned around that size.

For cellular MaxTunnel use, the intended pairing is therefore:

~~~text
MaxTunnel + --raw + a non-empty -k seed
~~~

## Prerequisites

### Repository layout

The desktop build integrates the maxcalls library with a relative path, so the
two repositories must be siblings:

~~~text
parent/
|-- SAF-AVTTS/
+-- SAF-LEP/
~~~

SAF-AVTTS is required even when you only plan to use direct UDP because it is
currently part of the desktop build graph.

### Windows desktop

- a 64-bit C++23 toolchain;
- CMake 3.22 or newer, or Visual Studio 2022 for the included solution;
- Boost.System;
- SAF-AVTTS dependencies: Boost.Beast/JSON/UUID, OpenSSL, LZ4, and libjuice;
- a TAP-Windows adapter;
- an elevated terminal when creating routes or configuring the adapter.

The included Visual Studio project uses the first TAP-Windows adapter it finds.
Adapter names currently need to be representable by the narrow-character
netsh command path; rename the adapter to an ASCII-only name if setup fails.

### Linux desktop

- a C++23 compiler and CMake 3.22 or newer;
- Boost.System and the SAF-AVTTS dependencies;
- /dev/net/tun, iproute2, and iptables;
- root privileges or equivalent capabilities for TUN and route changes.

See the SAF-AVTTS README for its complete dependency list and platform notes.

### Android

The Android application requires Android SDK Platform 36, Build Tools 36,
NDK 27.0.12077973, CMake 3.22.1, and JDK 17 or newer. It builds arm64-v8a and
x86_64 variants and supports Android API 24 or newer.

See [android/README.md](android/README.md) for SDK setup, Boost header handling,
command-line builds, installation, and the UI walkthrough.

## Building

### Linux with CMake

After installing the SAF-LEP and SAF-AVTTS dependencies and placing the
repositories side by side:

~~~bash
cd SAF-LEP
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
~~~

The executable is normally written to build/SAF-LEP.

### Windows with Visual Studio

First build the sibling SAF-AVTTS repository so that maxcalls.lib exists:

~~~powershell
cd ..\SAF-AVTTS
cmake --preset vcpkg-x64-static
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cd ..\SAF-LEP
~~~

Adjust SAF-AVTTS/CMakePresets.json if vcpkg is installed somewhere other than
the preset's toolchain path. Then open SAF-LEP-ExPuN.sln and build x64 Release.

The solution expects:

- Release maxcalls.lib in ..\SAF-AVTTS\build;
- Debug maxcalls.lib in ..\SAF-AVTTS\build-debug.

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

## Quick start: direct UDP

The defaults use VPN subnet 10.0.0.0/24, with 10.0.0.1 on the listening side.
A direct-UDP automatic client chooses a random host address from 10.0.0.2
through 10.0.0.254 and prints the choice at startup.

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
retains the legacy behavior. Automatically configured direct-UDP clients already
use randomized addresses. In manual mode, give every client a distinct `--ip`
value in the server's VPN subnet.

Add the same framing flag at both ends when changing the default. For example:

~~~bash
sudo ./build/SAF-LEP -s -p 14578 --raw -k "shared seed"
sudo ./build/SAF-LEP -c vpn.example.net:14578 --raw -k "shared seed"
~~~

Press Ctrl+C for a clean route and firewall teardown.

## Quick start: MaxTunnel

MaxTunnel is available only in the Windows and Linux desktop CLI.

The commands below use the Linux executable path. On Windows, use an elevated
terminal, replace ./build/SAF-LEP with .\SAF-LEP-ExPuN.exe, and omit sudo.

### 1. Bootstrap each MAX account

QR bootstrap is recommended:

~~~bash
./build/SAF-LEP --max-qr-bootstrap
~~~

Open or scan the printed link with the official MAX app and complete 2FA if
requested. The command prints a login token. Treat this token as a secret and
store a separate token at each endpoint.

SMS bootstrap is also available:

~~~bash
./build/SAF-LEP --max-bootstrap +79991234567
~~~

If the SMS path encounters CAPTCHA, the CLI falls back to QR bootstrap.

### 2. Provide the token

Linux:

~~~bash
export MAXCALLS_TOKEN="endpoint login token"
~~~

PowerShell:

~~~powershell
$env:MAXCALLS_TOKEN = "endpoint login token"
~~~

You can alternatively pass --max-token TOKEN on the command line, although
environment variables avoid placing the token directly in shell history.

### 3. Start the waiting endpoint

~~~bash
sudo ./build/SAF-LEP --max-wait --raw -k "shared seed"
~~~

After authentication, SAF-LEP prints the endpoint's external MAX user ID. Give
that ID to the caller.

### 4. Call it from the other endpoint

~~~bash
sudo ./build/SAF-LEP --max-call PEER_EXTERNAL_ID --raw -k "shared seed"
~~~

The caller defaults to VPN address 10.0.0.2/24 with gateway 10.0.0.1, so it
installs full-tunnel routes. SAF-LEP pins MAX, ICE, DNS, and relay transport
traffic to the physical uplink: source-policy routing on Linux and dynamic /32
bypass routes on Windows.

The waiting endpoint defaults to 10.0.0.1/24 without a VPN gateway. Unlike the
direct UDP -s mode, --max-wait does **not** automatically enable forwarding or
NAT. If it is meant to act as an Internet exit node, configure OS forwarding,
firewall rules, and masquerading/NAT on that machine separately.

### Running direct UDP and MaxTunnel as separate services

A server can keep an ordinary UDP tunnel and an emergency MaxTunnel endpoint
running as two independent SAF-LEP processes. Each process must own a different
TUN/TAP adapter and a different VPN subnet. On Linux, for example:

~~~bash
# Ordinary UDP service on 192.44.0.0/24.
sudo ./build/SAF-LEP -s -p 14578 --tun-name safudp0 \
  --ip 192.44.0.1 --mask 255.255.255.0 -k "udp seed"

# Emergency MAX service on 192.45.0.0/24.
sudo ./build/SAF-LEP --max-wait --raw --tun-name safmax0 \
  --ip 192.45.0.1 --mask 255.255.255.0 -k "max seed"
~~~

Supplying `--ip` deliberately keeps both processes in legacy/manual networking
mode. Configure IPv4 forwarding, firewall policy, and NAT persistently outside
SAF-LEP for both `safudp0` and `safmax0`. Do not run two automatic server
setups and rely on each process to own shared MASQUERADE or MSS-clamping rules:
stopping either process could remove rules still needed by the other.

The corresponding client configurations are:

~~~bash
# Normal path. Run one full-tunnel client at a time.
sudo ./build/SAF-LEP -c vpn.example.net:14578 \
  --ip 192.44.0.4 --mask 255.255.255.0 --gw 192.44.0.1 -k "udp seed"

# Emergency path when MAX infrastructure is reachable but ordinary UDP is not.
sudo ./build/SAF-LEP --max-call PEER_EXTERNAL_ID --raw \
  --ip 192.45.0.4 --mask 255.255.255.0 --gw 192.45.0.1 -k "max seed"
~~~

Stop the active full-tunnel client before starting the other one so their `/1`
default-route overrides do not compete. Switching between these independent
VPN subnets is a reconnect and does not preserve existing TCP sessions.

On Windows, install two TAP-Windows adapters and pass each process the desired
adapter's interface GUID with `--tap-guid`. Windows server forwarding and NAT
remain manually administered.

## Android client

The Android application is a direct-UDP client. In the UI, configure:

- server hostname or IPv4 address and UDP port;
- LEP v0, LEP v1, or raw framing;
- the same seed key used by the desktop peer;
- VPN address, prefix length, and optional gateway;
- optional verbose logging.

Raw framing cannot connect without a non-empty seed key. Leaving the gateway
empty routes only the configured VPN subnet; setting a gateway requests the
full IPv4 tunnel routes.

Android protects the transport socket with VpnService.protect(), so its own UDP
connection bypasses the VPN. It does not currently support MAX bootstrap,
MaxTunnel call/wait modes, or acting as an exit node.

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

In manual full-tunnel mode, you are responsible for keeping the direct UDP or
MaxTunnel transport endpoints reachable through the physical interface and for
configuring forwarding/NAT at the exit node.

## CLI reference

~~~text
Connection:
  -s, --server                    Listen for a direct UDP peer
  -c, --connect HOST:PORT         Connect to a direct UDP peer
  -p, --port PORT                 UDP listen port
  -k, --seed-key KEY             Shared seed for payload transformation

Framing:
      --lepv1                     Experimental LEP v1
      --raw                       Minimal 4-byte-index framing; requires -k

VPN:
      --ip IP                     VPN address; selects manual mode
      --mask MASK                 VPN subnet mask
      --gw GATEWAY                VPN gateway; non-empty means full IPv4 tunnel
      --forwarding MODE           hub (default) or route (per-peer IP routing)
      --tun-name NAME             Linux TUN device name; default: tun0
      --tap-guid GUID             Windows TAP adapter GUID; default: first TAP

MaxTunnel (desktop only):
      --max-qr-bootstrap          Bootstrap a MAX token using a QR link
      --max-bootstrap PHONE       Bootstrap using SMS, with QR fallback
      --max-token TOKEN           Use TOKEN instead of MAXCALLS_TOKEN
      --max-call PEER_ID          Call a MAX external user ID
      --max-wait                  Wait for an incoming custom call

Diagnostics:
  -v, --verbose                   Print packet events
  -w, --watchscreen               Show a live terminal dashboard
  -h, --help                      Show help
~~~

Direct UDP requires one of --server or --connect. MaxTunnel requires
--max-call or --max-wait; choose only one role per process. --raw is rejected
unless -k is non-empty.

## Troubleshooting

**No direct UDP peer appears**

- Confirm the listener's UDP port is allowed by the host firewall.
- Add router port-forwarding if the listener is behind NAT.
- Verify both sides use the same framing mode, key, and VPN subnet.
- Use -v to see packet events and retransmission activity.
- In routed mode, ensure every client has a unique VPN IP. Check route drop and
  conflict counters if a randomly selected automatic address collides.

**MaxTunnel authenticates but cannot carry traffic**

- Verify that each endpoint uses a valid token for its intended MAX account and
  that the caller has the correct external user ID.
- Check that both peers use the same framing mode and key.
- Ensure the physical uplink still has working DNS and Internet connectivity.
- On a full-tunnel caller, look for maxcalls transport-policy or bypass-route
  messages during startup.
- SAF-AVTTS may log a benign ICE role conflict while its tiebreaker resolves it.

**The client loses Internet access**

- The exit node must have IPv4 forwarding and NAT/masquerading.
- Automatic Linux setup is used only by direct UDP -s without --ip.
- MaxTunnel wait mode and all Windows server/manual configurations need
  forwarding and NAT configured separately.
- In manual mode, ensure the transport endpoint has a physical-interface bypass
  route before enabling the VPN default routes.

**Windows cannot open the virtual adapter**

- Install TAP-Windows and run from an elevated terminal.
- Check that an adapter exists and, if necessary, give it an ASCII-only name.
- SAF-LEP selects the first matching TAP adapter unless `--tap-guid` is given.

**Android connects but no packets return**

- Confirm the server is a direct UDP SAF-LEP peer; Android cannot call a
  MaxTunnel endpoint.
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
- SAF-AVTTS does not add DTLS or SRTP to the ICE datagram path.
- IPv6 tunnelling is not implemented.
- Crash or forced termination may leave routes or firewall state that needs
  manual cleanup.

A production security design should replace the current transform with an
authenticated-encryption construction, use a real password KDF or negotiated
session keys, bind peer identity to authentication, prevent nonce reuse, and
include replay protection.
