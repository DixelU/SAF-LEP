# SAF-LEP

SAF-LEP is a project aiming to provide a low-entropy protocol 
for "secure" `af` connection indistinguishable from some common UDP data by means of `Deep Packet Inspection`.

# Protocol

Low entropy data is embedded into the lower bits of each byte of the data packet.

Yada-yada ...

Description will be there once the protocol gets kinda-stable and/or embeded into custom
VPN software.

# Usage Instructions 

## Prerequisites (Server side)
The server must allow IP forwarding and NAT for the VPN to provide internet access.

- Enable IP forwarding
  ```bash
  sudo sysctl -w net.ipv4.ip_forward=1
  ```

- Enable NAT (Masquerade)
  ```bash
  sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  ```

- Allow VPN traffic forwarding
  ```bash
  sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
  sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
  ```

- Running the Server
  ```bash
  sudo ./build_linux/SAF-LEP -p 14578 --ip 10.0.0.1
  ```

## Running the Client side
  - **Important**: To avoid a routing loop, add a specific route to the server's public IP via your local gateway before starting the VPN.

- Replace <GATEWAY_IP> with your local router IP (e.g., 192.168.1.1)
  ```bash
  sudo ip route add <SERVER_PUBLIC_IP> via <GATEWAY_IP>
  ```

- Then start the client, pointing to the server's public IP and setting the gateway to the VPN server's virtual IP:
  ```bash
  sudo ./build_linux/SAF-LEP -c <SERVER_PUBLIC_IP>:14578 --ip 10.0.0.2 --gw 10.0.0.1
  ```

- Verification
  Ping: ping 10.0.0.1 (from client)
  Internet: curl google.com or traceroute google.com (should show hops through the VPN)