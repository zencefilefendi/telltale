#!/usr/bin/env bash
#
# TELLTALE — Zero-Trust Cellular Tunneling (Always-On VPN Generator)
#
# Since TELLTALE operates on the wire (network chokepoint), it goes blind when
# the target device switches from Wi-Fi to a Cellular (4G/5G) network. 
# 
# This script generates a WireGuard VPN configuration designed for "Always-On"
# deployment on iOS/Android. It forcibly routes all DNS and traffic metadata 
# back to your TELLTALE instance, eliminating the cellular blindspot.
#
# Note: For privacy, TELLTALE only inspects metadata. Your endpoint firewall 
# (iptables/ufw) should be configured to NAT the payloads directly to the internet
# while mirroring the headers (using tee or eBPF) to the TELLTALE sensor.

set -e

if ! command -v wg &> /dev/null; then
    echo "[-] Error: 'wireguard-tools' (wg) is not installed."
    echo "    Run: sudo apt install wireguard"
    exit 1
fi

ENDPOINT_IP=${1:-"203.0.113.50"} # Replace with your TELLTALE Server Public IP
ENDPOINT_PORT=${2:-"51820"}

echo "[*] Generating TELLTALE Zero-Trust WireGuard Keys..."

# Generate Server Keys
SERVER_PRIV=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)

# Generate Mobile Device Keys
CLIENT_PRIV=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)

# Create the Server Configuration
cat <<EOF > telltale-server.conf
# TELLTALE Sensor Gateway
[Interface]
PrivateKey = $SERVER_PRIV
Address = 10.99.99.1/24
ListenPort = $ENDPOINT_PORT

# Route forwarding & Metadata Mirroring
# This mirrors headers to the eBPF telltale-sensor while forwarding the payload
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# The Target Device
[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.99.99.2/32
EOF

# Create the Mobile Configuration
cat <<EOF > telltale-mobile.conf
# Target Device (iOS/Android)
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.99.99.2/24
DNS = 10.99.99.1, 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $ENDPOINT_IP:$ENDPOINT_PORT
# AllowedIPs = 0.0.0.0/0 forces ALL cellular traffic through the TELLTALE chokepoint
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

echo "[+] Success!"
echo "    1. Apply 'telltale-server.conf' on your Linux gateway (wg-quick up ./telltale-server.conf)"
echo "    2. Transfer 'telltale-mobile.conf' to the target's phone (Use WireGuard app -> Add from file/QR)"
echo ""
echo "    *Tip: Generate a QR code for the phone by running:*"
echo "      qrencode -t ansiutf8 < telltale-mobile.conf"
