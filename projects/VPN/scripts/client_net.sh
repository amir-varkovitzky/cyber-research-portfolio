#!/usr/bin/env bash
# Robust VPN client network setup script
# Usage: client_net.sh [--if <tun>] [--ip <virt_ip>] [--mtu <mtu>] [--net <net>] [--server <server_ip>]
set -euo pipefail

usage() {
	echo "Usage: $0 [--if <tun>] [--ip <virt_ip>] [--mtu <mtu>] [--net <net>] [--server <server_ip>]"
	echo "  --if <tun>      TUN device name (default: tun0)"
	echo "  --ip <virt_ip>  Virtual IP for client (default: 10.8.0.2)"
	echo "  --mtu <mtu>     MTU for TUN (default: 1400)"
	echo "  --net <net>     VPN subnet (default: 10.8.0.0/24)"
	echo "  --server <ip>   Server TUN IP (default: 10.8.0.1)"
	exit 1
}

IF="tun0"
VIP="10.8.0.2"
MTU="1400"
VPN_NET="10.8.0.0/24"
SERVER="10.8.0.1"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--if) IF="$2"; shift 2;;
		--ip) VIP="$2"; shift 2;;
		--mtu) MTU="$2"; shift 2;;
		--net) VPN_NET="$2"; shift 2;;
		--server) SERVER="$2"; shift 2;;
		-h|--help) usage;;
		*) echo "Unknown option: $1"; usage;;
	esac
done

log() { echo "[client_net] $*"; }

if ! command -v ip &>/dev/null; then log "Missing 'ip' command"; exit 2; fi

log "Setting up $IF as $VIP/24, subnet $VPN_NET, MTU $MTU, server $SERVER"

if ! ip link show "$IF" &>/dev/null; then
	sudo ip tuntap add dev "$IF" mode tun
	log "Created TUN device $IF"
fi

if ! ip addr show "$IF" | grep -q "${VIP}"; then
	sudo ip addr add "$VIP/24" dev "$IF"
	log "Assigned IP $VIP/24 to $IF"
fi

sudo ip link set "$IF" up
sudo ip link set "$IF" mtu "$MTU"
log "Set $IF up and MTU $MTU"

if ! ip route show | grep -q "$VPN_NET"; then
	sudo ip route add "$VPN_NET" dev "$IF"
	log "Added route for $VPN_NET via $IF"
fi

# Optional full-tunnel routes via server
# sudo ip route add 0.0.0.0/1 via $SERVER dev $IF
# sudo ip route add 128.0.0.0/1 via $SERVER dev $IF

log "Setup complete: $IF up as $VIP/24"