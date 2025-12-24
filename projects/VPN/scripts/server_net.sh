#!/usr/bin/env bash
# Robust VPN server network setup script
# Usage: server_net.sh [--if <tun>] [--pub-if <iface>] [--ip <ip>] [--net <net>] [--mtu <mtu>]
set -euo pipefail

# Get absolute path to script directory
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  echo "Usage: $0 [--if <tun>] [--pub-if <iface>] [--ip <ip>] [--net <net>] [--mtu <mtu>]"
  echo "  --if <tun>      TUN device name (default: tun0)"
  echo "  --pub-if <iface> Public interface for NAT (default: eth0)"
  echo "  --ip <ip>       VPN server IP (default: 10.8.0.1/24)"
  echo "  --net <net>     VPN subnet (default: 10.8.0.0/24)"
  echo "  --mtu <mtu>     MTU for TUN (default: 1400)"
  exit 1
}

IF="tun0"
VPN_NET="10.8.0.0/24"
VPN_IP="10.8.0.1/24"
PUB_IF="eth0"
MTU="1400"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --if) IF="$2"; shift 2;;
    --pub-if) PUB_IF="$2"; shift 2;;
    --ip) VPN_IP="$2"; shift 2;;
    --net) VPN_NET="$2"; shift 2;;
    --mtu) MTU="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown option: $1"; usage;;
  esac
done

check_deps ip iptables

log "Setting up $IF as $VPN_IP, NAT via $PUB_IF, subnet $VPN_NET, MTU $MTU"

ensure_tun "$IF"
ensure_ip "$IF" "$VPN_IP"
set_mtu_up "$IF" "$MTU"

sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
log "Enabled IPv4 forwarding"

if ! sudo iptables -t nat -C POSTROUTING -s "$VPN_NET" -o "$PUB_IF" -j MASQUERADE 2>/dev/null; then
  if sudo iptables -t nat -A POSTROUTING -s "$VPN_NET" -o "$PUB_IF" -j MASQUERADE; then
      log "Added NAT MASQUERADE rule for $VPN_NET via $PUB_IF"
  else
      log "Error: Failed to add NAT rule"
      exit 1
  fi
else
  log "NAT MASQUERADE rule already exists"
fi

log "Setup complete: $IF up as $VPN_IP, NAT via $PUB_IF"