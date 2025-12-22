#!/usr/bin/env bash
# Robust VPN teardown script
# Usage: teardown.sh [--if <tun>] [--pub-if <iface>] [--net <net>]
set -euo pipefail

usage() {
  echo "Usage: $0 [--if <tun>] [--pub-if <iface>] [--net <net>]"
  echo "  --if <tun>      TUN device name (default: tun0)"
  echo "  --pub-if <iface> Public interface for NAT (default: eth0)"
  echo "  --net <net>     VPN subnet (default: 10.8.0.0/24)"
  exit 1
}

IF="tun0"
VPN_NET="10.8.0.0/24"
PUB_IF="eth0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --if) IF="$2"; shift 2;;
    --pub-if) PUB_IF="$2"; shift 2;;
    --net) VPN_NET="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown option: $1"; usage;;
  esac
done

log() { echo "[teardown] $*"; }

if ! command -v ip &>/dev/null; then log "Missing 'ip' command"; exit 2; fi
if ! command -v iptables &>/dev/null; then log "Missing 'iptables' command"; exit 2; fi

if sudo iptables -t nat -C POSTROUTING -s "$VPN_NET" -o "$PUB_IF" -j MASQUERADE 2>/dev/null; then
  sudo iptables -t nat -D POSTROUTING -s "$VPN_NET" -o "$PUB_IF" -j MASQUERADE
  log "Removed NAT MASQUERADE rule for $VPN_NET via $PUB_IF"
else
  log "No NAT MASQUERADE rule to remove"
fi

if ip link show "$IF" &>/dev/null; then
  sudo ip link del "$IF"
  log "Deleted TUN device $IF"
else
  log "No TUN device $IF to delete"
fi

log "Teardown complete."