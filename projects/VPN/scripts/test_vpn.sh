#!/usr/bin/env bash
# VPN Integration Test using Network Namespaces
# Requires root/sudo privileges

set -u

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

BUILD_DIR="./build"
SERVER_BIN="$BUILD_DIR/vpn_server"
CLIENT_BIN="$BUILD_DIR/vpn_client"
PSK_FILE="/tmp/avpn_test.psk"

S_NS="avpn_server_ns"
C_NS="avpn_client_ns"

VETH_S="veth_s"
VETH_C="veth_c"
BRIDGE_IP_S="192.168.55.1"
BRIDGE_IP_C="192.168.55.2"

VPN_TUN="tun99"

log() { echo -e "${GREEN}[TEST] $*${NC}"; }
error() { echo -e "${RED}[ERROR] $*${NC}"; }

cleanup() {
    log "Cleaning up..."
    pkill -f "$SERVER_BIN" || true
    pkill -f "$CLIENT_BIN" || true
    ip netns del "$S_NS" 2>/dev/null || true
    ip netns del "$C_NS" 2>/dev/null || true
    rm -f "$PSK_FILE"
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

if [[ ! -x "$SERVER_BIN" || ! -x "$CLIENT_BIN" ]]; then
    error "Binaries not found in $BUILD_DIR. Please build first."
    exit 1
fi

# Create PSK
log "Generating PSK..."
dd if=/dev/urandom of="$PSK_FILE" bs=32 count=1 status=none
export AVPN_PSK_FILE="$PSK_FILE"
export AVPN_TUN="$VPN_TUN"

# Setup Namespaces
log "Setting up namespaces..."
ip netns add "$S_NS"
ip netns add "$C_NS"

# Setup VETH pair
ip link add "$VETH_S" type veth peer name "$VETH_C"
ip link set "$VETH_S" netns "$S_NS"
ip link set "$VETH_C" netns "$C_NS"

# Configure IPs in namespaces
ip netns exec "$S_NS" ip addr add "$BRIDGE_IP_S/24" dev "$VETH_S"
ip netns exec "$S_NS" ip link set "$VETH_S" up
ip netns exec "$S_NS" ip link set lo up

ip netns exec "$C_NS" ip addr add "$BRIDGE_IP_C/24" dev "$VETH_C"
ip netns exec "$C_NS" ip link set "$VETH_C" up
ip netns exec "$C_NS" ip link set lo up

# Verify connectivity between namespaces
log "Verifying namespace connectivity..."
if ! ip netns exec "$C_NS" ping -c 1 -W 1 "$BRIDGE_IP_S" >/dev/null; then
    error "Namespaces cannot reach each other"
    exit 1
fi

# Start Server
log "Starting VPN Server..."
# We run server in background
ip netns exec "$S_NS" env AVPN_PSK_FILE="$PSK_FILE" AVPN_TUN="$VPN_TUN" "$SERVER_BIN" > /tmp/vpn_server.log 2>&1 &
SERVER_PID=$!
sleep 1

# Setup Server TUN (Manual needed essentially because server code relies on script or user, 
# but here server binary creates TUN, we just need to config IP if binary doesn't fully do it?
# The binary code says:
#   if (!ip addr show "$IF" ... )
# Wait, the C code DOES NOT configure IP! The existing SCRIPTS did that.
# So we need to manually configure IPs for the C binaries in this test environment.
# Actually, the C code just opens the TUN. It assumes external config for IP/Routes usually, 
# or maybe I missed it.
# Let's check:
#   projects/VPN/src/server/vpn_server.c -> Does NOT call 'ip addr add' via system().
#   It relies on the setup script.
#   So in this test, we must configure the TUN interface after the process starts and creates it.
#   However, tun_alloc with IFF_TUN | IFF_NO_PI usually creates it persistent or transient.
#   If transient, we need to config it while the process is running.

log "Configuring Server TUN..."
# Give it a moment to open TUN
sleep 1
if ! ip netns exec "$S_NS" ip link show "$VPN_TUN" >/dev/null; then
    error "Server TUN device not created"
    cat /tmp/vpn_server.log
    exit 1
fi
ip netns exec "$S_NS" ip addr add 10.8.0.1/24 dev "$VPN_TUN"
ip netns exec "$S_NS" ip link set "$VPN_TUN" up
ip netns exec "$S_NS" ip link set "$VPN_TUN" mtu 1400

# Start Client
log "Starting VPN Client..."
ip netns exec "$C_NS" env AVPN_PSK_FILE="$PSK_FILE" AVPN_TUN="$VPN_TUN" "$CLIENT_BIN" "$BRIDGE_IP_S" > /tmp/vpn_client.log 2>&1 &
CLIENT_PID=$!

# Configure Client TUN
log "Configuring Client TUN..."
sleep 2 # Wait for handshake
if ! ip netns exec "$C_NS" ip link show "$VPN_TUN" >/dev/null; then
    error "Client TUN device not created"
    cat /tmp/vpn_client.log
    exit 1
fi
# Note: Client gets IP via handshake protocol (ASSIGN msg), but C code doesn't apply it to interface.
# It prints: [info] Received ASSIGN: id=..., virt_ip=...
# So we must manually apply 10.8.0.2 for this test since our C client doesn't use netlink to set IP.
ip netns exec "$C_NS" ip addr add 10.8.0.2/24 dev "$VPN_TUN"
ip netns exec "$C_NS" ip link set "$VPN_TUN" up
ip netns exec "$C_NS" ip link set "$VPN_TUN" mtu 1400
ip netns exec "$C_NS" ip route add 10.8.0.0/24 dev "$VPN_TUN"

# Test VPN Connectivity
log "Ping from Client to Server (VPN IP)..."
if ip netns exec "$C_NS" ping -c 3 -W 1 10.8.0.1; then
    log "VPN Ping SUCCESS!"
    echo "PASS"
else
    error "VPN Ping FAILED"
    echo "Server Log:"
    cat /tmp/vpn_server.log
    echo "Client Log:"
    cat /tmp/vpn_client.log
    exit 1
fi
