#!/usr/bin/env bash
# Common functions for VPN network setup scripts

# Function to log messages with the script name
log() {
    local script_name
    script_name=$(basename "$0" .sh)
    echo "[$script_name] $*"
}

# Function to check for required dependencies
check_deps() {
    local missing=0
    for cmd in "$@"; do
        if ! command -v "$cmd" &>/dev/null; then
            log "Error: Missing required command '$cmd'"
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        exit 2
    fi
}

# Function to create a TUN device if it doesn't exist
ensure_tun() {
    local iface="$1"
    if ! ip link show "$iface" &>/dev/null; then
        if sudo ip tuntap add dev "$iface" mode tun; then
            log "Created TUN device $iface"
        else
            log "Error: Failed to create TUN device $iface"
            exit 1
        fi
    fi
}

# Function to assign an IP address if not already assigned
ensure_ip() {
    local iface="$1"
    local ip_addr="$2"
    # Check if IP is already assigned (ignoring CIDR for grep to be safe, but ideally check exact)
    # Extract just the IP part for grep
    local ip_only="${ip_addr%%/*}"
    
    if ! ip addr show "$iface" | grep -q "$ip_only"; then
        if sudo ip addr add "$ip_addr" dev "$iface"; then
            log "Assigned IP $ip_addr to $iface"
        else
            log "Error: Failed to assign IP $ip_addr to $iface"
            exit 1
        fi
    fi
}

# Function to set interface UP and MTU
set_mtu_up() {
    local iface="$1"
    local mtu="$2"
    
    if sudo ip link set "$iface" up && sudo ip link set "$iface" mtu "$mtu"; then
        log "Set $iface up with MTU $mtu"
    else
        log "Error: Failed to set $iface up or set MTU"
        exit 1
    fi
}

# Function to remove TUN device
remove_tun() {
    local iface="$1"
    if ip link show "$iface" &>/dev/null; then
        if sudo ip link del "$iface"; then
            log "Deleted TUN device $iface"
        else
            log "Error: Failed to delete TUN device $iface"
        fi
    else
        log "No TUN device $iface to delete"
    fi
}
