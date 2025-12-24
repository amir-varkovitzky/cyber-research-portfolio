# VPN Project

A robust, secure, and lightweight VPN implementation using Linux TUN/TAP interfaces and custom UDP protocol with AES-256-GCM encryption.

## Features

*   **Security**: Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM (OpenSSL).
*   **Replay Protection**: Sliding window mechanism to prevent replay attacks.
*   **Architecture**: Client-Server model.
*   **Network**: Uses `TUN` interface for Layer 3 tunneling.
*   **Robustness**: Handles packet loss, reordering, and graceful shutdowns.
*   **Scripts**: Helper scripts for easy network configuration and teardown.

## Directory Structure

*   `src/`: Source code.
    *   `client/`: VPN Client implementation.
    *   `server/`: VPN Server implementation.
    *   `common/`: Shared libraries (Crypto, Packet building, TUN/UDP utils).
*   `scripts/`: Helper bash scripts for setting up networking (IPs, NAT, routing).
*   `Makefile`: Build system.

## Prerequisites

*   Linux OS with TUN/TAP support.
*   `gcc`, `make`.
*   `OpenSSL` development libraries (`libssl-dev` or similar).

## Building

```bash
make all
```

This will produce `build/vpn_server` and `build/vpn_client`.

## Usage

### 1. Generate a Pre-Shared Key (PSK)

Both client and server must share a 32-byte secret key.

**On the Server:**
```bash
dd if=/dev/urandom of=vpn.psk bs=32 count=1
export AVPN_PSK_FILE=$(pwd)/vpn.psk
```

**On the Client:**
Securely copy `vpn.psk` from the server to the client.
```bash
export AVPN_PSK_FILE=$(pwd)/vpn.psk
```

### 2. Start the Server (Public IP: e.g., `1.2.3.4`)

```bash
# Set environment variables
export AVPN_TUN=tun0

# Start the server binary
./build/vpn_server

# In a separate terminal, configure the server network (IPs, NAT)
sudo ./scripts/server_net.sh --if tun0
```

### 3. Start the Client

```bash
# Set environment variables
export AVPN_TUN=tun0

# Start the client binary (replace 1.2.3.4 with Server's Real IP)
./build/vpn_client 1.2.3.4

# In a separate terminal, configure the client network
sudo ./scripts/client_net.sh --if tun0 --server 1.2.3.4
```

### 4. Teardown

To stop the VPN and clean up network interfaces/rules:

```bash
sudo ./scripts/teardown.sh --if tun0
```

## Testing

### Automated Integration Test (Local)
The project includes an integration test script that uses **Network Namespaces** to simulate a complete client-server network on a single machine without needing external VMs.

```bash
# Requires sudo to create namespaces
make test
```

### Manual Verification
After following the **Usage** steps above to connect a real client:

**From Client:**
```bash
# Ping the server's virtual IP
ping 10.8.0.1
```

## Security Notes

*   **Encryption**: Protocol uses AES-256-GCM.
*   **Authentication**: All packets are authenticated. Handshake uses a minimal exchange to assign virtual IPs.
*   **Privileges**: The binaries require `CAP_NET_ADMIN` (usually root) to open TUN devices.
