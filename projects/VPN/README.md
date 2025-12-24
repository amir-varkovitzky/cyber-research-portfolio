# VPN Project

A robust, secure, and lightweight VPN implementation using Linux TUN/TAP interfaces and custom UDP protocol with AES-256-GCM encryption.

## Features

*   **Security**: Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM (OpenSSL).
*   **Replay Protection**: Sliding window mechanism to prevent replay attacks.
*   **Architecture**: Client-Server model.
*   **Network**: Uses `TUN` interface for Layer 3 tunneling.
*   **Robustness**: Handles packet loss, reordering, and graceful shutdowns.
*   **Scripts**: Helper scripts for easy network configuration and teardown.

## Key Design Insights

### 1. The TCP Meltdown Problem (Why UDP?)
This VPN uses **UDP** for the transport layer. Tunneling IP over TCP (TCP-over-TCP) is widely considered a bad practice due to "TCP Meltdown".
*   **Packet Loss**: If the outer TCP connection loses a packet, it retransmits.
*   **Latency Spike**: The inner TCP connection sees this delay and assumes congestion, backing off its transmission window.
*   **Result**: Performance collapses exponentially. UDP prevents this by allowing the inner TCP sessions to handle their own congestion control naturally.

### 2. TUN vs TAP (Layer 3 vs Layer 2)
We utilize **TUN (Layer 3)** interfaces instead of TAP (Layer 2).
*   **Efficiency**: TUN devices carry only IP packets, stripping unnecessary Ethernet headers (MAC addresses).
*   **Scalability**: Avoids the "chatter" of ARP broadcasts and other Layer 2 noise, making it more efficient for point-to-point VPN links unless legacy non-IP protocols (like IPX) are needed.

### 3. Authenticated Encryption (AEAD)
The protocol strictly uses **AES-256-GCM**.
*   **Integrity + Confidentiality**: Traditional encryption (CBC) only hides data. AEAD ensures that if an attacker modifies even a single bit of the encrypted ciphertext, the packet is rejected instantly (Tag Mismatch).
*   **Security**: This prevents padding oracle attacks and ensures no chosen-ciphertext attacks can tamper with the tunnel command stream.

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
