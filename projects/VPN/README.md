
# C99 VPN (TUN + UDP + AES‑256‑GCM) — Secure, Modular, and Easy to Deploy

This project is a NASA-style, from-scratch VPN in **C99** using Linux **TUN** (Layer‑3) and **UDP** transport, with **AES‑256‑GCM** (OpenSSL EVP) for authenticated encryption. The code is modular, robust, and easy to deploy, with strict security and code quality standards.

---

## Quickstart: Secure Deployment

### 1. Install Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev iproute2 iptables tcpdump iputils-ping
```

### 2. Build & Install

```bash
make lint
make
sudo make install
```

### 3. Generate Keys

```bash
mkdir -p keys
head -c 32 /dev/urandom > keys/psk.bin
export AVPN_PSK_FILE=$(pwd)/keys/psk.bin
```

### 4. Server Network Setup

```bash
./scripts/server_net.sh --if tun0 --pub-if eth0 --ip 10.8.0.1/24 --net 10.8.0.0/24 --mtu 1400
```

### 5. Client Network Setup

```bash
./scripts/client_net.sh --if tun0 --ip 10.8.0.2 --mtu 1400 --net 10.8.0.0/24 --server 10.8.0.1
```

### 6. Start the VPN Binaries

#### On server

```bash
export AVPN_PSK_FILE=$(pwd)/keys/psk.bin
sudo vpn_server
```

#### On client

```bash
export AVPN_PSK_FILE=$(pwd)/keys/psk.bin
sudo vpn_client <SERVER_PUBLIC_IP>
```

### 7. Test Connectivity

On client:

```bash
ping -c 3 10.8.0.1
```

On server:

```bash
ping -c 3 10.8.0.2
```

### 8. Verify Encryption

```bash
tcpdump -ni any udp port 51820 -vv
```

### 9. Teardown & Cleanup

```bash
./scripts/teardown.sh --if tun0 --pub-if eth0 --net 10.8.0.0/24
```

---

## Folder Structure

```text
VPN/
├─ README.md
├─ Makefile
├─ scripts/
│  ├─ server_net.sh
│  ├─ client_net.sh
│  └─ teardown.sh
├─ keys/
│  └─ psk.bin        (32 bytes, random; .gitignore this)
└─ src/
   ├─ common/
   │  ├─ proto.h
   │  ├─ packet.h
   │  ├─ packet.c
   │  ├─ tun.h
   │  ├─ tun.c
   │  ├─ udp.h
   │  ├─ udp.c
   │  ├─ aead.h
   │  ├─ aead_openssl.c
   │  ├─ util.h
   │  └─ util.c
   ├─ server/
   │  └─ vpn_server.c
   └─ client/
      └─ vpn_client.c
```

---

## Security & Deployment Notes

- **OS:** Ubuntu 20.04+ (root required for TUN and iptables).
- **Crypto:** AES‑256‑GCM, 12‑byte nonce, 16‑byte tag, PSK (32‑byte). Nonce counters reset on process restart; always rekey at startup.
- **Threat Model:** Integrity/confidentiality on-path; replay defense (64‑pkt window). No DoS/ratelimiting, no cert PKI.
- **Production:** Harden with DoS limits, session persistence, logging, and tests.

---

## Performance & Troubleshooting

- **MTU:** Default is 1400. If you see fragmentation, try `ip link set tun0 mtu 1380` on both sides.
- **Throughput:** Use `iperf3` for performance testing.
- **Troubleshooting:**
   - PSK mismatch: Both sides must use the same `keys/psk.bin`.
   - TUN not present: `ip addr show tun0`.
   - Forwarding off: `sysctl net.ipv4.ip_forward`.
   - NAT missing: `iptables -t nat -L -v | grep MASQUERADE`.
   - Firewall: Ensure UDP 51820 is open.
   - Wrong server IP: Use public IP.
   - MTU issues: Lower to 1380.
   - Packet path: `tcpdump -ni any -vv udp port 51820`.

## Design Recap

- **Data plane:** TUN ↔ (encrypt/decrypt) ↔ UDP
- **Control plane:** HELLO → ASSIGN_IP; replay window; per-client counters
- **Security:** AES‑256‑GCM with header as AAD; per-direction nonce counters
- **Routing/NAT:** Linux tooling; minimal userspace logic

## FAQ

**Q:** Why UDP?
**A:** Avoids TCP-over-TCP meltdown; simpler NAT traversal.

**Q:** Why AES-GCM?
**A:** OpenSSL EVP AES-GCM is widely available and secure.

**Q:** Multiple clients?
**A:** Yes; server supports up to 64 clients by default.

**Q:** Production ready?
**A:** Harden with handshake, identities/keys, rekeying, DoS limits, session persistence, logging, and tests.
