# Cyber Research Portfolio

This repository showcases system programming projects, C2 frameworks, and network security tools.

It demonstrates proficiency in low-level C programming, operating system internals, network security, and Python network automation.

## 📂 Projects

Major implementations demonstrating core concepts in operating systems and networking.

- **[C2 Framework](projects/C2_Framework)**: A production-ready Command & Control framework supporting ICMP and DNS tunneling.
- **[VPN](projects/VPN)**: A custom VPN implementation demonstrating secure network tunneling and encryption.
- **[Memory Allocators](projects/MemoryAllocators)**: Custom Fixed-Size (FSA) and Variable-Size (VSA) memory allocators optimizing for fragmentation and performance.
- **[Ext2 Filesystem Parser](projects/Ext2Parser)**: A user-space tool to parse and navigate Ext2 filesystem images directly.
- **[Simple Shell](projects/SimpleShell)**: A custom Unix shell with process management and signal handling.


## 🛠️ Security Tools

Advanced utilities for network reconnaissance and packet manipulation.

### Network
- **[Advanced ARP Spoofer Project](tools/network/arp_spoofer_nfqueue)**: Modular MITM framework using NFQUEUE. Features plugin support for DNS Spoofing (including DoH/DoT bypass) and HTTP Hijacking.
- **[Manual ARP Spoofer](tools/network/arp_spoofer_mnl_fwd.py)**: Userspace forwarding tool demonstrating raw packet manipulation (TTL, Checksum) and fragmentation.
- **[Subnet Scanner](tools/network/subnet_scanner.py)**: Horizontal scanner to identify active hosts on a subnet for a specific port.
- **[Port Scanner](tools/network/port_scanner.py)**: Vertical scanner to enumerate open ports on a single target.
- **[DNS Enumerator](tools/network/dns_enumeration.py)**: Subdomain discovery utility.

### Misc
- **[Brute Force](tools/misc)**: brute-forcing performance analysis.

---

## About
This portfolio represents a focus on understanding systems from the bottom up; From manual memory management and raw network packets to kernel interfaces and distributed systems.
