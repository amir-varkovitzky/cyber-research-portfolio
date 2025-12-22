import socket


def load_wordlist(file_path: str) -> list[str]:
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def enumerate_dns(base_domain: str, wordlist: list[str]) -> None:
    """
    Enumerates DNS records for a given base domain using a wordlist.
    """
    found = {}

    for word in wordlist:
        subdomain = f"{word}.{base_domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            if ip not in found:
                found[ip] = []
            found[ip].append(subdomain)
            print(f"[+] {subdomain} -> {ip}")
        except socket.gaierror:
            pass  # silently ignore unresolved

    print("\n== Unique IPs ==")
    for ip, subs in found.items():
        print(f"{ip}: {', '.join(subs)}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python dns_enum.py <base_domain> <wordlist_file>")
        sys.exit(1)

    base_domain = sys.argv[1]
    wordlist_file = sys.argv[2]
    wordlist = load_wordlist(wordlist_file)

    enumerate_dns(base_domain, wordlist)
