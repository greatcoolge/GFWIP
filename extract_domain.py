BLACKLIST_SOURCES = {
    "emerging_threats": "https://hosts.tweedge.net/malicious.txt",
    "emerging_cyberhost": "https://lists.cyberhost.uk/malware.txt",
    "curbengh_phishing": "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
}

MAX_DOMAIN_LEN = 70
MIN_DOMAIN_LEN = 3

# 正则定义
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
DOMAIN_RE = re.compile(r"^(?:[\w\-]+\.)+[a-z]{2,}$")


def extract_domain_or_ip(line: str) -> tuple[Optional[str], Optional[str]]:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("!"):
        return None, None

    entry = None

    # 1. hosts 格式
    if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
        parts = line.split()
        if len(parts) >= 2:
            entry = parts[1].lower()

    # 2. Adblock ||domain^，跳过带路径
    elif line.startswith("||"):
        content = line[2:]
        if "/" in content:
            return None, None
        entry = re.sub(r"[\^$].*", "", content).strip().lower()

    # 3. 普通行
    elif "." in line and "/" not in line:
        entry = line.strip().lower()

    # 类型判断
    if not entry:
        return None, None

    if IPV4_RE.match(entry) or CIDR_RE.match(entry):
        return None, entry
    elif DOMAIN_RE.match(entry) and MIN_DOMAIN_LEN <= len(entry) <= MAX_DOMAIN_LEN:
        return entry, None

    return None, None


def fetch_entries(url: str) -> tuple[set[str], set[str]]:
    print(f"Fetching {url} ...")
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        domains, ips = set(), set()
        for line in resp.text.splitlines():
            d, ip = extract_domain_or_ip(line)
            if d:
                domains.add(d)
            if ip:
                ips.add(ip)
        return domains, ips
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return set(), set()


def main():
    all_domains, all_ips = set(), set()
    for name, url in BLACKLIST_SOURCES.items():
        domains, ips = fetch_entries(url)
        print(f"Source {name} got {len(domains)} domains, {len(ips)} IPs")
        all_domains.update(domains)
        all_ips.update(ips)

    print(f"\n✅ Total collected:")
    print(f"- Domains: {len(all_domains)}")
    print(f"- IPs    : {len(all_ips)}")

    with open("blacklist_domains.txt", "w", encoding="utf-8") as f:
        for d in sorted(all_domains):
            f.write(d + "\n")

    with open("blacklist_ips.txt", "w", encoding="utf-8") as f:
        for ip in sorted(all_ips):
            f.write(ip + "\n")


if __name__ == "__main__":
    main()
