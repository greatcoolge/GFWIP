import re
import requests
from typing import Optional


BLACKLIST_SOURCES = {
    "emerging_threats": "https://hosts.tweedge.net/malicious.txt",
    "emerging_cyberhost": "https://lists.cyberhost.uk/malware.txt",
    "curbengh_phishing": "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
    # 可继续添加
}

MAX_DOMAIN_LEN = 70
MIN_DOMAIN_LEN = 3

def clean_rule_line(line: str) -> Optional[str]:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("!"):
        return None

    domain = None

    # hosts格式
    if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].lower()

    # Adblock规则 ||domain^ 或 ||domain/path^$all
    elif line.startswith("||"):
        domain = re.sub(r"[\^/$].*$", "", line[2:]).lower()

    # 其他普通域名行
    elif "." in line and "/" not in line:
        domain = line.lower()

    # 检查有效性和长度
    if domain and "." in domain:
        if MIN_DOMAIN_LEN <= len(domain) <= MAX_DOMAIN_LEN:
            return domain

    return None

def fetch_and_extract_domains(url: str) -> set:
    print(f"Fetching {url} ...")
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        domains = set()
        for line in lines:
            d = clean_rule_line(line)
            if d:
                domains.add(d)
        return domains
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return set()

def main():
    all_domains = set()
    for name, url in BLACKLIST_SOURCES.items():
        domains = fetch_and_extract_domains(url)
        print(f"Source {name} got {len(domains)} domains")
        all_domains.update(domains)

    print(f"\nTotal unique domains collected: {len(all_domains)}\n")

    # 输出到文件
    with open("merged_blacklist_domains.txt", "w", encoding="utf-8") as f:
        for d in sorted(all_domains):
            f.write(d + "\n")

if __name__ == "__main__":
    main()
