import re
import requests
from typing import Optional

# 黑名单来源
BLACKLIST_SOURCES = {
    "emerging_threats": "https://hosts.tweedge.net/malicious.txt",
    "emerging_cyberhost": "https://lists.cyberhost.uk/malware.txt",
    "curbengh_phishing": "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
}

# 设置域名长度限制
MAX_DOMAIN_LEN = 70
MIN_DOMAIN_LEN = 3

# 正则表达式
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
DOMAIN_RE = re.compile(r"^(?:[\w\-]+\.)+[a-z]{2,}$")

# 可选：短链、CDN类域名黑名单（不提取）
SHORTEN_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "1drv.ms", "we.tl"
}

CDN_DOMAINS = {
    "dropbox.com", "mega.nz", "mediafire.com", "weebly.com", "webflow.io",
    "webcindario.com", "godaddysites.com", "myqcloud.com"
}


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

    # 2. Adblock 格式 ||domain^，但跳过带路径的
    elif line.startswith("||"):
        content = line[2:]
        if "/" in content:
            return None, None
        entry = re.sub(r"[\^$].*", "", content).strip().lower()

    # 3. 普通域名/IP 行
    elif "." in line and "/" not in line:
        entry = line.strip().lower()

    # 空值或非法内容
    if not entry:
        return None, None

    # 跳过短链/CDN 域名
    if any(entry.endswith(bad) for bad in SHORTEN_DOMAINS | CDN_DOMAINS):
        return None, None

    # 判断是 IP 还是域名
    if IPV4_RE.match(entry) or CIDR_RE.match(entry):
        return None, entry

    elif DOMAIN_RE.match(entry) and MIN_DOMAIN_LEN <= len(entry) <= MAX_DOMAIN_LEN:
        return entry, None

    return None, None


def fetch_entries(url: str) -> tuple[set[str], set[str]]:
    print(f"📥 Fetching {url} ...")

    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()

        domains = set()
        ips = set()

        for line in resp.text.splitlines():
            domain, ip = extract_domain_or_ip(line)
            if domain:
                domains.add(domain)
            if ip:
                ips.add(ip)

        return domains, ips

    except Exception as e:
        print(f"⚠️  Error fetching {url}: {e}")
        return set(), set()


def main():
    all_domains = set()
    all_ips = set()

    for name, url in BLACKLIST_SOURCES.items():
        domains, ips = fetch_entries(url)
        print(f"✅ Source {name}: {len(domains)} domains, {len(ips)} IPs")
        all_domains.update(domains)
        all_ips.update(ips)

    print(f"\n📊 Total unique collected:")
    print(f"- Domains: {len(all_domains)}")
    print(f"- IPs    : {len(all_ips)}")

    with open("blacklist_domains.txt", "w", encoding="utf-8") as f:
        for domain in sorted(all_domains):
            f.write(domain + "\n")

    with open("blacklist_ips.txt", "w", encoding="utf-8") as f:
        for ip in sorted(all_ips):
            f.write(ip + "\n")


if __name__ == "__main__":
    main()
