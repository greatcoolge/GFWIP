import re
import requests
from typing import Optional, Set, Tuple

BLACKLIST_SOURCES = {
    "emerging_urlhaus": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
    #"emerging_cyberhost": "https://lists.cyberhost.uk/malware.txt",
    "curbengh_phishing": "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
}

MAX_DOMAIN_LEN = 70
MIN_DOMAIN_LEN = 3

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
DOMAIN_RE = re.compile(r"^(?:[\w\-]+\.)+[a-z]{2,}$")

# 排除的域名后缀（比如垃圾顶级域）这次清空，避免误排
DEFAULT_EXCLUDE_SUFFIXES = set()

# 排除的特定域名或带通配符的域名（*仅支持一次，表示任意字符），这次清空
DEFAULT_EXCLUDE_DOMAINS = {
    "doubleclick.net", "googletagmanager.com", "google-analytics.com",
    "fbcdn.net", "cdn.discordapp.com", "tiktokcdn.com", "facebook.com",
    # 其他广告、统计域名
}

# 排除的国家级顶级域名（这次清空）
COUNTRY_CODE_TLDS = set()

# 新增关键字排除，过滤含有这些关键字的域名（用于广告、统计等）
EXCLUDE_KEYWORDS = {
    "ads", "analytics", "track", "stat", "pixel", "report", "log", "measure",
    "metrics", "click", "doubleclick", "tagmanager"
}

def match_domain_pattern(domain: str, pattern: str) -> bool:
    if "*" not in pattern:
        return domain == pattern or domain.endswith("." + pattern)
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, domain) is not None

def is_excluded_domain(domain: str,
                       exclude_suffixes: Set[str],
                       exclude_domains: Set[str],
                       exclude_cc_tlds: Set[str]) -> bool:
    if any(domain.endswith(suffix) for suffix in exclude_suffixes):
        return True
    for pattern in exclude_domains:
        if match_domain_pattern(domain, pattern):
            return True
    if any(domain.endswith(cc_tld) for cc_tld in exclude_cc_tlds):
        return True
    # 额外根据关键字排除
    for kw in EXCLUDE_KEYWORDS:
        if kw in domain:
            return True
    return False

def extract_domain_or_ip(
    line: str,
    exclude_suffixes: Set[str],
    exclude_domains: Set[str],
    exclude_cc_tlds: Set[str],
) -> Tuple[Optional[str], Optional[str]]:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("!"):
        return None, None
    entry = None
    # hosts 格式
    if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
        parts = line.split()
        if len(parts) >= 2:
            entry = parts[1].lower()
    # Adblock 格式 ||domain^，跳过带路径
    elif line.startswith("||"):
        content = line[2:]
        if "/" in content:
            return None, None
        entry = re.sub(r"[\^$].*", "", content).strip().lower()
    # 普通行（无路径，可能是域名或IP）
    elif "." in line and "/" not in line:
        entry = line.strip().lower()
    if not entry:
        return None, None
    # 排除判断
    if is_excluded_domain(entry, exclude_suffixes, exclude_domains, exclude_cc_tlds):
        return None, None
    if IPV4_RE.match(entry) or CIDR_RE.match(entry):
        return None, entry
    elif DOMAIN_RE.match(entry) and MIN_DOMAIN_LEN <= len(entry) <= MAX_DOMAIN_LEN:
        return entry, None
    return None, None

def fetch_entries(
    url: str,
    exclude_suffixes: Set[str],
    exclude_domains: Set[str],
    exclude_cc_tlds: Set[str],
) -> Tuple[Set[str], Set[str]]:
    print(f"Fetching {url} ...")
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        domains, ips = set(), set()
        for line in resp.text.splitlines():
            d, ip = extract_domain_or_ip(
                line, exclude_suffixes, exclude_domains, exclude_cc_tlds
            )
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
        domains, ips = fetch_entries(
            url, DEFAULT_EXCLUDE_SUFFIXES, DEFAULT_EXCLUDE_DOMAINS, COUNTRY_CODE_TLDS
        )
        print(f"Source {name} got {len(domains)} domains, {len(ips)} IPs")
        all_domains.update(domains)
        all_ips.update(ips)
    print(f"\n✅ Total collected:")
    print(f"- Domains: {len(all_domains)}")
    print(f"- IPs    : {len(all_ips)}")
    with open("extract_domain/blacklist_domains.txt", "w", encoding="utf-8") as f:
        for d in sorted(all_domains):
            f.write(d + "\n")
    with open("extract_domain/blacklist_adblock.txt", "w", encoding="utf-8") as f:
        for domain in sorted(all_domains):
            f.write(f"||{domain}^\n")
    
    with open("extract_domain/blacklist_ips.txt", "w", encoding="utf-8") as f:
        for ip in sorted(all_ips):
            f.write(ip + "\n")

if __name__ == "__main__":
    main()
