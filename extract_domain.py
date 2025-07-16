import re
import requests
from typing import Optional, Set, Tuple

BLACKLIST_SOURCES = {
    "emerging_threats": "https://hosts.tweedge.net/malicious.txt",
    "emerging_cyberhost": "https://lists.cyberhost.uk/malware.txt",
    "curbengh_phishing": "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt",
}

MAX_DOMAIN_LEN = 70
MIN_DOMAIN_LEN = 3

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
DOMAIN_RE = re.compile(r"^(?:[\w\-]+\.)+[a-z]{2,}$")

# 排除的域名后缀（比如垃圾顶级域）
DEFAULT_EXCLUDE_SUFFIXES = {}

# 排除的特定域名或带通配符的域名（*仅支持一次，表示任意字符）
DEFAULT_EXCLUDE_DOMAINS = {
    # Google 广告与统计
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com",
    "google-analytics.com",
    "gstatic.com",

    # Facebook & Meta
    "facebook.com",
    "fbcdn.net",
    "connect.facebook.net",
    "facebook.net",

    # Microsoft & LinkedIn
    "msedge.net",
    "bing.com",
    "clarity.ms",
    "licdn.com",

    # Twitter/X
    "twitter.com",
    "t.co",

    # TikTok
    "tiktokcdn.com",

    # Cloudflare Analytics
    "cloudflareinsights.com",

    # Sentry - 错误收集
    "sentry.io",

    # Discord CDN（表情图像等）
    "cdn.discordapp.com",

    # Instagram 图片
    "cdninstagram.com",

    # JS 库 CDN
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",

    # Firebase
    "firebaseio.com",
    "firebaseapp.com",

    # 其他广告域名
    "scorecardresearch.com",
    "criteo.com",
    "adnxs.com",
    "adsafeprotected.com",
    "zedo.com",
    "quantserve.com",
    "adform.net",
    "adroll.com",
    "tapad.com",
    "trustarc.com",
    "moatads.com",
    "contextweb.com",
    "casalemedia.com",
    "openx.net",
    "bluekai.com",
    "rubiconproject.com",
    "mathtag.com",
    "yieldmo.com",
    "media.net",
    "advertising.com",
    "adservice.google.com",
}
# 排除的国家级顶级域名（可再细化）
COUNTRY_CODE_TLDS = {}


def match_domain_pattern(domain: str, pattern: str) -> bool:
    """
    简单通配符匹配，pattern 允许一个 *，代表任意字符
    例：
      analytics.* 匹配 analytics.com, analytics.co.uk
      *.example.com 匹配 www.example.com, abc.example.com
    """
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
            url, DEFAULT_EXCLUDE_SUFFIXES, DEFAULT_EXCLUDE_DOMAINS, DEFAULT_EXCLUDE_CC_TLDS
        )
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

DEFAULT_EXCLUDE_CC_TLDS = COUNTRY_CODE_TLDS  # <- 加这句绑定别名
if __name__ == "__main__":
    main()
