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
DEFAULT_EXCLUDE_SUFFIXES = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".fit", ".cfd", ".shop",
    ".review", ".zip", ".monster", ".cam", ".club", ".cyou",
    ".onion", ".bit", ".bazar", ".black", ".red",
    ".work", ".party", ".science", ".trade", ".loan", ".date", ".win",
    ".pw", ".icu", ".site", ".online", ".store", ".live",
    ".support", ".software", ".download", ".space", ".host",
    ".sex", ".adult", ".xxx", ".porn",
    ".fun", ".buzz", ".lol", ".app", ".dev", ".page"
}

# 排除的特定域名或带通配符的域名（*仅支持一次，表示任意字符）
DEFAULT_EXCLUDE_DOMAINS = {
    "cloudflare.com",
    "akamai.net",
    "googleusercontent.com",
    "googleapis.com",
    "gvt1.com",
    "gvt2.com",
    "fastly.net",
    "cloudfront.net",
    "netflix.net",
    "windowsupdate.com",
    "microsoft.com",
    "bing.com",
    "amazonaws.com",
    "fbcdn.net",
    "facebook.com",
    "tiktokcdn.com",
    "doubleclick.net",
    "doubleclick.*",           # 保留通配符形式
    "edgecastcdn.net",
    "cdninstagram.com",
    "cdn.discordapp.com",
    "discord.gg",
    "msedge.net",
    "googletagmanager.com",
    "analytics.*",             # 保留通配符形式
    "*.google.com",            # 保留通配符形式
    "*.googleusercontent.com" # 保留通配符形式
}
# 排除的国家级顶级域名（可再细化）
COUNTRY_CODE_TLDS = {
    ".ac", ".ad", ".ae", ".af", ".ag", ".ai", ".al", ".am", ".ao", ".aq",
    ".ar", ".as", ".at", ".au", ".aw", ".ax", ".az", ".ba", ".bb", ".bd",
    ".be", ".bf", ".bg", ".bh", ".bi", ".bj", ".bm", ".bn", ".bo", ".br",
    ".bs", ".bt", ".bv", ".bw", ".by", ".bz", ".ca", ".cc", ".cd", ".cf",
    ".cg", ".ch", ".ci", ".ck", ".cl", ".cm", ".cn", ".co", ".cr", ".cu",
    ".cv", ".cw", ".cx", ".cy", ".cz", ".de", ".dj", ".dk", ".dm", ".do",
    ".dz", ".ec", ".ee", ".eg", ".er", ".es", ".et", ".eu", ".fi", ".fj",
    ".fk", ".fm", ".fo", ".fr", ".ga", ".gb", ".gd", ".ge", ".gf", ".gg",
    ".gh", ".gi", ".gl", ".gm", ".gn", ".gp", ".gq", ".gr", ".gs", ".gt",
    ".gu", ".gw", ".gy", ".hk", ".hm", ".hn", ".hr", ".ht", ".hu", ".id",
    ".ie", ".il", ".im", ".in", ".io", ".iq", ".ir", ".is", ".it", ".je",
    ".jm", ".jo", ".jp", ".ke", ".kg", ".kh", ".ki", ".km", ".kn", ".kp",
    ".kr", ".kw", ".ky", ".kz", ".la", ".lb", ".lc", ".li", ".lk", ".lr",
    ".ls", ".lt", ".lu", ".lv", ".ly", ".ma", ".mc", ".md", ".me", ".mf",
    ".mg", ".mh", ".mk", ".ml", ".mm", ".mn", ".mo", ".mp", ".mq", ".mr",
    ".ms", ".mt", ".mu", ".mv", ".mw", ".mx", ".my", ".mz", ".na", ".nc",
    ".ne", ".nf", ".ng", ".ni", ".nl", ".no", ".np", ".nr", ".nu", ".nz",
    ".om", ".pa", ".pe", ".pf", ".pg", ".ph", ".pk", ".pl", ".pm", ".pn",
    ".pr", ".ps", ".pt", ".pw", ".py", ".qa", ".re", ".ro", ".rs", ".ru",
    ".rw", ".sa", ".sb", ".sc", ".sd", ".se", ".sg", ".sh", ".si", ".sj",
    ".sk", ".sl", ".sm", ".sn", ".so", ".sr", ".ss", ".st", ".su", ".sv",
    ".sx", ".sy", ".sz", ".tc", ".td", ".tf", ".tg", ".th", ".tj", ".tk",
    ".tl", ".tm", ".tn", ".to", ".tr", ".tt", ".tv", ".tz", ".ua", ".ug",
    ".uk", ".us", ".uy", ".uz", ".va", ".vc", ".ve", ".vg", ".vi", ".vn",
    ".vu", ".wf", ".ws", ".ye", ".yt", ".za", ".zm", ".zw"
}


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


if __name__ == "__main__":
    main()
