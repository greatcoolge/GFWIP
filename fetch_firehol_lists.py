import pathlib
import re
import ipaddress
import sys
import requests
import textwrap
from typing import Set

# ▶ 推荐使用的 IPv4 黑名单列表（FireHOL + abuse.ch 推荐）
LISTS_V4 = {
    "firehol_level1":    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus_drop":     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
    #"compromised-ips":   "http://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    #"dshield":           "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
    "feodo":             "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.netset",
    "sslbl":             "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslbl.netset",
    #"zeus_badips":       "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/zeus_badips.netset",
    #"firehol_webclient": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset",
}

# ▶ 推荐使用的 IPv6 黑名单（Spamhaus DROP IPv6）
LISTS_V6 = {
    "spamhaus_drop_v6": "https://www.spamhaus.org/drop/drop_v6.json",
}

OUT_DIR = pathlib.Path(__file__).resolve().parent  # 输出目录=脚本同级

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

def fetch_list(url: str) -> str:
    """下载名单文本，失败时抛异常"""
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    return resp.text

def parse_ipv4_lines(text: str, ips: set, cidrs: set) -> None:
    """按行解析 IPv4 列表，填充 ips / cidrs，校验合法性"""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        # 尝试先解析为CIDR
        try:
            net = ipaddress.IPv4Network(line, strict=False)
            cidrs.add(str(net))
            continue
        except ValueError:
            pass

        # 尝试解析为单个IP
        try:
            ip = ipaddress.IPv4Address(line)
            ips.add(str(ip))
            continue
        except ValueError:
            pass

        # 不合法则跳过
        # print(f"Invalid IPv4 or CIDR ignored: {line}")

def fetch_ipv6_blacklist(url: str) -> Set[str]:
    import json
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    cidrs = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if "cidr" in obj:
                cidrs.add(obj["cidr"])
        except Exception as e:
            print(f"[WARN] IPv6 blacklist line parse error: {e}")
    return cidrs

def main() -> None:
    ips_v4, cidrs_v4 = set(), set()
    cidrs_v6 = set()

    # 下载并解析 IPv4 黑名单
    for name, url in LISTS_V4.items():
        sys.stdout.write(f"⬇  downloading IPv4 {name:20} ... ")
        try:
            text = fetch_list(url)
            parse_ipv4_lines(text, ips_v4, cidrs_v4)
            print(f"ok  (lines: {len(text.splitlines())})")
        except Exception as e:
            print(f"failed → {e}")

    # 下载并解析 IPv6 黑名单
    for name, url in LISTS_V6.items():
        sys.stdout.write(f"⬇  downloading IPv6 {name:20} ... ")
        try:
            cidrs = fetch_ipv6_blacklist(url)
            cidrs_v6.update(cidrs)
            print(f"ok  (CIDRs: {len(cidrs)})")
        except Exception as e:
            print(f"failed → {e}")

    # IPv4 排序和格式统一
    cidrs_v4_sorted = sorted(cidrs_v4)
    ips_v4_sorted = sorted(ips_v4)
    all_plain_v4 = cidrs_v4_sorted + ips_v4_sorted
    cidr_unified_v4 = cidrs_v4_sorted + sorted(f"{ip}/32" for ip in ips_v4_sorted)

    # IPv6 排序
    cidrs_v6_sorted = sorted(cidrs_v6)

    # 写入文件
    (OUT_DIR / "cidrs_v4.txt").write_text("\n".join(cidrs_v4_sorted), encoding="utf-8")
    (OUT_DIR / "ips_v4.txt").write_text("\n".join(ips_v4_sorted), encoding="utf-8")
    (OUT_DIR / "all_blacklist_v4.txt").write_text("\n".join(all_plain_v4), encoding="utf-8")
    (OUT_DIR / "blacklist_cidr_v4.txt").write_text("\n".join(cidr_unified_v4), encoding="utf-8")

    (OUT_DIR / "blacklist_cidr_v6.txt").write_text("\n".join(cidrs_v6_sorted), encoding="utf-8")

    print(textwrap.dedent(f"""
        ✅ 黑名单提取完成！
        - IPv4 CIDR 段数量    : {len(cidrs_v4):>6}
        - IPv4 单 IP 数量      : {len(ips_v4):>6}
        - IPv4 合并统一 CIDR   : {len(cidr_unified_v4):>6}
        - IPv6 CIDR 段数量    : {len(cidrs_v6):>6}
        - 输出目录            : {OUT_DIR}
        - 输出文件：
            - cidrs_v4.txt
            - ips_v4.txt
            - all_blacklist_v4.txt
            - blacklist_cidr_v4.txt
            - blacklist_cidr_v6.txt
        """))

if __name__ == "__main__":
    main()
