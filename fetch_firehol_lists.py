import pathlib
import ipaddress
import sys
import requests
import json
import textwrap
from typing import Set

# ▶ 推荐使用的 IPv4 黑名单列表（FireHOL + abuse.ch）
LISTS_V4 = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "abuse_palevo": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/iblocklist_abuse_palevo.netset",
    "dshield": "https://feeds.dshield.org/block.txt",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "sslbl": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslbl.netset",
    "zeus_badips": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/zeus_badips.netset",
    "bogons": "http://www.cidr-report.org/bogons/freespace-prefix.txt",
}

# ▶ 推荐使用的 IPv6 黑名单（Spamhaus DROP IPv6）
LISTS_V6 = {
    "spamhaus_drop_v6": "https://www.spamhaus.org/drop/drop_v6.json",
}

# 输出目录
OUT_DIR = pathlib.Path(__file__).resolve().parent / "fetch_firehol_lists"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def fetch_list(url: str) -> str:
    """下载名单文本，失败时抛异常"""
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    return resp.text


def parse_ipv4_lines(text: str) -> Set[str]:
    """解析 IPv4 列表，返回 CIDR 集合，支持单 IP、CIDR、起始-结束 IP"""
    cidrs = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 去掉 ; 后的注释
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        parts = line.split()
        # 起始-结束 IP
        if len(parts) >= 2:
            try:
                start_ip = ipaddress.IPv4Address(parts[0])
                end_ip = ipaddress.IPv4Address(parts[1])
                networks = ipaddress.summarize_address_range(start_ip, end_ip)
                cidrs.update(str(net) for net in networks)
                continue
            except ValueError:
                pass
        # CIDR
        try:
            net = ipaddress.IPv4Network(line, strict=False)
            cidrs.add(str(net))
            continue
        except ValueError:
            pass
        # 单 IP
        try:
            ip = ipaddress.IPv4Address(line)
            cidrs.add(f"{ip}/32")
        except ValueError:
            pass
    return cidrs


def fetch_ipv6_blacklist(url: str) -> Set[str]:
    """下载 IPv6 黑名单（Spamhaus DROP），返回 CIDR 集合，兼容两种 JSON 格式"""
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    cidrs = set()

    # 尝试解析整个 JSON 数组
    try:
        data = resp.json()
        if isinstance(data, list):
            for entry in data:
                if "cidr" in entry:
                    cidrs.add(entry["cidr"])
            return cidrs
    except Exception:
        pass

    # 回退：按行解析每行 JSON 对象
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
    cidrs_v4 = set()
    cidrs_v6 = set()

    # 下载并解析 IPv4 黑名单
    for name, url in LISTS_V4.items():
        sys.stdout.write(f"⬇  downloading IPv4 {name:20} ... ")
        sys.stdout.flush()
        try:
            text = fetch_list(url)
            parsed = parse_ipv4_lines(text)
            cidrs_v4.update(parsed)
            print(f"ok  (lines: {len(text.splitlines())}, CIDRs: {len(parsed)})")
        except Exception as e:
            print(f"failed → {e}")

    # 下载并解析 IPv6 黑名单
    for name, url in LISTS_V6.items():
        sys.stdout.write(f"⬇  downloading IPv6 {name:20} ... ")
        sys.stdout.flush()
        try:
            parsed = fetch_ipv6_blacklist(url)
            cidrs_v6.update(parsed)
            print(f"ok  (CIDRs: {len(parsed)})")
        except Exception as e:
            print(f"failed → {e}")

    # IPv4 排序和格式统一
    cidrs_v4_sorted = sorted(cidrs_v4)

    # IPv6 排序
    cidrs_v6_sorted = sorted(cidrs_v6)

    # 输出文件
    (OUT_DIR / "blacklist_cidr_v4.txt").write_text("\n".join(cidrs_v4_sorted), encoding="utf-8")
    (OUT_DIR / "blacklist_cidr_v6.txt").write_text("\n".join(cidrs_v6_sorted), encoding="utf-8")

    print(textwrap.dedent(f"""
        ✅ 黑名单提取完成！
        - IPv4 CIDR 段数量 : {len(cidrs_v4_sorted):>6}
        - IPv6 CIDR 段数量 : {len(cidrs_v6_sorted):>6}
        - 输出目录          : {OUT_DIR}
        - 输出文件：
            - blacklist_cidr_v4.txt
            - blacklist_cidr_v6.txt
    """))


if __name__ == "__main__":
    main()
