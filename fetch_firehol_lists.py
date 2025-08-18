import pathlib
import ipaddress
import sys
import requests
import json
import textwrap

from pathlib import Path
from extract_domain import load_blacklist_ips
from typing import Set, Union
# 输出目录
OUT_DIR = pathlib.Path(__file__).resolve().parent / "fetch_firehol_lists"
OUT_DIR.mkdir(parents=True, exist_ok=True)
# ▶ 推荐使用的 IPv4 黑名单列表（FireHOL + abuse.ch）
LISTS_V4 = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "abuse_palevo": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/iblocklist_abuse_palevo.netset",
    "dshield": "https://feeds.dshield.org/block.txt",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "sslbl": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslbl.netset",
    # "Blocklist.de": "https://lists.blocklist.de/lists/strongips.txt",
    "zeus_badips": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/zeus_badips.netset",
    "bogons": "http://www.cidr-report.org/bogons/freespace-prefix.txt",
}

# ▶ 推荐使用的 IPv6 黑名单（Spamhaus DROP IPv6）
LISTS_V6 = {
    "spamhaus_drop_v6": "https://www.spamhaus.org/drop/drop_v6.json",
}

# ▶ 加入本地黑名单
blacklist_ips = load_blacklist_ips()
print(f"加载到 {len(blacklist_ips)} 个本地黑名单 IP")
LISTS_V4["local_blacklist"] = blacklist_ips


def fetch_list(url_or_ips: Union[str, Set[str]]) -> str:
    if isinstance(url_or_ips, set):
        return "\n".join(url_or_ips)
    elif url_or_ips.startswith("file://"):
        path = Path(url_or_ips[7:])
        return path.read_text()
    else:
        resp = requests.get(url_or_ips, timeout=20)
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
    """下载 IPv6 黑名单，兼容 JSON 数组、JSONL 和纯文本格式"""
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    cidrs = set()

    # 尝试解析整个 JSON 数组
    try:
        data = resp.json()
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and "cidr" in entry:
                    cidrs.add(entry["cidr"])
            if cidrs:
                return cidrs
    except Exception:
        pass

    # 回退：按行解析
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 尝试 JSON 对象
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "cidr" in obj:
                cidrs.add(obj["cidr"])
                continue
        except Exception:
            pass
        # 如果不是 JSON，就当作纯文本 CIDR
        cidrs.add(line)

    return cidrs

def collapse_cidrs(cidrs: Set[str], ip_version: int = 4) -> Set[str]:
    """去重并合并连续/包含关系的 CIDR"""
    network_objs = []
    for c in cidrs:
        try:
            if ip_version == 4:
                network_objs.append(ipaddress.IPv4Network(c, strict=False))
            else:
                network_objs.append(ipaddress.IPv6Network(c, strict=False))
        except ValueError:
            continue
    collapsed = ipaddress.collapse_addresses(network_objs)
    return {str(net) for net in collapsed}


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
    # cidrs_v4_sorted = sorted(cidrs_v4)
    cidrs_v4_collapsed = sorted(collapse_cidrs(cidrs_v4, ip_version=4))
    # IPv6 排序
    # cidrs_v6_sorted = sorted(cidrs_v6)
    cidrs_v6_collapsed = sorted(collapse_cidrs(cidrs_v6, ip_version=6))
    # 输出文件
    # (OUT_DIR / "blacklist_cidr_v4.txt").write_text("\n".join(cidrs_v4_sorted), encoding="utf-8")
    (OUT_DIR / "blacklist_cidr_v4.txt").write_text("\n".join(cidrs_v4_collapsed), encoding="utf-8")
    # (OUT_DIR / "blacklist_cidr_v6.txt").write_text("\n".join(cidrs_v6_sorted), encoding="utf-8")
    (OUT_DIR / "blacklist_cidr_v6.txt").write_text("\n".join(cidrs_v6_collapsed), encoding="utf-8")
   
    print(textwrap.dedent(f"""
        ✅ 黑名单提取完成！
        - IPv4 CIDR 段数量 : {len(cidrs_v4_collapsed):>6}
        - IPv6 CIDR 段数量 : {len(cidrs_v6_collapsed):>6}
        - 输出目录          : {OUT_DIR}
        - 输出文件：
            - blacklist_cidr_v4.txt
            - blacklist_cidr_v6.txt
    """))


if __name__ == "__main__":
    main()
