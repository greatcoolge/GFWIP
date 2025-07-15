import pathlib, re, sys, requests, textwrap
from typing import Set

# ▶ 推荐使用的黑名单（FireHOL + abuse.ch 推荐）
LISTS = {
    #"firehol_level1":     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus_drop":      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",
    "dshield":            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",
    "feodo":              "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.netset",
    "sslbl":              "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslbl.netset",
    "zeus_badips":        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/zeus_badips.netset",
    "firehol_webclient":  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset",
}

OUT_DIR = pathlib.Path(__file__).resolve().parent  # 输出目录=脚本同级

IP_RE   = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

def fetch_list(url: str) -> str:
    """下载名单文本，失败时抛异常"""
    resp = requests.get(url, timeout=20)
    resp.raise_for_status()
    return resp.text

def parse_lines(text: str, ips: Set[str], cidrs: Set[str]) -> None:
    """按行解析，填充至 ips / cidrs"""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        if CIDR_RE.match(line):
            cidrs.add(line)
        elif IP_RE.match(line):
            ips.add(line)

def main() -> None:
    ips, cidrs = set(), set()

    for name, url in LISTS.items():
        sys.stdout.write(f"⬇  downloading {name:20} ... ")
        try:
            text = fetch_list(url)
            parse_lines(text, ips, cidrs)
            print(f"ok  (lines: {len(text.splitlines())})")
        except Exception as e:
            print(f"failed → {e}")

    # 排序和统一格式
    cidrs_sorted = sorted(cidrs)
    ips_sorted = sorted(ips)
    all_plain = cidrs_sorted + ips_sorted
    cidr_unified = cidrs_sorted + sorted(f"{ip}/32" for ip in ips_sorted)

    # 写入文件
    (OUT_DIR / "cidrs.txt").write_text("\n".join(cidrs_sorted), encoding="utf-8")
    (OUT_DIR / "ips.txt").write_text("\n".join(ips_sorted), encoding="utf-8")
    (OUT_DIR / "all_blacklist.txt").write_text("\n".join(all_plain), encoding="utf-8")
    (OUT_DIR / "blacklist_cidr.txt").write_text("\n".join(cidr_unified), encoding="utf-8")

    print(textwrap.dedent(f"""
        ✅ 黑名单提取完成！
        - CIDR 段数量    : {len(cidrs):>6}
        - 单 IP 数量      : {len(ips):>6}
        - 合并统一 CIDR   : {len(cidr_unified):>6}
        - 输出目录        : {OUT_DIR}
        - 输出文件：
            - cidrs.txt
            - ips.txt
            - all_blacklist.txt
            - blacklist_cidr.txt
        """))

if __name__ == "__main__":
    main()
