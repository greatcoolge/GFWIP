import pathlib, re, sys, requests, textwrap
from typing import Set

# ▶ 你可以按需增减列表
LISTS = {
    # 名称             GitHub RAW 地址
    "firehol_level1":     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
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
        # spamhaus_drop 类：CIDR 在首字段，后跟 ';'
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        if CIDR_RE.match(line):
            cidrs.add(line)
        elif IP_RE.match(line):
            ips.add(line)
        # 其余格式忽略

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

    # 输出文件
    (OUT_DIR / "cidrs.txt").write_text("\n".join(sorted(cidrs)), encoding="utf-8")
    (OUT_DIR / "ips.txt").write_text("\n".join(sorted(ips)),   encoding="utf-8")
    (OUT_DIR / "all_blacklist.txt").write_text(
        "\n".join(sorted(cidrs) + sorted(ips)), encoding="utf-8"
    )

    print(textwrap.dedent(f"""
        ✅ 完成！
        CIDR 段  : {len(cidrs):>8}
        单 IP    : {len(ips):>8}
        保存路径 : {OUT_DIR}
        """))

if __name__ == "__main__":
    main()
