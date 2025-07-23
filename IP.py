import requests
from bs4 import BeautifulSoup
import re

url = "https://zh.wikiversity.org/wiki/%E9%98%B2%E7%81%AB%E9%95%BF%E5%9F%8E%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93IP%E5%88%97%E8%A1%A8"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

try:
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
except requests.RequestException as e:
    print("❌ 网络请求失败:", e)
    exit(1)

soup = BeautifulSoup(response.text, "html.parser")
pre_tags = soup.find_all("pre")
if not pre_tags:
    print("❌ 没有找到任何 <pre> 标签，可能网页结构变化。")
    exit(1)

ip4_list = []
ip6_list = []

def is_valid_ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def is_valid_ipv6(ip):
    if ip.count("::") > 1:
        return False
    parts = ip.split(":")
    if len(parts) > 8:
        return False
    for part in parts:
        if part == "":
            continue
        if len(part) > 4:
            return False
        if not all(c in "0123456789abcdefABCDEF" for c in part):
            return False
    return True

ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

ipv6_pattern = re.compile(r"""
    \b
    (?:                                     
      (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}         
      |                                   
      (?:[0-9a-fA-F]{1,4}:){1,7}:                 
      |                                   
      (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}           
      |                                   
      ::                                  
    )
    \b
""", re.VERBOSE)

for pre in pre_tags:
    text = pre.text
    ip4s = ipv4_pattern.findall(text)
    ip4_list.extend(filter(is_valid_ipv4, ip4s))
    ip6s = ipv6_pattern.findall(text)
    ip6_list.extend(filter(is_valid_ipv6, ip6s))

ip4_list = sorted(set(ip4_list))
ip6_list = sorted(set(ip6_list))

with open("IP/ip4_list.txt", "w") as f4:
    for ip in ip4_list:
        f4.write(ip + "\n")

with open("IP/ip6_list.txt", "w") as f6:
    for ip in ip6_list:
        f6.write(ip + "\n")

print(f"✅ IPv4 共提取 {len(ip4_list)} 个，已保存到 IP/ip4_list.txt")
print(f"✅ IPv6 共提取 {len(ip6_list)} 个，已保存到 IP/ip6_list.txt")
