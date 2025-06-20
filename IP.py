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

# 更稳健地查找 <pre> 标签
pre_tags = soup.find_all("pre")
if not pre_tags:
    print("❌ 没有找到任何 <pre> 标签，可能网页结构变化。")
    exit(1)

# 提取所有符合 IPv4 格式的字符串
ip_list = []
for pre in pre_tags:
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", pre.text)
    ip_list.extend(ips)

# 去重、过滤非法 IP
def is_valid_ipv4(ip):
    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)

ip_list = sorted(set(filter(is_valid_ipv4, ip_list)))

if not ip_list:
    print("⚠️ 没有找到合法 IP 地址")
else:
    with open("ip_list.txt", "w") as file:
        for ip in ip_list:
            file.write(ip + "\n")
    print(f"✅ 共提取并写入 {len(ip_list)} 个合法 IP 到 ip_list.txt 文件中！")
