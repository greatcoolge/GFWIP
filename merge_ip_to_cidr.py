import ipaddress

# 读取原始 IP 列表
with open("IP/ip4_list.txt", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

# 写入未合并（全是 /32）版本
with open("IP/ip4_cidr.txt", "w") as f_raw:
    for ip in lines:
        f_raw.write(ip + "/32\n")

# 转为 IPv4Network 对象（每个 IP 都当成 /32）
networks = [ipaddress.IPv4Network(ip + "/32") for ip in lines]

# 使用 collapse 合并相邻网段
merged = ipaddress.collapse_addresses(networks)

# 写入合并后版本
with open("gfw_ip_list.txt", "w") as f_merge:
    for net in merged:
        f_merge.write(str(net) + "\n")
