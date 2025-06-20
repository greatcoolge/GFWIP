import ipaddress

with open("ip4_list.txt", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

# 添加 /32 后变为 IP 网络对象
ip_networks = [ipaddress.ip_network(ip + "/32") for ip in lines]

# 合并成最小 CIDR 块（自动归并连续 IP）
merged = ipaddress.collapse_addresses(ip_networks)

with open("gfw_ip_list.txt", "w") as f:
    for net in merged:
        f.write(str(net) + "\n")
