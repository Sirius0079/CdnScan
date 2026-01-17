import argparse
import socket
import re
from collections import Counter
from openpyxl import Workbook

# ======================
# IP 校验
# ======================

def is_valid_ip(ip):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip)

# ======================
# ASN 关键词库（强化）
# ======================

CDN_KEYWORDS = ["cloudflare", "fastly", "akamai"]
CLOUD_KEYWORDS = ["google", "amazon", "aws", "alibaba", "azure", "tencent"]
LOCAL_IDC_KEYWORDS = [
    "terasys", "idnic", "datacenter", "hosting",
    "vps", "nap", "server", "virtual"
]
LOCAL_ISP_KEYWORDS = [
    "linknet", "telkom", "indosat", "biznet",
    "xl axiata", "moratel", "cbn"
]

# ======================
# ASN 分类
# ======================

def classify_asn(org):
    o = org.lower()
    if any(k in o for k in CDN_KEYWORDS):
        return "CDN", "P0"
    if any(k in o for k in CLOUD_KEYWORDS):
        return "Cloud", "P1"
    if any(k in o for k in LOCAL_IDC_KEYWORDS):
        return "Local IDC", "P3"
    if any(k in o for k in LOCAL_ISP_KEYWORDS):
        return "Local ISP", "P3"
    return "Enterprise / Unknown", "P3"

# ======================
# Team Cymru ASN 查询
# ======================

def cymru_lookup(ip_list):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.cymru.com", 43))
    query = "begin\nverbose\n" + "\n".join(ip_list) + "\nend\n"
    s.sendall(query.encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()

    result = {}
    for line in data.decode(errors="ignore").splitlines():
        if "|" not in line or line.startswith("AS"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7:
            asn, ip, *_ , org = parts
            result[ip] = (asn, org)
    return result

# ======================
# 主程序
# ======================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", required=True)
    args = parser.parse_args()

    raw_lines = open(args.f, encoding="utf-8", errors="ignore").read().splitlines()

    ip_list = []
    invalid_lines = []

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        if is_valid_ip(line):
            ip_list.append(line)
        else:
            invalid_lines.append(line)

    print(f"[+] Loaded {len(ip_list)} valid IPs")
    print(f"[!] Ignored {len(invalid_lines)} invalid lines")

    asn_data = cymru_lookup(ip_list)
    ip_count = Counter(ip_list)

    wb = Workbook()
    ws = wb.active
    ws.append([
        "IP", "ASN", "Org", "ASN Type",
        "Origin Score", "Conclusion"
    ])

    # ===== 关键改动：先收集结果 =====
    rows = []

    for ip in ip_list:
        if ip not in asn_data:
            continue

        asn, org = asn_data[ip]
        asn_type, _ = classify_asn(org)

        score = 0
        if asn_type in ["Local IDC", "Enterprise / Unknown"]:
            score += 40
        if asn_type == "Local ISP":
            score += 30
        if ip_count[ip] > 1:
            score += 30

        if score >= 70:
            conclusion = "🔥 极可能真实源站"
        elif score >= 40:
            conclusion = "⚠️ 可能真实源站"
        else:
            conclusion = "❌ 低概率"

        print(f"""
[*] {ip}
    ├─ ASN        : {asn}
    ├─ Org        : {org}
    ├─ Type       : {asn_type}
    ├─ Score      : {score}
    └─ Result     : {conclusion}
""")

        rows.append([ip, asn, org, asn_type, score, conclusion])

    # ===== 关键改动：按 Score 排序再写表格 =====
    rows.sort(key=lambda x: x[4], reverse=True)

    for row in rows:
        ws.append(row)

    wb.save("origin_score.xlsx")
    print("[+] Saved origin_score.xlsx")

if __name__ == "__main__":
    main()
