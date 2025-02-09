import os
import re
import random
import ipaddress
import subprocess
import concurrent.futures

import requests
from lxml import etree
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import geoip2.database

# 文件路径
IPS_FILE = "Fission_ip.txt"
DOMAINS_FILE = "Fission_domain.txt"
DNS_RESULT_FILE = "dns_result.txt"
GEOIP_DB_PATH = "GeoLite2-ASN.mmdb"

# 并发参数
MAX_WORKERS_REQUEST = 200
MAX_WORKERS_DNS = 500
MAX_DOMAINS = 10000
MAX_IPS = 20000

# User-Agent 生成器
ua = UserAgent()

# 站点配置
SITES_CONFIG = {
    "site_ip138": {
        "url": "https://site.ip138.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "dnsdblookup": {
        "url": "https://dnsdblookup.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpath": '//div[@id="J_domain"]/p/a'
    }
}


def setup_session():
    """ 设置带重试策略的 requests session """
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def get_headers():
    """ 生成随机 User-Agent 请求头 """
    return {
        'User-Agent': ua.random,
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }


def fetch_domains_for_ip(ip_address, session):
    """ 获取某个 IP 关联的域名 """
    print(f"[INFO] Fetching domains for {ip_address}...")
    
    for attempt in range(3):
        site_key = random.choice(list(SITES_CONFIG.keys()))
        site_info = SITES_CONFIG[site_key]

        try:
            url = f"{site_info['url']}{ip_address}/"
            headers = get_headers()
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            parser = etree.HTMLParser()
            tree = etree.fromstring(response.text, parser)
            domains = [a.text for a in tree.xpath(site_info['xpath']) if a.text]

            if domains:
                print(f"[SUCCESS] Domains found for {ip_address} from {site_info['url']}")
                return domains
        except requests.RequestException as e:
            print(f"[ERROR] Request failed for {ip_address} from {site_info['url']} (Attempt {attempt+1}/3): {e}")
        except etree.XMLSyntaxError:
            print(f"[ERROR] Failed to parse HTML for {ip_address} from {site_info['url']} (Attempt {attempt+1}/3)")

    return []


def fetch_domains_concurrently(ip_addresses):
    """ 并发获取多个 IP 关联的域名 """
    session = setup_session()
    domains = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_REQUEST) as executor:
        future_to_ip = {executor.submit(fetch_domains_for_ip, ip, session): ip for ip in ip_addresses}
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                domains.update(result)

    return list(domains)


def dns_lookup(domain):
    """ 进行 DNS 解析 """
    print(f"[INFO] Performing DNS lookup for {domain}...")
    result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
    return domain, result.stdout


def get_asn(reader, ip):
    """ 获取 IP 对应的 ASN 号 """
    try:
        return reader.asn(ip).autonomous_system_number
    except geoip2.errors.AddressNotFoundError:
        print(f"[WARNING] ASN not found for IP {ip}")
        return None


def perform_dns_lookups():
    """ 执行 DNS 查询，并过滤全球 IP """
    try:
        with open(DOMAINS_FILE, 'r') as file:
            domains = file.read().splitlines()

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_DNS) as executor:
            future_to_domain = {executor.submit(dns_lookup, domain): domain for domain in domains}
            results = {future_to_domain[future]: future.result()[1] for future in concurrent.futures.as_completed(future_to_domain)}

        with open(DNS_RESULT_FILE, 'w') as output_file:
            for domain, output in results.items():
                output_file.write(output)

        ipv4_addresses = set()
        for output in results.values():
            ipv4_addresses.update(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output))

        with open(IPS_FILE, 'r') as file:
            existing_ips = set(file.read().splitlines())

        filtered_ips = set()
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            for ip in ipv4_addresses:
                try:
                    if ipaddress.ip_address(ip).is_global and get_asn(reader, ip) != 13335:
                        filtered_ips.add(ip)
                except ValueError:
                    continue

        filtered_ips.update(existing_ips)

        with open(IPS_FILE, 'w') as output_file:
            output_file.write("\n".join(filtered_ips))

    except Exception as e:
        print(f"[ERROR] Error performing DNS lookups: {e}")


def main():
    """ 主函数 """
    os.makedirs(os.path.dirname(IPS_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(DOMAINS_FILE), exist_ok=True)

    with open(IPS_FILE, 'a+'):
        pass
    with open(DOMAINS_FILE, 'a+'):
        pass

    with open(IPS_FILE, 'r') as file:
        ip_list = [ip.strip() for ip in file]

    domain_list = fetch_domains_concurrently(ip_list)

    with open(DOMAINS_FILE, 'r') as file:
        exist_domains = set(file.read().splitlines())

    domain_list = list(set(domain_list + list(exist_domains)))

    with open(DOMAINS_FILE, 'w') as file:
        file.writelines("\n".join(domain_list[:MAX_DOMAINS]))

    print("[INFO] IP -> 域名 已完成")

    perform_dns_lookups()

    print("[INFO] 域名 -> IP 已完成")


if __name__ == "__main__":
    main()
