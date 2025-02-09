import os
import re
import random
import ipaddress
import subprocess
import concurrent.futures
from typing import List, Set, Tuple

import requests
from lxml import etree
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import geoip2.database
import geoip2.errors

# 文件路径配置
IPS_FILE = "Fission_ip.txt"
DOMAINS_FILE = "Fission_domain.txt"
DNS_RESULT_FILE = "dns_result.txt"
GEOIP_DB_PATH = "GeoLite2-ASN.mmdb"

# 并发线程数配置
MAX_WORKERS_REQUEST = 200
MAX_WORKERS_DNS = 500

ua = UserAgent()

# 查询网站配置，每个站点包含基础 URL 和对应的 xpath 表达式
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


def setup_session() -> requests.Session:
    """创建并配置一个 requests.Session 对象，启用重试机制。"""
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_headers() -> dict:
    """获取随机 User-Agent 的请求头。"""
    return {
        "User-Agent": ua.random,
        "Accept": "*/*",
        "Connection": "keep-alive",
    }


def fetch_domains_for_ip(ip_address: str, session: requests.Session) -> List[str]:
    """
    对于给定的 IP 地址，从配置的网站中依次尝试查询对应的域名，
    如果在某个网站成功提取到域名，则立即返回结果，最多重试 3 次。
    """
    max_attempts = 3
    used_sites: Set[str] = set()
    attempts = 0

    while attempts < max_attempts:
        available_sites = [key for key in SITES_CONFIG if key not in used_sites]
        if not available_sites:
            break

        site_key = random.choice(available_sites)
        used_sites.add(site_key)
        site_info = SITES_CONFIG[site_key]
        url = f"{site_info['url']}{ip_address}/"
        headers = get_headers()

        try:
            response = session.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            # 解析页面
            tree = etree.HTML(response.text)
            a_elements = tree.xpath(site_info["xpath"])
            domains = [a.text.strip() for a in a_elements if a.text and a.text.strip()]

            if domains:
                return domains
            else:
                raise ValueError("未提取到有效域名")
        except Exception:
            attempts += 1

    return []


def fetch_domains_concurrently(ip_addresses: List[str]) -> List[str]:
    """
    并发处理所有 IP 地址，获取所有对应的域名，并返回去重后的域名列表。
    """
    session = setup_session()
    all_domains: Set[str] = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_REQUEST) as executor:
        future_to_ip = {
            executor.submit(fetch_domains_for_ip, ip, session): ip
            for ip in ip_addresses if ip
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                domains = future.result()
                all_domains.update(domains)
            except Exception:
                continue

    return list(all_domains)


def dns_lookup(domain: str) -> Tuple[str, str]:
    """
    对给定域名执行 nslookup，并返回 (域名, nslookup 输出) 的元组。
    """
    result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
    return domain, result.stdout


def get_asn(reader: geoip2.database.Reader, ip: str) -> int:
    """
    利用 geoip2 数据库查询 IP 地址的 ASN 信息。
    如果未找到则返回 None。
    """
    try:
        response = reader.asn(ip)
        return response.autonomous_system_number
    except geoip2.errors.AddressNotFoundError:
        return None


def perform_dns_lookups(
    domain_filename: str, result_filename: str, unique_ipv4_filename: str, excluded_ip_ranges: List[ipaddress.IPv4Network] = []
) -> None:
    """
    读取域名文件，执行 DNS 查询，保存查询结果，并解析出其中的 IPv4 地址，
    利用 geoip2 数据库过滤出合法的 IP（全局地址且 ASN 不为 13335 和 209242），
    同时排除指定的 IP 段，最后将 IP 与文件中已有的 IP 合并保存。
    """
    try:
        # 读取域名列表
        with open(domain_filename, "r", encoding="utf-8") as file:
            domains = [line.strip() for line in file if line.strip()]

        # 并发执行 nslookup
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_DNS) as executor:
            results = list(executor.map(dns_lookup, domains))

        # 将 nslookup 结果写入文件
        with open(result_filename, "w", encoding="utf-8") as output_file:
            for domain, output in results:
                output_file.write(output + "\n")

        # 编译 IPv4 正则表达式
        ipv4_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        ipv4_addresses: Set[str] = set()
        for _, output in results:
            ipv4_addresses.update(ipv4_pattern.findall(output))

        # 读取已有的 IP 列表（去除空行）
        if os.path.exists(unique_ipv4_filename):
            with open(unique_ipv4_filename, "r", encoding="utf-8") as file:
                exist_list = {ip.strip() for ip in file if ip.strip()}
        else:
            exist_list = set()

        filtered_ipv4_addresses: Set[str] = set()
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            for ip in ipv4_addresses:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    # 打印调试信息，查看哪些 IP 被排除
                    if any(ip_obj in range for range in excluded_ip_ranges):
                        print(f"排除 IP: {ip_obj}，因为它在排除段内")
                        continue
                    if ip_obj.is_global:
                        asn = get_asn(reader, ip)
                        # 同时过滤掉 Cloudflare（ASN 13335）和 AS209242（ASN 209242）的 IP
                        if asn and asn not in (13335, 209242, 140224):
                            filtered_ipv4_addresses.add(ip)
                except ValueError:
                    continue

        # 合并已有的 IP 列表
        filtered_ipv4_addresses.update(exist_list)

        # 写入结果
        with open(unique_ipv4_filename, "w", encoding="utf-8") as output_file:
            for address in sorted(filtered_ipv4_addresses):
                output_file.write(address + "\n")

    except Exception as e:
        print(f"执行 DNS 查询出错：{e}")


def update_domains(ip_file: str, domain_file: str, max_domains: int = 10000) -> None:
    """
    1. 从 ip_file 中读取 IP 列表
    2. 并发查询对应的域名
    3. 与已有域名合并后保存到 domain_file 中（最多 max_domains 条）
    """
    with open(ip_file, "r", encoding="utf-8") as f:
        ip_list = [line.strip() for line in f if line.strip()]

    if not ip_list:
        return

    new_domains = fetch_domains_concurrently(ip_list)

    # 读取已有的域名（如果文件存在）
    if os.path.exists(domain_file):
        with open(domain_file, "r", encoding="utf-8") as f:
            existing_domains = {line.strip() for line in f if line.strip()}
    else:
        existing_domains = set()

    all_domains = set(new_domains) | existing_domains

    with open(domain_file, "w", encoding="utf-8") as f:
        for domain in list(all_domains)[:max_domains]:
            f.write(domain + "\n")


def update_ips(domain_file: str, dns_result_file: str, ip_file: str, excluded_ip_ranges: List[ipaddress.IPv4Network] = [], max_ips: int = 20000) -> None:
    """
    1. 根据域名文件执行 DNS 查询，更新 ip_file 中的 IP 列表；
    2. 最后对 IP 文件进行数量限制（最多 max_ips 条）。
    """
    perform_dns_lookups(domain_file, dns_result_file, ip_file, excluded_ip_ranges)

    with open(ip_file, "r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip()]

    unique_ips = ips[:max_ips]
    with open(ip_file, "w", encoding="utf-8") as f:
        for ip in unique_ips:
            f.write(ip + "\n")


def ensure_file_exists(filepath: str) -> None:
    """如果文件不存在，则创建一个空文件。"""
    if not os.path.exists(filepath):
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("")


def main() -> None:
    # 排除的 IP 段
    excluded_ip_ranges = [
        ipaddress.IPv4Network("103.237.95.0/24"),
        ipaddress.IPv4Network("10.0.0.0/8")
    ]

    # 确保必要的文件存在
    ensure_file_exists(IPS_FILE)
    ensure_file_exists(DOMAINS_FILE)

    # 更新域名文件：通过 IP 查询对应的域名，并合并已有域名
    update_domains(IPS_FILE, DOMAINS_FILE, max_domains=50000)

    # 更新 IP 文件：通过域名执行 DNS 查询，更新 IP 列表
    update_ips(DOMAINS_FILE, DNS_RESULT_FILE, IPS_FILE, excluded_ip_ranges, max_ips=20000)


if __name__ == "__main__":
    main()
