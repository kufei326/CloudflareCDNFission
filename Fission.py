import os
import re
import time
import random
import socket
import ipaddress
import concurrent.futures
from datetime import datetime
from typing import Set, List, Tuple, Optional

import requests
import geoip2.database
from lxml import etree
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置文件路径
IPS_FILE = "Fission_ip.txt"
DOMAINS_FILE = "Fission_domain.txt"
DNS_RESULT_FILE = "dns_result.txt"
GEOLITE_DB_PATH = "GeoLite2-ASN.mmdb"
LOG_FILE = "fission.log"
FAILED_DOMAINS_FILE = "failed_domains.txt"  # 新增：记录失败的域名

# 并发配置
MAX_WORKERS_REQUEST = 200
MAX_WORKERS_DNS = 300

# 限制配置
MAX_DOMAINS = 10000
MAX_IPS = 20000
CHECK_INTERVAL = 5       # 5分钟检查一次（秒）
MAX_STAGNANT_CYCLES = 3    # 最大停滞周期数
MAX_TOTAL_CYCLES = 100     # 最大总循环次数防止无限循环
DNS_TIMEOUT = 5          # DNS解析超时时间（秒）
MAX_DNS_RETRIES = 3 # 域名解析最大重试次数

sites_config = {
    "site_ip138": {
        "url": "https://site.ip138.com/",
        "xpath": '//ul[@id="list"]/li/a',
        "weight": 3
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpath": '//div[@id="J_domain"]/p/a',
        "weight": 2
    }
}

class DomainResolver:
    def __init__(self):
        self.session = self.setup_session()
        self.geoip_reader = self.init_geoip_reader()
        self.failed_domains: Dict[str, int] = self.load_failed_domains() # 加载失败域名计数


    @staticmethod
    def setup_session():
        """配置带重试机制的会话"""
        session = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=frozenset(['GET', 'POST'])
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    @staticmethod
    def init_geoip_reader():
        """初始化GeoIP数据库读取器"""
        try:
            return geoip2.database.Reader(GEOLITE_DB_PATH)
        except Exception as e:
            log_error(f"Failed to initialize GeoIP reader: {e}")
            raise

    @staticmethod
    def get_headers():
        """生成随机请求头"""
        return {
            'User-Agent': UserAgent().random,
            'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
    def load_failed_domains(self) -> dict:
        """加载失败域名及其尝试次数"""
        try:
            with open(FAILED_DOMAINS_FILE, 'r') as f:
                return {line.split()[0]: int(line.split()[1]) for line in f if line.strip()}
        except FileNotFoundError:
            return {}

    def save_failed_domains(self):
        """保存失败域名及其尝试次数"""
        with open(FAILED_DOMAINS_FILE, 'w') as f:
            for domain, count in self.failed_domains.items():
                f.write(f"{domain} {count}\n")
    def fetch_domains(self, ip: str) -> Set[str]:
        """获取IP关联的域名"""
        log_info(f"Starting domain lookup for {ip}")
        sites = sorted(
            sites_config.items(),
            key=lambda x: x[1]["weight"],
            reverse=True
        )

        for site_name, config in sites:
            try:
                url = f"{config['url']}{ip}/"
                log_info(f"Requesting URL: {url}")  # 记录请求的URL
                response = self.session.get(
                    url,
                    headers=self.get_headers(),
                    timeout=15
                )
                response.raise_for_status()  # 检查HTTP状态码

                parser = etree.HTMLParser()
                tree = etree.fromstring(response.text, parser)
                elements = tree.xpath(config['xpath'])
                domains = {e.text.strip() for e in elements if e.text}

                if domains:
                    log_info(f"Found {len(domains)} domains for {ip} on {site_name}")
                    return domains
            except requests.exceptions.RequestException as e:
                log_warning(f"Failed to fetch from {site_name} for {ip}: {e}")
            except Exception as e:
                log_warning(f"Failed to fetch from {site_name} for {ip}: {e}")
        
        return set()

    def dns_resolve(self, domain: str) -> Set[str]:
        """解析域名的IPv4地址 (使用线程模拟超时)"""

        # 检查域名是否已经失败多次
        if domain in self.failed_domains and self.failed_domains[domain] >= MAX_DNS_RETRIES:
            log_info(f"Skipping {domain} due to previous failures.")
            return set()

        def _resolve():
            try:
                info = socket.getaddrinfo(
                    host=domain,
                    port=None,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                )
                return {addr[4][0] for addr in info}
            except socket.gaierror as e:
                log_error(f"DNS resolution error (gaierror) for {domain}: {e}")
                return set()
            except Exception as e:
                log_error(f"DNS resolution error for {domain}: {e}")
                return set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_resolve)
            try:
                result = future.result(timeout=DNS_TIMEOUT)
                # 如果成功，重置失败计数
                if domain in self.failed_domains:
                    del self.failed_domains[domain]
                    self.save_failed_domains()
                return result
            except concurrent.futures.TimeoutError:
                log_warning(f"DNS resolution timed out for {domain}")
                self.failed_domains[domain] = self.failed_domains.get(domain, 0) + 1
                self.save_failed_domains()
                return set()
            except Exception as e:
                log_error(f"DNS resolution failed: {e}")
                self.failed_domains[domain] = self.failed_domains.get(domain, 0) + 1
                self.save_failed_domains()
                return set()
    def filter_ips(self, ips: Set[str]) -> Set[str]:
        """过滤有效的公网IP"""
        valid_ips = set()
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_global:
                    log_info(f"Filtering out non-global IP: {ip}") #记录过滤ip
                    continue

                # ASN过滤
                response = self.geoip_reader.asn(ip)
                if response.autonomous_system_number != 13335:
                    valid_ips.add(ip)
                else:
                    log_info(f"Filtering out IP with ASN 13335: {ip}") #记录过滤ip
            except (ValueError, geoip2.errors.AddressNotFoundError):
                log_info(f"Filtering out invalid IP format or address not found: {ip}") #记录过滤ip
                continue
            except Exception as e:
                log_error(f"ASN check failed for {ip}: {e}")

        return valid_ips

class DataManager:
    @staticmethod
    def load_data(filename: str) -> Set[str]:
        """加载数据文件"""
        try:
            with open(filename, 'r') as f:
                return {line.strip() for line in f if line.strip()}
        except FileNotFoundError:
            return set()

    @staticmethod
    def save_data(filename: str, data: Set[str], max_items: int = 0):
        """保存数据文件（带滚动保留）"""
        data_list = list(data)
        if max_items > 0 and len(data_list) > max_items:
            data_list = data_list[:max_items]  # 保留最新数据

        with open(filename, 'w') as f:
            for item in data_list:
                f.write(f"{item}\n")
    @staticmethod
    def remove_domains(domains_to_remove: Set[str]):
        """从域名文件中移除指定域名"""
        current_domains = DataManager.load_data(DOMAINS_FILE)
        updated_domains = current_domains - domains_to_remove
        DataManager.save_data(DOMAINS_FILE, updated_domains)

def main():
    # 初始化组件
    resolver = DomainResolver()
    data_mgr = DataManager()

    cycle_count = 0
    stagnant_cycles = 0
    last_state = (0, 0)  # (domains, ips)

    while cycle_count < MAX_TOTAL_CYCLES:
        cycle_count += 1
        log_info(f"========== Cycle {cycle_count} Started ==========")

        # 阶段1：IP -> 域名
        current_ips = data_mgr.load_data(IPS_FILE)
        current_domains = data_mgr.load_data(DOMAINS_FILE)

        if len(current_domains) < MAX_DOMAINS:
            try:
                new_domains = set()
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_REQUEST) as executor:
                    futures = {executor.submit(resolver.fetch_domains, ip): ip for ip in current_ips}

                    for future in concurrent.futures.as_completed(futures):
                        ip = futures[future]  # 获取与future关联的IP
                        try:
                            result = future.result()
                            new_domains.update(result)
                        except Exception as e:
                            log_error(f"Domain fetch failed for IP {ip}: {e}") # 记录具体ip

                # 合并并保存域名
                updated_domains = current_domains | new_domains
                data_mgr.save_data(DOMAINS_FILE, updated_domains, MAX_DOMAINS)
                log_info(f"Domains: +{len(new_domains)} | Total: {len(updated_domains)}/{MAX_DOMAINS}")
            except Exception as e:
                log_error(f"Domain collection phase failed: {e}")
        else:
            log_info("Domain limit reached, skipping domain collection")

        # 阶段2：域名 -> IP
        current_domains = data_mgr.load_data(DOMAINS_FILE)
         # 移除多次失败的域名
        domains_to_remove = {domain for domain, count in resolver.failed_domains.items() if count >= MAX_DNS_RETRIES}
        if domains_to_remove:
            data_mgr.remove_domains(domains_to_remove)
            log_info(f"Removed failed domains: {domains_to_remove}")
            current_domains = data_mgr.load_data(DOMAINS_FILE) #重新读取
        
        current_ips = data_mgr.load_data(IPS_FILE)

        if len(current_ips) < MAX_IPS:
            try:
                raw_ips = set()
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_DNS) as executor:
                    futures = {executor.submit(resolver.dns_resolve, domain): domain for domain in current_domains}

                    for future in concurrent.futures.as_completed(futures):
                        domain = futures[future] # 获取与future关联的域名
                        try:
                            result = future.result()
                            raw_ips.update(result)
                        except Exception as e:
                            log_error(f"DNS resolution failed for domain {domain}: {e}")#记录具体域名

                # 过滤并保存IP
                valid_ips = resolver.filter_ips(raw_ips)
                updated_ips = current_ips | valid_ips
                data_mgr.save_data(IPS_FILE, updated_ips, MAX_IPS)
                log_info(f"IPs: +{len(valid_ips)} | Total: {len(updated_ips)}/{MAX_IPS}")
            except Exception as e:
                log_error(f"IP collection phase failed: {e}")
        else:
            log_info("IP limit reached, skipping IP collection")

        # 检查终止条件
        current_domains = data_mgr.load_data(DOMAINS_FILE)
        current_ips = data_mgr.load_data(IPS_FILE)
        current_state = (len(current_domains), len(current_ips))

        # 检查是否达到限制
        if len(current_domains) >= MAX_DOMAINS and len(current_ips) >= MAX_IPS:
            log_info("Both limits reached, exiting...")
            break

        # 检查数据增长
        if current_state == last_state:
            stagnant_cycles += 1
            log_info(f"No data growth detected ({stagnant_cycles}/{MAX_STAGNANT_CYCLES})")
            if stagnant_cycles >= MAX_STAGNANT_CYCLES:
                log_info("Stagnant cycle limit reached, exiting...")
                break
        else:
            stagnant_cycles = 0
            last_state = current_state

        # 显示进度
        log_info(f"Progress: Domains {current_state[0]}/{MAX_DOMAINS} | IPs {current_state[1]}/{MAX_IPS}")

        # 等待下一个周期
        log_info(f"Cycle {cycle_count} completed, sleeping {CHECK_INTERVAL}s...")
        time.sleep(CHECK_INTERVAL)

    log_info(f"Process completed after {cycle_count} cycles")

def log_info(message: str):
    log("INFO", message)

def log_warning(message: str):
    log("WARNING", message)

def log_error(message: str):
    log("ERROR", message)

def log(level: str, message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {message}"
    print(log_msg)
    with open(LOG_FILE, "a") as f:
        f.write(log_msg + "\n")

if __name__ == "__main__":
    # 初始化必要文件
    for f in [IPS_FILE, DOMAINS_FILE, DNS_RESULT_FILE, LOG_FILE, FAILED_DOMAINS_FILE]: # 增加了 FAILED_DOMAINS_FILE
        if not os.path.exists(f):
            open(f, 'w').close()

    try:
        main()
    except KeyboardInterrupt:
        log_info("Process interrupted by user")
    except Exception as e:
        log_error(f"Critical failure: {e}")
    finally:
        log_info("Cleaning up resources...")
