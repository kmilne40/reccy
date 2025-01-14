#!/usr/bin/env python3

import re
import logging
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
from tabulate import tabulate
import ipaddress
import subprocess
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import socket
import ssl
import webbrowser  # For Google dorks
import json
import os
import colorama
from colorama import Fore, Style

colorama.init()

# For the new Shodan sub-menu code
import shodan

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# =============================================================================
# Hardcoded Shodan API Key (REPLACE if needed)
# =============================================================================
SHODAN_API_KEY = "put-your-key-here"  # Replace with your Shodan API key

try:
    api = shodan.Shodan(SHODAN_API_KEY)
except Exception as e:
    print("Error initializing Shodan API:", e)
    # We won't exit here in case user uses other menu options that don't need Shodan
    # exit(1)

# =============================================================================
# Utility Functions (Original)
# =============================================================================
def print_table(data, headers):
    if data:
        print(tabulate(data, headers=headers, tablefmt="pretty"))
    else:
        print("No data available.")

def is_valid_domain(domain):
    domain_regex = re.compile(
        r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
    )
    return bool(domain_regex.match(domain))

def is_valid_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

# =============================================================================
# WHOIS (Option 6)
# =============================================================================
def whois_lookup(domain):
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    try:
        whois_output = subprocess.check_output(
            ["whois", domain],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10
        )
    except FileNotFoundError:
        print("Error: The 'whois' command is not installed on this system.")
        return
    except subprocess.CalledProcessError as e:
        print(f"WHOIS command failed:\n{e.output}")
        return
    except Exception as e:
        print(f"WHOIS lookup error occurred: {e}")
        return

    # Raw WHOIS
    print(whois_output)

    # Check for domain transfer lock
    whois_data = {}
    lines = whois_output.splitlines()
    for line in lines:
        line = line.strip()
        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()
            if key not in whois_data:
                whois_data[key] = []
            whois_data[key].append(val)

    transfer_locked = None
    status_lines_found = False
    for k, values in whois_data.items():
        if "status" in k.lower():
            status_lines_found = True
            for v in values:
                if "transferprohibited" in v.lower():
                    transfer_locked = True
                else:
                    if transfer_locked is not True:
                        transfer_locked = False

    if status_lines_found:
        if transfer_locked is True:
            print("\nDomain status: LOCKED (transferProhibited).")
        elif transfer_locked is False:
            print("\n\033[91mDomain might be UNLOCKED (transfer possible)!\033[0m")
        else:
            print("\nDomain transfer lock status: Unknown.")
    else:
        print("\nDomain transfer lock status: Unknown (no 'Status' lines found).")

# =============================================================================
# DNS Lookups (Options 1-5, 7, 8, 10)
# =============================================================================
def generic_dns_lookup(domain, record_type):
    if not is_valid_domain(domain):
        logging.warning(f"Domain might be invalid: {domain}")
        return []
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata.to_text()) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as e:
        logging.error(f"DNS error ({record_type}) for {domain}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error ({record_type}) for {domain}: {e}")
        return []

def dns_lookup(domain):
    results = generic_dns_lookup(domain, 'A')
    if results:
        data = [(r,) for r in results]
        print_table(data, ["IP Address"])
    else:
        print(f"No A records found for {domain} or domain is invalid.")

def mx_lookup(domain):
    results = generic_dns_lookup(domain, 'MX')
    parsed = []
    for mx_rec in results:
        parts = mx_rec.split()
        if len(parts) == 2:
            parsed.append((parts[1].rstrip("."),))
        else:
            parsed.append((mx_rec,))
    if parsed:
        print_table(parsed, ["Mail Server"])
    else:
        print(f"No MX records found for {domain}")

def ns_lookup(domain):
    results = generic_dns_lookup(domain, 'NS')
    if results:
        data = [(r.rstrip("."),) for r in results]
        print_table(data, ["Name Server"])
    else:
        print(f"No NS records found for {domain}")

def soa_lookup(domain):
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        data = []
        for rdata in answers:
            data.append((
                rdata.mname.to_text(),
                rdata.rname.to_text(),
                rdata.serial,
                rdata.refresh,
                rdata.retry,
                rdata.expire,
                rdata.minimum
            ))
        headers = [
            "Primary Name Server", "Responsible Person", "Serial Number",
            "Refresh Interval", "Retry Interval", "Expire Limit", "Minimum TTL"
        ]
        print_table(data, headers)
    except dns.resolver.NoAnswer:
        print(f"No SOA records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during SOA lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during SOA lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def reverse_lookup(ip_address):
    if not is_valid_ip(ip_address):
        print(f"Invalid IP address: {ip_address}")
        return
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        data = [(rdata.target.to_text(),) for rdata in answers]
        print_table(data, ["Domain Name"])
    except dns.resolver.NoAnswer:
        print(f"No PTR records found for {ip_address}.")
    except dns.resolver.NXDOMAIN:
        print(f"No reverse DNS record exists for {ip_address}.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during reverse lookup for {ip_address}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during reverse lookup for {ip_address}: {e}")
        print("An unexpected error occurred.")

def get_all_information(domain):
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    print(f"Getting DNS + WHOIS info (raw) for: {domain}")
    print("-" * 60)

    # A
    print("DNS Lookup (A record):")
    a_records = generic_dns_lookup(domain, 'A')
    if a_records:
        for ip in a_records:
            print(ip)
    else:
        print(f"No A records found for {domain}.")

    # MX
    print("\nMX Lookup:")
    mx_records = generic_dns_lookup(domain, 'MX')
    if mx_records:
        for mx in mx_records:
            print(mx)
    else:
        print(f"No MX records found for {domain}.")

    # NS
    print("\nNS Lookup:")
    ns_records = generic_dns_lookup(domain, 'NS')
    if ns_records:
        for ns in ns_records:
            print(ns)
    else:
        print(f"No NS records found for {domain}.")

    # SOA
    print("\nSOA Lookup:")
    soa_records = generic_dns_lookup(domain, 'SOA')
    if soa_records:
        for soa in soa_records:
            print(soa)
    else:
        print(f"No SOA records found for {domain}.")

    # Reverse DNS (first A if any)
    if a_records:
        print("\nReverse DNS Lookup (for first IP):")
        first_ip = a_records[0]
        if is_valid_ip(first_ip):
            try:
                rev_name = dns.reversename.from_address(first_ip)
                ptr_answers = dns.resolver.resolve(rev_name, 'PTR')
                for rdata in ptr_answers:
                    print(rdata.target.to_text())
            except dns.resolver.NoAnswer:
                print(f"No PTR records found for {first_ip}.")
            except dns.resolver.NXDOMAIN:
                print(f"No reverse DNS record exists for {first_ip}.")
            except dns.exception.DNSException as e:
                logging.error(f"DNS error during reverse lookup for {first_ip}: {e}")
                print("DNS error occurred.")
            except Exception as e:
                logging.error(f"Unexpected error during reverse lookup for {first_ip}: {e}")
                print("An unexpected error occurred.")
        else:
            print(f"{first_ip} is not a valid IP address.")
    else:
        print("\nNo IP addresses available for reverse lookup.")

    print("\nWHOIS Lookup:")
    whois_lookup(domain)

def zone_transfer(domain):
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns_record in ns_records:
            ns_server = str(ns_record.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=5))
                if zone:
                    print(f"Zone transfer results for domain: {domain}")
                    print(zone.to_text())
                    return
            except dns.exception.DNSException as e:
                logging.info(f"Zone transfer failed at {ns_server} for {domain}: {e}")
        print("Zone transfer did not succeed with any name server.")
    except dns.resolver.NoAnswer:
        print(f"No NS records found for {domain}, cannot attempt zone transfer.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during zone transfer for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during zone transfer for {domain}: {e}")
        print("An unexpected error occurred.")

def subdomain_brute_force(domain, wordlist_path):
    if not is_valid_domain(domain):
        print(f"Warning: {domain} might not pass regex validation.\n")

    print(f"[*] Starting subdomain brute force for: {domain}")
    print(f"[*] Using subdomain wordlist: {wordlist_path}\n")

    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Wordlist file not found: {wordlist_path}")
        return
    except Exception as e:
        logging.error(f"Error reading subdomain file '{wordlist_path}': {e}")
        return

    found_subdomains = []
    for sub in subdomains:
        brute_domain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(brute_domain, 'A')
            ip_addresses = [rdata.address for rdata in answers]
            found_subdomains.append((brute_domain, ", ".join(ip_addresses)))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.DNSException as ex:
            logging.debug(f"DNS error for subdomain {brute_domain}: {ex}")
            pass

    if found_subdomains:
        print("Discovered subdomains:\n")
        print_table(found_subdomains, ["Subdomain", "Resolved IP(s)"])
    else:
        print("No subdomains were discovered.")

# =============================================================================
# Email Scraper (Option 9)
# =============================================================================
def email_scraper():
    visited_urls = set()
    emails_found = set()

    def extract_emails_from_page(url):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            page_emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", response.text)
            for email in page_emails:
                emails_found.add(email)
            links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)]
            return links
        except Exception as e:
            logging.debug(f"Failed to fetch {url}: {e}")
            return []

    def spider_website(base_url, max_depth=2):
        queue = [(base_url, 0)]
        visited_urls.add(base_url)
        while queue:
            current_url, depth = queue.pop(0)
            if depth > max_depth:
                continue
            new_links = extract_emails_from_page(current_url)
            for link in new_links:
                if link.startswith(base_url) and link not in visited_urls:
                    visited_urls.add(link)
                    print(f"Visiting: {link}")
                    queue.append((link, depth + 1))

    start_url = input("Enter the website URL to spider (e.g., https://example.com): ").strip()
    max_depth_input = input("Enter the spidering depth (e.g., 2): ").strip()
    try:
        max_depth = int(max_depth_input)
    except ValueError:
        print("Invalid depth. Defaulting to 2.")
        max_depth = 2
    print(f"Starting spidering for: {start_url} with depth: {max_depth}\n")
    spider_website(start_url, max_depth)

    print("\nEmails found:")
    if emails_found:
        for email in emails_found:
            print(email)
    else:
        print("No emails found.")

# =============================================================================
# 11. Port Scanning & Banner Grabbing
# =============================================================================
def port_scan_banner():
    host = input("Enter domain or IP to scan: ").strip()
    ports_str = input("Enter comma-delimited ports to scan (e.g., 22,80,443): ").strip()
    try:
        port_list = []
        for p in ports_str.split(","):
            p = p.strip()
            if p.isdigit():
                port_list.append(int(p))
    except:
        print("Invalid ports specified. Exiting.")
        return
    print(f"\nScanning {host} for ports: {port_list}")
    open_ports = []
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is OPEN. Attempting banner grab...")
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024)
                    print(f"  Banner: {banner.decode(errors='replace')}")
                except Exception as e:
                    print(f"  Could not grab banner: {e}")
            sock.close()
        except Exception:
            pass

    if open_ports:
        print("\nOpen ports found:")
        print(open_ports)
    else:
        print("\nNo open ports found among the specified ports.")

# =============================================================================
# 12. HTTP Header Inspection
# =============================================================================
def http_header_inspection():
    url = input("Enter the full URL (e.g., https://example.com): ").strip()
    try:
        resp = requests.get(url, timeout=5)
        print(f"Status Code: {resp.status_code}")
        print("Headers:")
        for k, v in resp.headers.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"Error retrieving headers for {url}: {e}")

# =============================================================================
# 13. robots.txt & sitemap.xml Parsing
# =============================================================================
def robots_sitemap_inspection():
    domain = input("Enter the domain (e.g. example.com): ").strip()
    if not domain.startswith("http"):
        domain = "http://" + domain
    robots_url = domain.rstrip("/") + "/robots.txt"
    try:
        r = requests.get(robots_url, timeout=5)
        if r.status_code == 200:
            print("\n[robots.txt found:]\n")
            print(r.text)
        else:
            print(f"No robots.txt found (HTTP {r.status_code}).")
    except Exception as e:
        print(f"Error retrieving robots.txt: {e}")
    sitemap_url = domain.rstrip("/") + "/sitemap.xml"
    try:
        s = requests.get(sitemap_url, timeout=5)
        if s.status_code == 200:
            print("\n[sitemap.xml found:]\n")
            print(s.text)
        else:
            print(f"No sitemap.xml found (HTTP {s.status_code}).")
    except Exception as e:
        print(f"Error retrieving sitemap.xml: {e}")

# =============================================================================
# 14. SSL/TLS Certificate Information
# =============================================================================
def ssl_certificate_info():
    domain = input("Enter domain for SSL info (e.g. example.com): ").strip()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print("\n[SSL Certificate Info]\n")
                print(cert)
    except Exception as e:
        print(f"Error retrieving SSL cert for {domain}: {e}")

# =============================================================================
# 15. DNSSEC Validation (Basic)
# =============================================================================
def dnssec_validation():
    domain = input("Enter domain for DNSSEC check: ").strip()
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    print(f"Checking DNSSEC records for {domain}...")
    try:
        rrsig_answers = dns.resolver.resolve(domain, 'RRSIG')
        if rrsig_answers:
            print("\nRRSIG records found:")
            for r in rrsig_answers:
                print(r.to_text())
        else:
            print("No RRSIG records found.")
    except dns.resolver.NoAnswer:
        print("No RRSIG records found.")
    except Exception as e:
        print(f"Error checking RRSIG: {e}")

    try:
        dnskey_answers = dns.resolver.resolve(domain, 'DNSKEY')
        if dnskey_answers:
            print("\nDNSKEY records found:")
            for r in dnskey_answers:
                print(r.to_text())
        else:
            print("No DNSKEY records found.")
    except dns.resolver.NoAnswer:
        print("No DNSKEY records found.")
    except Exception as e:
        print(f"Error checking DNSKEY: {e}")

# =============================================================================
# 16. Parse Webpage Comments
# =============================================================================
def parse_web_comments():
    url = input("Enter the full URL (e.g. https://example.com): ").strip()
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        comments = re.findall(r'<!--(.*?)-->', resp.text, re.DOTALL)
        if comments:
            print("\nDiscovered HTML Comments:\n")
            for c in comments:
                print("-----------")
                print(c.strip())
                print("-----------")
        else:
            print("No HTML comments found.")
    except Exception as e:
        print(f"Error retrieving page or parsing comments: {e}")

# =============================================================================
# 17. Google Dorks
# =============================================================================
def google_dorks():
    domain = input("Enter domain for Google Dorks (e.g. example.com): ").strip()
    if not domain:
        print("No domain provided. Exiting.")
        return
    dorks = [
        f'site:{domain}',
        f'site:{domain} inurl:admin',
        f'site:{domain} filetype:pdf',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} "phpinfo()"',
    ]
    print("\nCommon Google Dorks:\n")
    for d in dorks:
        print(f"  {d}")
    open_in_browser = input("\nOpen these searches in browser? (y/n): ").strip().lower()
    if open_in_browser == 'y':
        for d in dorks:
            url = f"https://www.google.com/search?q={d}"
            print(f"Opening: {url}")
            webbrowser.open(url)

# =============================================================================
# 18. Shodan Sub-Menu
# =============================================================================

def sub_menu_shodan():
    """
    A sub-menu for a KISS-style interactive Shodan tool using the built-in
    SHODAN_API_KEY and `shodan` library code you provided.
    """
    # We'll embed your code snippet for the Shodan KISS approach here:
    # Just call `main_menu_shodan_kiss()` to handle everything.

    main_menu_shodan_kiss()


###############################################################################
# Code snippet from your Shodan-based script (KISS) integrated as a function
###############################################################################
class ShodanQueryBuilder:
    def __init__(self):
        self.base_query = ""
        self.full_query = ""

    def set_base_query(self, base):
        self.base_query = base.strip()
        self.full_query = self.base_query

    def reset(self):
        self.base_query = ""
        self.full_query = ""

    def is_empty(self):
        return not self.full_query.strip()

    def add_filter(self, f, operator="AND"):
        f = f.strip()
        if not f:
            return
        if self.is_empty():
            self.full_query = f
        else:
            if operator.upper() == "AND":
                self.full_query = f"{self.full_query} {f}"
            elif operator.upper() == "OR":
                self.full_query = f"({self.full_query}) OR ({f})"

    def get_query(self):
        if self.is_empty():
            return "*"
        return self.full_query.strip()


results_cache = []
query_builder = ShodanQueryBuilder()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_ascii_banner():
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    print("@@@@     K   I   S   S       @@@@")
    print("@@@@                         @@@@")
    print("@@@@   Kev's Interactive     @@@@")
    print("@@@@   Shodan Simplifier     @@@@")
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")

def main_menu_shodan_kiss():
    """ The main menu for your KISS approach. """
    while True:
        clear_screen()
        print_ascii_banner()
        print("KISS: Kev's Interactive Shodan Simplifier")
        print("==========================================")
        print("1. Choose a target type (domain, organization, network, IP, or nothing)")
        print("2. Add filters (port, vulnerabilities, etc.) with AND/OR")
        print("3. Finalize query, edit manually if needed, and execute")
        print("4. Save last results to file")
        print("5. View and add trending CVE-based queries (Requires Shodan API usage, might fail if no plan)")
        print("6. Manage Shodan Alerts")
        print("7. View Stats/Facets for the current query")
        print("8. Start a new clean query")
        print("9. Exit back to Main Program")
        print("==========================================")
        choice = input("Choose an option (1-9): ")

        if choice == "1":
            choose_target_type()
        elif choice == "2":
            add_filters_menu()
        elif choice == "3":
            finalize_and_execute_query()
        elif choice == "4":
            save_results_to_file()
        elif choice == "5":
            add_trending_cve_filter()
        elif choice == "6":
            manage_alerts_menu()
        elif choice == "7":
            view_stats()
        elif choice == "8":
            start_new_query()
        elif choice == "9":
            print("Returning to main program menu...")
            input("Press Enter...")
            return
        else:
            print("Invalid choice. Press Enter to continue...")
            input()

def start_new_query():
    query_builder.reset()
    global results_cache
    results_cache = []
    print("A new, clean query has been started. Previous query and results cleared.")
    input("Press Enter to return to sub-menu...")

def choose_target_type():
    clear_screen()
    print("Target Type Selection")
    print("======================")
    print("1. Domain (e.g., hostname:example.com)")
    print("2. Organization (e.g., org:\"Google LLC\")")
    print("3. Network (CIDR) (e.g., net:192.168.1.0/24)")
    print("4. IP Address (e.g., 8.8.8.8)")
    print("5. Nothing (empty base query)")
    print("======================")
    choice = input("Choose a target type (1-5): ")

    if choice == "1":
        domain = input("Enter the domain (e.g., example.com): ").strip()
        query_builder.set_base_query(f"hostname:{domain}")
    elif choice == "2":
        org = input("Enter the organization name (e.g., Google LLC): ").strip()
        query_builder.set_base_query(f'org:"{org}"')
    elif choice == "3":
        network = input("Enter the network CIDR (e.g., 192.168.1.0/24): ").strip()
        query_builder.set_base_query(f"net:{network}")
    elif choice == "4":
        ip_address = input("Enter the IP address (e.g., 8.8.8.8): ").strip()
        query_builder.set_base_query(ip_address)
    elif choice == "5":
        query_builder.set_base_query("")
    else:
        print("Invalid choice.")
        input("Press Enter to continue...")
        return

    print(f"Current query: {query_builder.get_query()}")
    input("Press Enter to return to sub-menu...")

def add_filters_menu():
    while True:
        clear_screen()
        print("Filter Options")
        print("===================")
        print("1. Add port filter (port:22)")
        print("2. Add vulnerability (vuln:CVE-xxxx-xxxx)")
        print("3. Add key phrase (e.g., \"admin\")")
        print("4. Add product (e.g., product:Apache)")
        print("5. Add country (e.g., country:US)")
        print("6. Add city (e.g., city:\"New York\")")
        print("7. Add OS (e.g., os:\"Windows 10\")")
        print("8. Add raw filter (expert mode)")
        print("9. Return to sub-menu")
        choice = input("Choose a filter type (1-9): ")

        if choice == "9":
            break

        operator = input("Combine this filter with the existing query using AND or OR? [AND/OR]: ").strip().upper()
        if operator not in ["AND", "OR"]:
            operator = "AND"

        filter_str = ""
        if choice == "1":
            port = input("Enter the port number (e.g., 22): ").strip()
            filter_str = f"port:{port}"
        elif choice == "2":
            vuln = input("Enter the CVE (e.g., CVE-2023-12345): ").strip()
            filter_str = f"vuln:{vuln}"
        elif choice == "3":
            phrase = input("Enter the key phrase (e.g., admin): ").strip()
            if " " in phrase and not (phrase.startswith('"') and phrase.endswith('"')):
                phrase = f"\"{phrase}\""
            filter_str = phrase
        elif choice == "4":
            product = input("Enter the product name (e.g., Apache): ").strip()
            filter_str = f"product:{product}"
        elif choice == "5":
            country = input("Enter the country code (e.g., US): ").strip()
            filter_str = f"country:{country}"
        elif choice == "6":
            city = input("Enter the city (e.g., \"New York\"): ").strip()
            if " " in city and not (city.startswith('"') and city.endswith('"')):
                city = f"\"{city}\""
            filter_str = f"city:{city}"
        elif choice == "7":
            os_name = input("Enter the operating system (e.g., \"Windows 10\"): ").strip()
            if " " in os_name and not (os_name.startswith('"') and os_name.endswith('"')):
                os_name = f"\"{os_name}\""
            filter_str = f"os:{os_name}"
        elif choice == "8":
            filter_str = input("Enter the raw filter string (title:\"Login Page\"): ").strip()
        else:
            print("Invalid choice. Press Enter to continue...")
            input()
            continue

        if filter_str:
            query_builder.add_filter(filter_str, operator=operator)
            print(f"Filter added. Current Query: {query_builder.get_query()}")
        else:
            print("No filter added.")

        input("Press Enter to continue...")

def add_trending_cve_filter():
    clear_screen()
    print("Attempting to fetch trending queries from Shodan... (May fail on free plans.)")
    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            print("No trending CVE-based queries found at this time.")
            input("Press Enter to return...")
            return

        print("Trending CVE Queries (first 10):")
        for i, q in enumerate(cve_queries[:10]):
            print(f"{i+1}. Title: {q['title']} | Query: {q['query']}")

        choice = input(f"Select a query to add (1-{min(len(cve_queries),10)}) or press Enter to cancel: ").strip()
        if not choice.isdigit():
            return
        idx = int(choice)
        if 1 <= idx <= len(cve_queries[:10]):
            chosen_query = cve_queries[idx-1]['query']
            operator = input("Combine with AND or OR? [AND/OR]: ").strip().upper()
            if operator not in ["AND", "OR"]:
                operator = "AND"
            query_builder.add_filter(chosen_query, operator=operator)
            print(f"Trending CVE Query added. Current Query: {query_builder.get_query()}")
        else:
            print("Invalid selection.")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")

    input("Press Enter to return...")

def finalize_and_execute_query():
    clear_screen()
    q = query_builder.get_query()
    print("Final Query (Before Execution):")
    print("======================")
    print(q)
    print("======================")
    edit_choice = input("Would you like to (E)dit, (R)un, or (C)ancel? [E/R/C]: ").strip().upper()
    if edit_choice == "E":
        new_q = input(f"Query [{q}]: ").strip()
        if new_q:
            q = new_q
    elif edit_choice == "C":
        return
    execute_query(q)

results_cache = []

def execute_query(final_query):
    clear_screen()
    print(f"Executing Shodan Query: {final_query}")
    print("======================")
    page = 1
    global results_cache
    results_cache = []

    while True:
        try:
            results = api.search(final_query, page=page)
            total = results.get('total', 0)
            matches = results.get('matches', [])
            if page == 1:
                print(f"Total results found: {total}")
            if not matches and page == 1:
                print("No results found.")
                input("Press Enter to return...")
                return
            elif not matches:
                print("No more results.")
                input("Press Enter to return...")
                return

            for match in matches:
                ip = match.get('ip_str', 'N/A')
                port = match.get('port', 'N/A')
                org = match.get('org', 'N/A')
                print(f"IP: {ip}, Port: {port}, Org: {org}")

            results_cache.extend(matches)

            print("\n[P]revious Page  |  [N]ext Page  |  [M]ain Menu")
            nav = input("Choose an action (P/N/M): ").lower()
            if nav == 'p':
                if page > 1:
                    page -= 1
                else:
                    print("Already on the first page.")
                    input("Press Enter...")
            elif nav == 'n':
                if len(matches) > 0:
                    page += 1
                else:
                    print("No more pages.")
                    input("Press Enter...")
            elif nav == 'm':
                return
            else:
                print("Invalid choice. Returning to sub-menu...")
                input("Press Enter...")
                return
        except shodan.APIError as e:
            print(f"Shodan API Error: {e}")
            logging.error(f"Shodan API Error: {e}")
            input("Press Enter...")
            return
        except Exception as e:
            print(f"Unexpected error: {e}")
            logging.error(f"Unexpected error: {e}")
            input("Press Enter...")
            return

def save_results_to_file():
    global results_cache
    if not results_cache:
        print("No results cached. Execute a query first.")
        input("Press Enter...")
        return
    filename = input("Enter filename to save results (e.g., results.json): ").strip()
    if not filename:
        filename = "results.json"
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_cache, f, ensure_ascii=False, indent=4)
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving file: {e}")
        logging.error(f"File Save Error: {e}")
    input("Press Enter...")

def manage_alerts_menu():
    while True:
        clear_screen()
        print("Shodan Alerts Management")
        print("========================")
        print("1. Create a new alert")
        print("2. List existing alerts")
        print("3. Delete an alert")
        print("4. Return to sub-menu")
        choice = input("Choose an option (1-4): ")

        if choice == "1":
            create_alert()
        elif choice == "2":
            list_alerts()
        elif choice == "3":
            delete_alert()
        elif choice == "4":
            break
        else:
            print("Invalid choice.")
            input("Press Enter...")

def create_alert():
    name = input("Enter a name for the alert: ").strip()
    ip_range = input("Enter the network or IP to monitor (e.g., 1.2.3.0/24): ").strip()
    if not name or not ip_range:
        print("Invalid input. Name and IP range are required.")
        input("Press Enter...")
        return
    try:
        alert = api.create_alert(name, ip_range)
        print(f"Alert created: {alert['id']}")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
    input("Press Enter...")

def list_alerts():
    try:
        alerts = api.alerts()
        if not alerts:
            print("No alerts found.")
        else:
            print("Existing Alerts:")
            for a in alerts:
                print(f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
    input("Press Enter...")

def delete_alert():
    alert_id = input("Enter the alert ID to delete: ").strip()
    if not alert_id:
        print("Invalid alert ID.")
        input("Press Enter...")
        return
    try:
        api.delete_alert(alert_id)
        print("Alert deleted successfully.")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
    input("Press Enter...")

def view_stats():
    q = query_builder.get_query()
    clear_screen()
    print("View Stats/Facets for Current Query")
    print("===================================")
    print("Enter a comma-separated list of facets to view.")
    print("For example: port, country, org")
    facets_input = input("Facets (e.g., port, country): ").strip()
    if not facets_input:
        print("No facets entered. Returning.")
        input("Press Enter...")
        return

    facets = [f.strip() for f in facets_input.split(',') if f.strip()]
    if not facets:
        print("No valid facets found.")
        input("Press Enter...")
        return

    try:
        facet_str = []
        for f in facets:
            facet_str.append(f"{f}:10")
        facet_query = q
        results = api.count(facet_query, facets=",".join(facet_str))
        print(f"Stats for Query: {facet_query}")
        print("="*50)
        if 'facets' in results:
            for f in facets:
                if f in results['facets']:
                    print(f"Top {f.capitalize()}s:")
                    for item in results['facets'][f]:
                        val, count = item['value'], item['count']
                        print(f"  {val}: {count}")
                    print("-"*50)
                else:
                    print(f"No data for facet '{f}'")
        else:
            print("No facet information returned.")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")

    input("Press Enter...")

# =============================================================================
# 18. Shodan Option - Using Sub-Menu
# =============================================================================
def shodan_lookup():
    """
    Instead of prompting for an API key or doing a simple host lookup,
    we'll launch the sub-menu approach you provided (KISS).
    """
    print("Launching Shodan KISS sub-menu...\n")
    input("Press Enter to continue...")
    sub_menu_shodan()

# =============================================================================
# Main Menu
# =============================================================================
def main_menu():
    ascii_art = r"""
    RRRR   EEEE   CCCC  CCCC  Y    Y
    R   R  E     C     C       Y  Y
    RRRR   EEEE  C     C        YY
    R  R   E   D C     C        YY
    R   R  EEEE   CCCC  CCCC    YY
    """
    print(ascii_art)
    print(Fore.RED + "\n    ---  KEV'S RECCY TOOLSET  ---" + Style.RESET_ALL)
    print(Fore.GREEN + "Domain Reconnaissance + WHOIS (system command)\n" + Style.RESET_ALL)
    print("1.  Perform DNS Lookup (A)")
    print("2.  Perform MX Lookup")
    print("3.  Perform NS Lookup")
    print("4.  Perform SOA Lookup")
    print("5.  Perform Reverse DNS Lookup")
    print("6.  WHOIS Lookup (system whois)")
    print("7.  Get All Information (DNS + WHOIS, raw output)")
    print("8.  Perform Zone Transfer")
    print("9.  Email Scraper")
    print("10. Brute Force Subdomains")
    print("11. Port Scan & Banner Grab")
    print("12. HTTP Header Inspection")
    print("13. robots.txt & sitemap.xml Parsing")
    print("14. SSL/TLS Certificate Information")
    print("15. DNSSEC Validation")
    print("16. Parse Webpage Comments")
    print("17. Google Dorks")
    print("18. Shodan Lookup (KISS Sub-Menu)")
    print("X.  Exit\n")

def main():
    while True:
        main_menu()
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            domain = input("Enter domain name: ").strip()
            dns_lookup(domain)
        elif choice == '2':
            domain = input("Enter domain name: ").strip()
            mx_lookup(domain)
        elif choice == '3':
            domain = input("Enter domain name: ").strip()
            ns_lookup(domain)
        elif choice == '4':
            domain = input("Enter domain name: ").strip()
            soa_lookup(domain)
        elif choice == '5':
            ip_address = input("Enter IP Address: ").strip()
            reverse_lookup(ip_address)
        elif choice == '6':
            domain = input("Enter domain name: ").strip()
            whois_lookup(domain)
        elif choice == '7':
            domain = input("Enter domain name: ").strip()
            get_all_information(domain)
        elif choice == '8':
            domain = input("Enter domain name: ").strip()
            zone_transfer(domain)
        elif choice == '9':
            email_scraper()
        elif choice == '10':
            domain = input("Enter domain name: ").strip()
            subdomains_file = input("Enter path to subdomain wordlist: ").strip()
            subdomain_brute_force(domain, subdomains_file)
        elif choice == '11':
            port_scan_banner()
        elif choice == '12':
            http_header_inspection()
        elif choice == '13':
            robots_sitemap_inspection()
        elif choice == '14':
            ssl_certificate_info()
        elif choice == '15':
            dnssec_validation()
        elif choice == '16':
            parse_web_comments()
        elif choice == '17':
            google_dorks()
        elif choice == '18':
            # Launch the Shodan KISS sub-menu
            shodan_lookup()
        elif choice.upper() == 'X':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 18 or 'X' to exit.")

if __name__ == "__main__":
    main()
