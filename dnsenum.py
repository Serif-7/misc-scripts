#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "bs4",
#     "dnspython",
#     "netaddr",
#     "requests",
#     "whois",
# ]
# ///
"""
DNSEnum - DNS Enumeration Tool
Version: 1.0.0

A Python port of the original dnsenum.pl script for DNS enumeration and network reconnaissance.
This tool performs various DNS queries to gather information about a domain including:
- Host addresses
- Nameservers
- MX records
- Zone transfers
- Google scraping for subdomains
- Brute force subdomain discovery
- Network range analysis
- Reverse DNS lookups

Original perl script copyright (C) 2014 - Filip Waeytens, tixxDZ
Python port created 2025 by Serif
"""

import argparse
import concurrent.futures
import csv
import dns.resolver
import dns.zone
import dns.query
import ipaddress
import json
import logging
import random
import re
import string
import sys
import time
from bs4 import BeautifulSoup
import requests
from netaddr import IPNetwork, IPAddress
import whois

class Colors:
    """ANSI color codes for terminal output"""
    BLUE = '\033[94m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class DNSEnum:
    def __init__(self, domain, args):
        """Initialize DNS enumeration with domain and configuration"""
        self.domain = domain.lower()
        self.args = args
        self.nameservers = set()
        self.subdomains = set()
        self.mx_servers = set()
        self.ip_addresses = set()
        self.netranges = set()
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        if args.dnsserver:
            self.resolver.nameservers = [args.dnsserver]
        self.resolver.timeout = args.timeout
        self.resolver.lifetime = args.timeout

        # Configure logging
        logging.basicConfig(
            level = logging.DEBUG if args.verbose else logging.INFO,
            format = '%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def print_header(self, text):
        """Print formatted header text"""
        if not self.args.nocolor:
            print(f"\n\n{Colors.RED}{text}{'_' * len(text)}\n{Colors.RESET}\n")
        else:
            print(f"\n\n{text}{'_' * len(text)}\n\n")

    def get_host_addresses(self):
        """Get the host's A records"""
        self.print_header("Host's addresses:")
        try:
            answers = self.resolver.resolve(self.domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                print(f"{self.domain}    A    {ip}")
                self.ip_addresses.add(ip)
        except dns.exception.DNSException as e:
            self.logger.error(f"Failed to get A records: {e}")

    def check_wildcards(self):
        """Test for DNS wildcard records"""
        self.print_header("Wildcards test:")
        random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=12))
        test_domain = f"{random_subdomain}.{self.domain}"
        
        try:
            answers = self.resolver.resolve(test_domain, 'A')
            wildcard_ips = set(str(rdata) for rdata in answers)
            
            if wildcard_ips:
                print(f"\n!!! Wildcards detected, all subdomains will point to: {', '.join(wildcard_ips)}")
                print("Consider using another DNS server or validate results manually\n")
                return wildcard_ips
            return set()
        except dns.exception.DNSException:
            self.logger.debug("No wildcards detected")
            return set()

    def get_nameservers(self):
        """Get domain nameservers"""
        self.print_header("Name Servers:")
        try:
            answers = self.resolver.resolve(self.domain, 'NS')
            for rdata in answers:
                ns = str(rdata.target).rstrip('.')
                self.nameservers.add(ns)
                print(f"{self.domain}    NS    {ns}")
                
                # Get A records for nameservers
                try:
                    ns_answers = self.resolver.resolve(ns, 'A')
                    for ns_rdata in ns_answers:
                        print(f"{ns}    A    {str(ns_rdata)}")
                except dns.exception.DNSException:
                    self.logger.debug(f"Could not resolve nameserver {ns}")
        except dns.exception.DNSException as e:
            self.logger.error(f"Failed to get NS records: {e}")
            sys.exit(1)

    def get_mx_records(self):
        """Get domain MX records"""
        self.print_header("Mail (MX) Servers:")
        try:
            answers = self.resolver.resolve(self.domain, 'MX')
            for rdata in answers:
                mx = str(rdata.exchange).rstrip('.')
                self.mx_servers.add(mx)
                print(f"{self.domain}    MX    {mx}")
                
                # Get A records for MX servers
                try:
                    mx_answers = self.resolver.resolve(mx, 'A')
                    for mx_rdata in mx_answers:
                        print(f"{mx}    A    {str(mx_rdata)}")
                except dns.exception.DNSException:
                    self.logger.debug(f"Could not resolve MX server {mx}")
        except dns.exception.DNSException as e:
            self.logger.debug(f"No MX records found: {e}")

    def try_zone_transfer(self):
        """Attempt zone transfers from nameservers"""
        self.print_header("Trying Zone Transfers:")
        for ns in self.nameservers:
            try:
                print(f"\nTrying Zone Transfer for {self.domain} on {ns}...")
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns, self.domain, lifetime=self.args.timeout)
                )
                for name, node in zone.nodes.items():
                    name = str(name)
                    if name != '@':
                        subdomain = f"{name}.{self.domain}"
                        self.subdomains.add(subdomain)
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                print(f"{subdomain}    {dns.rdatatype.to_text(rdataset.rdtype)}    {str(rdata)}")
            except Exception as e:
                self.logger.debug(f"Zone transfer failed for {ns}: {e}")

    def google_scraping(self):
        """Scrape subdomains from Google search results"""
        if not self.args.scrap:
            return

        self.print_header(f"Scraping {self.domain} subdomains from Google:")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        found = set()
        
        for page in range(self.args.pages):
            try:
                query = f"site:{self.domain} -www"
                url = f"https://www.google.com/search?q={query}&start={page * 10}"
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = soup.find_all('a')
                    
                    for link in links:
                        href = link.get('href', '')
                        # match = re.search(f'(?:https?://)?([a-zA-Z0-9.-]+\.{self.domain})', href)
                        match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', href)
                        if match and match.group(1) not in found:
                            subdomain = match.group(1)
                            found.add(subdomain)
                            print(f"Found: {subdomain}")
                            if len(found) >= self.args.scrap:
                                return
                    
                    time.sleep(random.uniform(2, 5))  # Be nice to Google
                else:
                    self.logger.warning("Google may be blocking our requests")
                    return
            except Exception as e:
                self.logger.error(f"Google scraping error: {e}")
                return

    def brute_force_subdomains(self):
        """Brute force subdomains using provided wordlist"""
        if not self.args.file:
            return
            
        self.print_header(f"Brute forcing with {self.args.file}:")
        try:
            with open(self.args.file, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Could not read wordlist file: {e}")
            return

        wildcard_ips = self.check_wildcards()
        
        def check_subdomain(word):
            subdomain = f"{word}.{self.domain}"
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    if ip not in wildcard_ips:
                        return (subdomain, ip)
            except dns.exception.DNSException:
                pass
            return None

        # Use ThreadPoolExecutor for parallel subdomain checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(check_subdomain, word) for word in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ip = result
                    print(f"{subdomain}    A    {ip}")
                    self.subdomains.add(subdomain)
                    self.ip_addresses.add(ip)

    def analyze_network_ranges(self):
        """Analyze discovered IP addresses and perform network range analysis"""
        if not self.ip_addresses:
            return

        self.print_header("Network Ranges Analysis:")
        
        # Group IPs by /24 network
        networks = {}
        for ip in self.ip_addresses:
            if not ipaddress.ip_address(ip).is_private:
                network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                if network not in networks:
                    networks[network] = set()
                networks[network].add(ip)

        # Perform whois queries if requested
        if self.args.whois:
            for network in networks:
                try:
                    w = whois.whois(network)
                    if w.nets:
                        for net in w.nets:
                            cidr = net.get('cidr')
                            if cidr:
                                print(f"Network: {network} → CIDR: {cidr}")
                                self.netranges.add(cidr)
                    time.sleep(random.uniform(1, self.args.delay))
                except Exception as e:
                    self.logger.debug(f"Whois query failed for {network}: {e}")
                    self.netranges.add(network)
        else:
            self.netranges.update(networks.keys())

    def reverse_dns_lookup(self):
        """Perform reverse DNS lookups on discovered IP ranges"""
        if self.args.noreverse:
            return

        self.print_header("Performing Reverse DNS Lookups:")
        
        def reverse_lookup(ip):
            try:
                answers = self.resolver.resolve_address(ip)
                for rdata in answers:
                    hostname = str(rdata.target).rstrip('.')
                    if self.domain in hostname:
                        if not self.args.exclude or not re.search(self.args.exclude, hostname):
                            return (ip, hostname)
            except Exception:
                pass
            return None

        for network in self.netranges:
            print(f"\nChecking network {network}:")
            try:
                ip_list = [str(ip) for ip in IPNetwork(network)]
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                    futures = [executor.submit(reverse_lookup, ip) for ip in ip_list]
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if result:
                            ip, hostname = result
                            print(f"{ip}    PTR    {hostname}")
            except Exception as e:
                self.logger.error(f"Error processing network {network}: {e}")

    def save_results(self):
        """Save results to output files"""
        # Save IP blocks
        with open(f"{self.domain}_ips.txt", 'w') as f:
            for network in sorted(self.netranges):
                f.write(f"{network}\n")

        # Save subdomains if requested
        if self.args.subfile:
            with open(self.args.subfile, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")

def main():
    parser = argparse.ArgumentParser(description='DNS enumeration tool')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--dnsserver', help='Use this DNS server for queries')
    parser.add_argument('--enum', action='store_true', help='Equivalent to --threads 5 -s 15 -w')
    parser.add_argument('--noreverse', action='store_true', help='Skip reverse lookup operations')
    parser.add_argument('--nocolor', action='store_true', help='Disable color output')
    parser.add_argument('-f', '--file', help='Read subdomains from this file')
    parser.add_argument('-s', '--scrap', type=int, default=15, help='Maximum number of subdomains to scrape')
    parser.add_argument('-p', '--pages', type=int, default=5, help='Number of Google pages to process')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout for DNS queries')
    parser.add_argument('-w', '--whois', action='store_true', help='Perform whois queries')
    parser.add_argument('-d', '--delay', type=int, default=3, help='Delay between whois queries')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-e', '--exclude', help='Exclude PTR records matching regex')
    parser.add_argument('--subfile', help='Save subdomains to this file')

    args = parser.parse_args()

    # Apply enum shortcut
    if args.enum:
        args.threads = 5
        args.scrap = 15
        args.whois = True

    try:
        enumerator = DNSEnum(args.domain, args)
        
        # Perform enumeration steps
        print(f"\n----- {args.domain} -----\n")
        
        enumerator.get_host_addresses()
        enumerator.get_nameservers()
        enumerator.get_mx_records()
        enumerator.try_zone_transfer()
        
        if args.scrap:
            enumerator.google_scraping()
            
        if args.file:
            enumerator.brute_force_subdomains()
        else:
            print("\nBrute force file not specified, skipping subdomain brute force.")
            
        enumerator.analyze_network_ranges()
        enumerator.reverse_dns_lookup()
        enumerator.save_results()
        
        print("\nEnumeration completed. Results saved to files:")
        print(f"- IP ranges: {args.domain}_ips.txt")
        if args.subfile:
            print(f"- Subdomains: {args.subfile}")

    except KeyboardInterrupt:
        print("\nEnumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during enumeration: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
