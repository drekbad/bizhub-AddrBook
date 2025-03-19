#!/usr/bin/env python3
import argparse
import requests
import sys
import os
import xml.etree.ElementTree as ET

# Suppress "InsecureRequestWarning" about verify=False
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

CHUNK_SIZE = 50  # Fetch records in increments of 50
MAX_ENTRIES = 2000  # Max limit the device supports
ALL_EMAILS_FILE = "ALL-BizHub-Emails.txt"

def parse_args():
    parser = argparse.ArgumentParser(description="Fetch full address book from internal network printers (Bizhub).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP or hostname.")
    group.add_argument("--list", help="File containing a list of IPs/hosts (one per line).")
    parser.add_argument("-d", "--debug", action="store_true", help="Print debug info, including response details and cookie info.")
    return parser.parse_args()

# (Functions like auto_get_cookie, fetch_abbr_chunk, request_next_page, parse_xml remain unchanged)

def process_host(host, debug=False):
    """Handles full address book extraction for a single host."""
    session, protocol, cookie_value = auto_get_cookie(host, debug=debug)
    if not session:
        return None

    abbr_list = fetch_all_abbr(host, protocol, session, cookie_value, debug=debug)

    if not abbr_list:
        print(f"[!] No address book entries found for {host}.")
        return None

    output_file = f"{host}_addrbook.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for name, email in abbr_list:
            f.write(f"{name},{email}\n")

    print(f"[+] Extracted {len(abbr_list)} records from {host} -> {output_file}")
    return output_file  # Return filename for aggregation

def aggregate_unique_emails(file_list):
    """Read all extracted files and create a unique sorted email list."""
    unique_emails = set()

    for file in file_list:
        if os.path.exists(file):
            with open(file, "r", encoding="utf-8") as f:
                for line in f:
                    _, email = line.strip().split(",", 1)
                    if email and email != "No Email":
                        unique_emails.add(email)

    if unique_emails:
        sorted_emails = sorted(unique_emails)
        with open(ALL_EMAILS_FILE, "w", encoding="utf-8") as f:
            for email in sorted_emails:
                f.write(email + "\n")

        print(f"[+] Created unique email list: {ALL_EMAILS_FILE} ({len(sorted_emails)} unique emails)")
    else:
        print("[!] No valid email addresses found across devices.")

def main():
    parser = parse_args()
    hosts = [parser.ip] if parser.ip else open(parser.list).read().splitlines()

    extracted_files = []
    for host in hosts:
        host = host.strip()
        if host:
            file = process_host(host, debug=parser.debug)
            if file:
                extracted_files.append(file)

    if extracted_files:
        aggregate_unique_emails(extracted_files)

if __name__ == "__main__":
    main()
