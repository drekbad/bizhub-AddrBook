#!/usr/bin/env python3
import argparse
import json
import requests
import sys
import os
import warnings

# Suppress "InsecureRequestWarning: Unverified HTTPS request is being made..." 
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Retrieve and parse the Konica Bizhub address book from one or more hosts."
    )
    
    # Create a mutually exclusive group so user can either supply an IP or a file, but not both
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="Single IP or hostname.")
    group.add_argument("-l", "--list", help="File containing a list of IPs/hosts (one per line).")

    parser.add_argument(
        "-c", "--cookie",
        help="Optional cookie string for the Bizhub session if needed (e.g. 'ID=abcdef123...').",
        default=None
    )
    parser.add_argument(
        "-n", "--names",
        action="store_true",
        help="If set, also dump the list of user names to bizhub-addrBk_names_<ip>.txt"
    )
    return parser.parse_args()

def get_address_book_data(ip, cookie=None):
    """
    Performs a POST request to https://<ip>/wcd/api/AppReqGetAbbr
    and returns parsed JSON (a dictionary) or None if an error occurs.
    """
    url = f"https://{ip}/wcd/api/AppReqGetAbbr"

    # Minimal headers that often suffice for this endpoint
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript",
    }
    
    # Prepare cookies if user supplies -c/--cookie
    cookies = {}
    if cookie:
        # User might pass "ID=abcdef123..."
        # We'll parse that to put it in the cookies dictionary.
        # If multiple name=value pairs are needed, expand this logic.
        try:
            name_val = cookie.split("=", 1)
            cookies[name_val[0]] = name_val[1]
        except IndexError:
            print("[!] Cookie format error; expected something like 'ID=abcdef123...'.", file=sys.stderr)
            return None
    
    try:
        # Some printers accept an empty POST body or an empty form
        response = requests.post(
            url,
            headers=headers,
            data={},             # or data="" if truly no body needed
            cookies=cookies,
            verify=False,        # ignoring SSL cert errors (self-signed likely)
            timeout=15
        )
        if response.status_code == 200:
            # Printer often returns large single-line JSON
            return json.loads(response.text)
        else:
            print(f"[!] Received unexpected HTTP status code {response.status_code} from {ip}", file=sys.stderr)
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to {ip}: {e}", file=sys.stderr)
        return None

def extract_names_and_emails(data):
    """
    Given the parsed JSON from the Bizhub address book,
    return two lists (or sets): (names, emails).
    """
    names = []
    emails = []
    
    # Typically the address book is in data["AbbrList"]["Abbr"]
    try:
        abbr_list = data["AbbrList"]["Abbr"]
    except (KeyError, TypeError):
        # Possibly no data or unexpected structure
        return names, emails
    
    for entry in abbr_list:
        # "Name" is top-level in each entry.
        name = entry.get("Name", "").strip()
        
        # "To" is typically in entry["SendConfiguration"]["AddressInfo"]["EmailMode"]["To"]
        try:
            to_email = entry["SendConfiguration"]["AddressInfo"]["EmailMode"]["To"].strip()
        except (KeyError, AttributeError):
            to_email = ""

        if name:
            names.append(name)
        if to_email:
            emails.append(to_email)
    
    return names, emails

def write_to_file(filename, items):
    """
    Write each item on its own line to the specified filename.
    """
    with open(filename, "w", encoding="utf-8") as f:
        for item in items:
            f.write(item + "\n")

def process_single_host(ip, cookie=None, dump_names=False):
    print(f"[*] Retrieving address book for host: {ip}")
    data = get_address_book_data(ip, cookie)
    if data is None:
        print(f"[!] No data retrieved from {ip}.")
        return  # Could not retrieve/parse
    
    names, emails = extract_names_and_emails(data)
    unique_names = sorted(set(names))
    unique_emails = sorted(set(emails))
    
    # If there's no data at all, skip file creation.
    if not unique_emails and not unique_names:
        print(f"[!] No valid address records found for {ip}. Skipping file creation.")
        return

    # Otherwise, we found something. Print summary:
    print(f"    Found {len(unique_names)} unique names.")
    print(f"    Found {len(unique_emails)} unique email addresses.")

    # If we have emails, write them to file
    if unique_emails:
        email_filename = f"bizhub-addrBk_emailAddr_{ip}.txt"
        write_to_file(email_filename, unique_emails)
        print(f"    Email addresses saved to: {email_filename}")
    
    # If dump_names and we have names, write them
    if dump_names and unique_names:
        names_filename = f"bizhub-addrBk_names_{ip}.txt"
        write_to_file(names_filename, unique_names)
        print(f"    Names saved to: {names_filename}")

    print("---------------------------------------\n")

def main():
    args = parse_arguments()
    
    # If user passes -i/--ip, handle just that host
    if args.ip:
        process_single_host(args.ip, args.cookie, args.names)
    
    # If user passes -l/--list, read IPs from the file line by line
    if args.list:
        if not os.path.isfile(args.list):
            print(f"[!] The file {args.list} does not exist.")
            sys.exit(1)
        
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    process_single_host(ip, args.cookie, args.names)

if __name__ == "__main__":
    main()
