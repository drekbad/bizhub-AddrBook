#!/usr/bin/env python3
import argparse
import json
import requests
import sys
import os

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Retrieve and parse the Konica Bizhub address book from one or more hosts."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-h", "--host", help="Single host IP or hostname.")
    group.add_argument("-i", "--input", help="File containing a list of IPs/hosts (one per line).")
    
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

    # Minimal headers that are often enough for this endpoint
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript",
    }
    
    # Prepare a cookies dict if the user supplies -c/--cookie
    cookies = {}
    if cookie:
        # The user might pass something like "ID=abcdef123..."
        # We'll parse that to put it in the cookies dictionary.
        # If the user passes multiple name=value pairs, you'd have to expand this logic.
        try:
            name_val = cookie.split("=")
            cookies[name_val[0]] = "=".join(name_val[1:])
        except IndexError:
            print("Cookie format error; expected something like 'ID=abcdef123...'.", file=sys.stderr)
    
    try:
        # Some printers simply accept an empty POST body or an empty form, so let's send minimal data.
        response = requests.post(
            url, 
            headers=headers,
            data={},            # or data="" if truly no body
            cookies=cookies,
            verify=False,       # ignore SSL cert errors (self-signed likely)
            timeout=15
        )
        if response.status_code == 200:
            # The printer often returns a large single-line JSON. Let's try to parse it.
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
    return two lists or sets: (names, emails).
    """
    names = []
    emails = []
    
    # The relevant portion is typically data["AbbrList"]["Abbr"], which is a list of addresses
    try:
        abbr_list = data["AbbrList"]["Abbr"]
    except KeyError:
        # The structure may be different or no data returned
        return names, emails
    
    for entry in abbr_list:
        # "Name" is top-level. "To" is inside entry["SendConfiguration"]["AddressInfo"]["EmailMode"]["To"]
        name = entry.get("Name", "").strip()
        # Pull out the "To" email field. 
        # In some Bizhub firmwares, it might be under entry["SendConfiguration"]["EmailAddress"] directly or so.
        # Adjust if you see your JSON is different.
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
    data = get_address_book_data(ip, cookie)
    if data is None:
        return  # Could not retrieve/parse
    
    names, emails = extract_names_and_emails(data)
    unique_names = sorted(set(names))
    unique_emails = sorted(set(emails))
    
    # Write out the email addresses
    email_filename = f"bizhub-addrBk_emailAddr_{ip}.txt"
    write_to_file(email_filename, unique_emails)
    
    # Optionally write out the names
    if dump_names:
        names_filename = f"bizhub-addrBk_names_{ip}.txt"
        write_to_file(names_filename, unique_names)
    
    # Print summary
    print(f"\nHost: {ip}")
    print("---------------------------------------")
    print(f"  Found {len(unique_names)} unique names.")
    print(f"  Found {len(unique_emails)} unique email addresses.")
    print(f"  Email list written to: {email_filename}")
    if dump_names:
        print(f"  Names list written to: {names_filename}")
    print("---------------------------------------\n")

def main():
    args = parse_arguments()
    
    # If user passes -h, handle just that host
    if args.host:
        process_single_host(args.host, args.cookie, args.names)
    
    # If user passes -i, read IPs from the file line by line
    if args.input:
        if not os.path.isfile(args.input):
            print(f"[!] The file {args.input} does not exist.")
            sys.exit(1)
        
        with open(args.input, "r", encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    process_single_host(ip, args.cookie, args.names)

if __name__ == "__main__":
    main()
