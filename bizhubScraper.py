#!/usr/bin/env python3
import argparse
import requests
import json
import sys
import os
import warnings

# Suppress InsecureRequestWarning about verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Attempt a fully replicated Bizhub request to retrieve the address book.")
    parser.add_argument("-i", "--ip", required=True, help="IP or hostname of the Bizhub device.")
    parser.add_argument("-c", "--cookie", default=None,
                        help="Raw cookie string from your browser dev tools (everything after 'Cookie:').")
    parser.add_argument("-f", "--formdata", default=None,
                        help="Raw form data if the POST body is not empty. E.g. 'gAbbrStatus=0&someOtherKey=val'")
    parser.add_argument("-n", "--names", action="store_true",
                        help="Also output names (in addition to emails).")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
                        help="User-Agent string to send. Default mimics a modern Firefox.")
    parser.add_argument("--referer", default=None, help="Referer header to send.")
    parser.add_argument("--origin", default=None, help="Origin header to send.")
    return parser.parse_args()


def extract_names_and_emails(data):
    """
    Given the parsed JSON from the Bizhub address book,
    return two lists: (names, emails).
    """
    names = []
    emails = []
    
    # Some firmwares store data in data["AbbrList"]["Abbr"]
    # Others may differ. Adjust as needed.
    try:
        abbr_list = data["AbbrList"]["Abbr"]
    except (KeyError, TypeError):
        return names, emails
    
    for entry in abbr_list:
        name = entry.get("Name", "").strip()
        # Typically "To" is in entry["SendConfiguration"]["AddressInfo"]["EmailMode"]["To"]
        to_email = ""
        try:
            to_email = entry["SendConfiguration"]["AddressInfo"]["EmailMode"]["To"].strip()
        except (KeyError, AttributeError):
            pass

        if name:
            names.append(name)
        if to_email:
            emails.append(to_email)

    return names, emails


def main():
    args = parse_arguments()
    ip = args.ip

    # If user didn't provide an --origin, we can default to https://<ip>
    origin = args.origin if args.origin else f"https://{ip}"
    # If user didn't provide a --referer, we can default to the spa_main.html path
    referer = args.referer if args.referer else f"https://{ip}/wcd/spa_main.html"
    
    # Build the URL
    url = f"https://{ip}/wcd/api/AppReqGetAbbr"
    
    # Build the headers.  
    # NOTE: If your dev tools show more headers, add them here (Accept-Language, Accept-Encoding, etc).
    headers = {
        "User-Agent": args.user_agent,
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Origin": origin,
        "Referer": referer,
    }
    
    # If user has a raw cookie string, put it in the "Cookie" header.
    # e.g. "selno=En; lang=En; vm=Html; ID=...; bv=Firefox/128.0; ..."
    if args.cookie:
        headers["Cookie"] = args.cookie

    # The form data (body). If not given, we default to empty string.
    # But on some devices you absolutely must pass something that the dev tools show.
    form_data = args.formdata if args.formdata else ""

    print(f"[*] Sending POST to {url}")
    print(f"[*] Using Cookie: {args.cookie}")
    print(f"[*] Using Form Data: {form_data}\n")

    try:
        response = requests.post(
            url,
            headers=headers,
            data=form_data,
            verify=False,
            timeout=15
        )
        print(f"[+] HTTP {response.status_code} received.\n")
        if response.status_code == 200:
            # Attempt to parse JSON
            try:
                data_json = response.json()
            except json.JSONDecodeError:
                print("[!] The response body does not appear to be valid JSON.")
                print("[!] Response body snippet:\n", response.text[:500])
                sys.exit(1)
            
            # Extract names and emails
            names, emails = extract_names_and_emails(data_json)
            unique_names = sorted(set(names))
            unique_emails = sorted(set(emails))

            if not unique_names and not unique_emails:
                print("[!] No address book data found or the device returned an empty set.")
                sys.exit(0)
            
            print(f"Found {len(unique_names)} unique names.")
            print(f"Found {len(unique_emails)} unique emails.")

            # Write emails to file
            if unique_emails:
                email_filename = f"bizhub-addrBk_emailAddr_{ip}.txt"
                with open(email_filename, "w", encoding="utf-8") as f:
                    for e in unique_emails:
                        f.write(e + "\n")
                print(f"[+] Email addresses written to: {email_filename}")

            # Optionally write names
            if args.names and unique_names:
                names_filename = f"bizhub-addrBk_names_{ip}.txt"
                with open(names_filename, "w", encoding="utf-8") as f:
                    for n in unique_names:
                        f.write(n + "\n")
                print(f"[+] Names written to: {names_filename}")
        else:
            print(f"[!] Received HTTP {response.status_code} instead of 200.")
            print("    Response text (partial):", response.text[:500])
    except requests.exceptions.RequestException as e:
        print(f"[!] Error while connecting or sending request: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
