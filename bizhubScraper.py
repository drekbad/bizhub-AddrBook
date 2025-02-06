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

CHUNK_SIZE = 50  # number of entries to request each time

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
        help="Print debug info, including response details and cookie info."
    )
    return parser.parse_args()

def auto_get_cookie(host, debug=False):
    """
    Perform a GET to https://<host>/wcd/index.html to see if the device sets an 'ID' cookie automatically.
    Return a requests.Session (with cookie) if success, or None if no 'ID' was set.
    """
    url = f"https://{host}/wcd/index.html"
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

def fetch_abbr_chunk(host, session=None, cookie_value=None, start=1, end=50, debug=False):
    """
    Fetch one chunk (start..end) from /wcd/api/AppReqGetAbbr.
    Returns the parsed JSON dict (or None on failure).
    Only sets a minimal Cookie: ID=... if cookie_value is provided,
    or uses session cookies if session is provided.
    """
    url = f"https://{host}/wcd/api/AppReqGetAbbr"

    # The JSON body for obtaining a chunk
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

    # We'll send it as JSON string. Some devices want this even though they say x-www-form-urlencoded.
    # If your device truly wants raw JSON in data=..., do json.dumps(payload).
    data_str = json.dumps(payload)

    # Minimal approach: If session is provided, do session.post(...).
    # Otherwise, do requests.post with a cookies dict.
    try:
        if session:
            if debug:
                print(f"[DEBUG] fetch_abbr_chunk {start}-{end} using session cookie(s).")
            resp = session.post(url, data=data_str, verify=False, timeout=15)
        else:
            # Build a minimal cookie dict if we have cookie_value
            cookie_dict = {}
            if cookie_value:
                # If user gave "ID=someval", parse out "someval"
                val = cookie_value
                if val.startswith("ID="):
                    val = val[3:]
                cookie_dict["ID"] = val.strip()

            if debug:
                print(f"[DEBUG] fetch_abbr_chunk {start}-{end} with cookie:", cookie_dict)
            resp = requests.post(url, data=data_str, cookies=cookie_dict, verify=False, timeout=15)

        if debug:
            print(f"[DEBUG] chunk {start}-{end} -> HTTP {resp.status_code}")
            # print entire body if you want to see everything:
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

def fetch_all_abbr(host, session=None, cookie_value=None, debug=False):
    """
    Fetch all address entries by chunking in increments of CHUNK_SIZE (50).
    Returns (allAbbrList, arraySize) or ([], 0) if nothing found or error.
    The device usually provides "ArraySize" to tell total number of entries.
    """
    all_abbr = []
    current_start = 1
    total_size = 0

    # First chunk
    data = fetch_abbr_chunk(host, session=session, cookie_value=cookie_value, start=current_start,
                            end=current_start + CHUNK_SIZE - 1, debug=debug)
    if not data:
        return ([], 0)

    # The real structure might be data["MFP"]["AbbrList"]...
    # So let's unify that logic: 
    mfp_obj = data.get("MFP")
    if mfp_obj and "AbbrList" in mfp_obj:
        abbr_list_data = mfp_obj["AbbrList"]
    elif "AbbrList" in data:
        abbr_list_data = data["AbbrList"]
    else:
        # No address data found
        return ([], 0)

    # ArraySize is typically a string, let's parse it
    array_size_str = abbr_list_data.get("ArraySize", "0")
    try:
        total_size = int(array_size_str)
    except ValueError:
        total_size = 0

    # The actual chunk of entries is in abbr_list_data["Abbr"]
    first_chunk_abbr = abbr_list_data.get("Abbr", [])
    all_abbr.extend(first_chunk_abbr)

    if debug:
        print(f"[DEBUG] chunk 1 -> got {len(first_chunk_abbr)} entries. ArraySize={total_size} (from device).")

    # If there's more than we got in the first chunk, keep requesting
    while len(first_chunk_abbr) == CHUNK_SIZE and (total_size > len(all_abbr)):
        current_start += CHUNK_SIZE
        next_end = current_start + CHUNK_SIZE - 1

        data = fetch_abbr_chunk(host, session=session, cookie_value=cookie_value,
                                start=current_start, end=next_end, debug=debug)
        if not data:
            break

        # parse the "MFP" or top-level "AbbrList"
        mfp_obj = data.get("MFP")
        if mfp_obj and "AbbrList" in mfp_obj:
            abbr_list_data = mfp_obj["AbbrList"]
        elif "AbbrList" in data:
            abbr_list_data = data["AbbrList"]
        else:
            break

        chunk_abbr = abbr_list_data.get("Abbr", [])
        all_abbr.extend(chunk_abbr)

        if debug:
            print(f"[DEBUG] chunk {current_start}-{next_end} -> got {len(chunk_abbr)} entries.")
            print(f"[DEBUG] Total so far: {len(all_abbr)}")

        if len(chunk_abbr) < CHUNK_SIZE:
            # There's nothing more to fetch
            break

    return (all_abbr, total_size)

def extract_names_and_emails(abbr_entries):
    """
    abbr_entries is the combined list of address records from all chunks.
    Return (names, emails).
    Each entry typically has "Name" and then "SendConfiguration" -> "AddressInfo" -> "EmailMode" -> "To".
    """
    names = []
    emails = []

    for entry in abbr_entries:
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

    return (names, emails)

def process_host(host, cookie=None, dump_names=False, debug=False):
    print(f"\n[*] Processing host: {host}")

    # Step 1: if user didn't provide --cookie, we attempt auto-get
    session = None
    cookie_value = cookie
    if cookie_value:
        if debug:
            print(f"[DEBUG] Using user-supplied cookie: {cookie_value}")
    else:
        session = auto_get_cookie(host, debug=debug)
        if not session:
            print(f"[!] Could not retrieve an ID cookie automatically from {host}. Skipping.")
            return

    # Step 2: fetch all address entries in chunks
    abbr_list, array_size = fetch_all_abbr(host, session=session, cookie_value=cookie_value, debug=debug)

    if debug:
        print(f"[DEBUG] Completed chunking. Collected {len(abbr_list)} total entries from {host}.")

    if len(abbr_list) == 0:
        print("    [!] Found no address book entries.")
        return

    # Step 3: parse out names/emails
    names, emails = extract_names_and_emails(abbr_list)
    unique_names = sorted(set(names))
    unique_emails = sorted(set(emails))

    if debug:
        print(f"[DEBUG] parse_abbr -> found {len(unique_names)} unique names, {len(unique_emails)} unique emails.")

    # Step 4: If array_size is > 0 but doesn't match the total abbr_list length, show a warning
    if array_size > 0 and array_size != len(abbr_list):
        print(f"[!] WARNING: Device reported ArraySize={array_size} but we only retrieved {len(abbr_list)} entries.")

    # Step 5: Summaries / file output
    if not unique_names and not unique_emails:
        print("    [!] Found no email addresses and no names.")
        return

    print(f"    Found {len(unique_names)} unique names.")
    print(f"    Found {len(unique_emails)} unique email addresses.")

    # If we have emails, write them
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

    if args.ip:
        process_host(args.ip, cookie=args.cookie, dump_names=args.names, debug=args.debug)
    elif args.list:
        if not os.path.isfile(args.list):
            print(f"[!] The file {args.list} does not exist.")
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                host = line.strip()
                if host:
                    process_host(host, cookie=args.cookie, dump_names=args.names, debug=args.debug)

if __name__ == "__main__":
    main()
