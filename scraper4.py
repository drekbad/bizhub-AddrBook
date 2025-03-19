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


def get_address_book(ip, cookie, protocol, debug
