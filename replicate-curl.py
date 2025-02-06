#!/usr/bin/env python3
import requests
import json
import sys

# Suppress InsecureRequestWarning because we're using verify=False 
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.simplefilter("ignore", InsecureRequestWarning)

def main():
    # Replace with your actual host/IP
    url = "https://10.20.30.65/wcd/api/AppReqGetAbbr"
    
    # Replace with the exact raw JSON from your working cURL:
    payload = '{"AbbrListCondition":{"WellUse":"false","SearchKey":"None","ObtainCondition":{"Type":"IndexList","IndexRange":{"Start":1,"End":50}},"SortInfo":{"Condition":"No","Order":"Ascending"},"AddressKind":"Public","SearchSendMode":"0"}}'
    
    # Replace with the exact 'ID=...' value from your working cURL.
    # If in cURL you did: `-H 'Cookie: ID=0V/cpC1...'`, just paste that.
    cookie_string = "ID=0V/cpC1Wvck5s1rv2... (whatever your valid ID is)"

    # Minimal headers. If your cURL had more, you can add them:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Cookie": cookie_string
    }

    try:
        resp = requests.post(
            url,
            headers=headers,
            data=payload,   # same as --data-raw in cURL
            verify=False    # same as curl -k
        )
        print(f"HTTP {resp.status_code}")
        if resp.status_code == 200:
            # Try parsing JSON
            try:
                data_json = resp.json()
                print("Parsed JSON, top-level keys:", list(data_json.keys()))
                print()
                print("Full JSON (truncated to 500 chars):")
                print(resp.text[:500])
                
                # If you want to see everything, comment the line above 
                # and just do: print(resp.text)

            except json.JSONDecodeError:
                print("Received 200 but not valid JSON. Response snippet:")
                print(resp.text[:500])
        else:
            print("Non-200 status. Response snippet:")
            print(resp.text[:500])

    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
