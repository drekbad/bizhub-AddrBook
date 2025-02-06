#!/usr/bin/env python3
import requests
import json
import sys

# If self-signed SSL, we disable certificate verification (same as curl -k)
# and ignore the warning that comes with it
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

def main():
    url = "https://10.20.30.65/wcd/api/AppReqGetAbbr"
    
    # The same raw JSON that you put in --data-raw
    # If your device returns only 50 at a time, you can keep Start=1, End=50.
    # Or try increasing End=9999 if the device supports a larger range in one go.
    payload = '{"AbbrListCondition":{"WellUse":"false","SearchKey":"None","ObtainCondition":{"Type":"IndexList","IndexRange":{"Start":1,"End":50}},"SortInfo":{"Condition":"No","Order":"Ascending"},"AddressKind":"Public","SearchSendMode":"0"}}'
    
    # These headers match the curl command line. 
    # Adjust them to exactly match what you see in dev tools or what works in curl.
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "application/json, text/Javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://10.20.30.65",
        "Referer": "https://10.20.30.65/wcd/spa_main.html",
        "Cookie": "ID=0V/cpC1Wvck5s1rv2... (etc.)",  # Replace with the actual ID cookie
        # If the device actually needs the other cookie keys, put them all here:
        # "Cookie": "selno=En; vm=Html; lang=En; ID=xxxxx; bv=Firefox/128.0; ..."
    }
    
    try:
        resp = requests.post(
            url,
            headers=headers,
            data=payload,      # data= means we're sending raw body (like --data-raw)
            verify=False,      # same as curl -k
            timeout=20
        )
        print(f"HTTP {resp.status_code} returned.\n")

        if resp.status_code == 200:
            # Try to parse JSON
            try:
                data_json = resp.json()
                print("Successfully parsed JSON. Keys at top level:\n", list(data_json.keys()))
                
                # Here, you can do the name/email extraction as needed
                # For instance:
                abbr_list = data_json["AbbrList"]["Abbr"]
                for entry in abbr_list:
                    name = entry.get("Name", "")
                    # Attempt to retrieve the email
                    try:
                        email = entry["SendConfiguration"]["AddressInfo"]["EmailMode"]["To"]
                    except KeyError:
                        email = ""
                    print(f"Name: {name}   Email: {email}")
                
            except json.JSONDecodeError:
                print("Response was 200 but not valid JSON. Text:\n", resp.text[:500])
        else:
            print("Response body snippet:\n", resp.text[:500])
    
    except requests.exceptions.RequestException as e:
        print(f"Error in POST request: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
