import os
import requests
import logging
import csv

logging.basicConfig(level=logging.INFO)

def scan_lfi(url):

    # Read PHP files list from "misc/files.txt"
    php_file = os.path.join("misc", "files.txt")
    with open(php_file, "r") as php_files:
        php_files = php_files.read().splitlines()

    # Read GET parameters list from "misc/files.txt"
    n1file = os.path.join("misc", "files.txt")
    with open(n1file, "r") as files:
        files = files.read().splitlines()

    # Read payloads list from "misc/payload.txt"
    payload_file = os.path.join("misc", "payload.txt")
    with open(payload_file, "r") as payloads:
        payloads = payloads.read().splitlines()

    with open("results.csv", mode='a', newline='') as csv_file:
        fieldnames = ['Vulnerability', 'URL', 'Severity']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for payload in payloads:
            payload = payload.strip()
            #logging.info(f"Trying payload: {payload}")
            for file in files:
                file = file.strip()
                for php in php_files:
                    php = php.strip()
                    target_url = f"{url}{php}?{file}={payload}"
                    #logging.info(f"Scanning: {target_url}")
                    response = requests.get(target_url)
                    if "root:x" in response.text:
                        print(f"\n------------------------------------------------------------------------------------------------\n")
                        print(f"[!] Vulnerability Found: A01:Broken Access Control - Local File Inclusion")
                        writer.writerow({'Vulnerability': 'Local File Inclusion', 'URL': target_url, 'Severity': 'Critical'})
                        print(f"\tURL:\t\t{target_url}")
                        print(f"\tURI:\t\t{url}{php}?{file}")
                        print(f"\tPayload:\t{payload}")
                        print(f"\tSeverity:\tCritical\n")
                        print(f"\n------------------------------------------------------------------------------------------------\n")
                        return
                    #else:
                        #logging.info(f"LFI not found in {target_url}")