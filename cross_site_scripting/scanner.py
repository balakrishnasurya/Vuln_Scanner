import requests
import csv
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from cross_site_scripting.form_utils import get_all_forms, get_form_details
from cross_site_scripting.submit import submit_form


def scan_xss(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    try:
        # get all the forms from the URL
        forms = get_all_forms(url)
        #print(f"[+] Detected {len(forms)} forms on {url}.")

        # read XSS payloads from file
        with open("misc/xss_payloads.txt", "r") as f:
            payloads = f.read().splitlines()

        # returning value
        is_vulnerable = False

        # iterate over all forms
        for form in forms:
            if is_vulnerable:
                break  # stop scanning if XSS is already found

            form_details = get_form_details(form)

            # iterate over all payloads
            for payload in payloads:
                content = submit_form(form_details, url, payload).content.decode()
                if payload in content:

                    print(f"\n------------------------------------------------------------------------------------------------\n")
                    print(f"[!] Vulnerability Found: A03:Injection - Cross Site Scripting (XSS)")
                    print(f"\tURL:\t\t{urljoin(url, form_details['action'])}")
                    print(f"\tPayload:\t{payload}")
                    print(f"\tSeverity:\tCritical\n")


                    is_vulnerable = True
                    
                    # save results to CSV file
                    with open("results.csv", "a", newline="") as f:
                        writer = csv.DictWriter(f, fieldnames=["Vulnerability", "URL", "Severity"])
                        writer.writerow({"Vulnerability": "XSS", "URL": urljoin(url, form_details['action']), "Severity": "Critical"})
                    
                    break  # stop trying payloads if XSS is found on this form

        return is_vulnerable
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"[-] An error occurred while scanning {url}: {str(e)}")
        return False
