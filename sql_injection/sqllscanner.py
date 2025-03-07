import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
import csv
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

# Initializes an HTTP session & sets the browser
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/573.36 (KHTML, like Gecko) " \
                          "Chrome/83.0.4103.106 Safari/537.36 "

# Since SQL injection is all about user inputs, we will need to extract web forms first.
def get_all_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}

    try:
        action = form.attrs.get("action").lower()

    except:
        action = None

    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    errors = {
        # MySQL
        "error in sql syntax;",
        "warning: mysql",
    }

    for error in errors:
        if error in response.content.decode().lower():
            return True

    # No error detected;
    return False

def scan_sql_injection(url):
    with open('results.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        #writer.writerow(['SQL', 'URL', 'Severity'])

        for c in "\"'":
            new_url = f"{url}{c}"
            #print("[!] Trying", new_url)
            res = s.get(new_url)

            if is_vulnerable(res):
                #print("[+] SQL Injection vulnerability detected, link:", new_url)
                
                print(f"\n------------------------------------------------------------------------------------------------\n")
                print(f"[!] Vulnerability Found: A03:SQL Injection (SQLi)")
                print(f"\tURL:\t\t{new_url}")
                print(f"\tSeverity:\tHigh\n")

                writer.writerow(['SQL', new_url, 'High'])
                return

    forms = get_all_forms(url)
    #print(f"[+] Detected {len(forms)} forms on {url}.")

    #if len(forms) > 0:
        #print(f"[+] Possible SQL Injection Vuln on {url}")
    #else:
        #print(f"[-] No forms were detected on {url}")


    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c

                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{c}"

            url = urljoin(url, form_details["action"])

            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)

def scan_sql():
#if __name__ == "__main__":
    with open('misc/url.txt', 'r') as f:
        urls = f.read().splitlines()
    for url in urls:
        scan_sql_injection(url)



