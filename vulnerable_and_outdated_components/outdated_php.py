import requests
import csv

def check_php_version(url):
    with open('results.csv', 'a', newline='') as file:
        writer = csv.writer(file)

        response = requests.get(url)
        headers = response.headers

        if 'X-Powered-By' in headers:
            version = headers['X-Powered-By']
            if 'PHP/' in version:
                version_number = version.split('/')[1]
                if version_number < '7.2':
                    print(f"\n------------------------------------------------------------------------------------------------\n")
                    print(f"[!] Vulnerability Found: A06:Vulnerable and Outdated Component")
                    print(f"\tURL:\t\t\t{url}")
                    print(f"\tMisconfiguration:\tThe PHP version on this website is out of date")
                    print(f"\tSeverity:\t\tMedium\n")
                    print(f"\n------------------------------------------------------------------------------------------------\n")
                    #print("[+] The PHP version on this website is out of date.")
                    writer.writerow(['Outdated Component', url, 'Medium'])
        else:
            print("[+] The X-Powered-By header is not present in the response headers.")

        source_code = response.text
        deprecated_functions = []
        if 'mysql_' in source_code:
            deprecated_functions.append('mysql_')
        if 'ereg(' in source_code:
            deprecated_functions.append('ereg()')
        if deprecated_functions:
            #print("[+] The following deprecated PHP functions are present in the source code:", ', '.join(deprecated_functions))
            print(f"\n------------------------------------------------------------------------------------------------\n")
            print(f"[!] Vulnerability Found: A06:Vulnerable and Outdated Component")
            print(f"\tURL:\t\t\t{url}")
            print(f"\tMisconfiguration:\tDeprecated PHP functions are present in the source code")
            print(f"\tSeverity:\t\tMedium\n")
            print(f"\n------------------------------------------------------------------------------------------------\n")
