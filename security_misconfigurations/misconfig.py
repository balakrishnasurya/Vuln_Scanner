import csv
import urllib.request

def find_misconfigs(url):
    url += 'secured/phpinfo.php'

    # check if url exists
    try:
        response = urllib.request.urlopen(url)
        if response.status == 404:
            print(f"{url} does not exist.")
            return
    except urllib.error.URLError as e:
        print(f"Error: {e.reason}")
        return

    response = urllib.request.urlopen(url)
    content = response.read().decode('utf-8')

    misconfigs = []
    if 'allow_call_time_pass_reference' in content and 'On' in content:
        misconfigs.append('allow_call_time_pass_reference is On')
    if 'allow_url_fopen' in content and 'On' in content:
        misconfigs.append('allow_url_fopen is On')
    if 'display_errors' in content and 'On' in content:
        misconfigs.append('display_errors is On')
    if 'expose_php' in content and 'On' in content:
        misconfigs.append('expose_php is set as On')
    if 'session.auto_start' in content and 'Off' in content:
        misconfigs.append('session.auto_start is Off')
    if 'session.use_trans_sid' in content and '0' in content:
        misconfigs.append('session.use_trans_sid is set to 0')
    if 'open_basedir' not in content:
        misconfigs.append('open_basedir not set')
    if 'session.cookie_secure' in content and 'Off' in content:
        misconfigs.append('session.cookie_secure is Off')
    if 'session.cookie_httponly' not in content:
        misconfigs.append('session.cookie_httponly not set')

    if misconfigs:
        with open('results.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            for misconfig in misconfigs:
                writer.writerow(['Security Misconfiguration ('+ misconfig +')', url, 'Low'])
                #print(f"Misconfiguration found: {misconfig} ({url})")
                print(f"\n------------------------------------------------------------------------------------------------\n")
                print(f"[!] Vulnerability Found: A05:Security Misconfiguration")
                print(f"\tURL:\t\t\t{url}")
                print(f"\tMisconfiguration:\t{misconfig}")
                print(f"\tSeverity:\t\tLow\n")
    else:
        print('No misconfigurations were found.')
