from misc.urlscanner import validate_url
from cross_site_scripting.scanner import scan_xss
from local_file_inclusion.lfi_scanner import scan_lfi
from sql_injection.sqllscanner import scan_sql
from misc.create_url import create_url
from security_misconfigurations.misconfig import find_misconfigs
from vulnerable_and_outdated_components.outdated_php import check_php_version

url = input("Enter the website URL to scan: ")

url = validate_url(url)
create_url(url)

print("\n[+] Scanning for Local File Inclusion")
scan_lfi(url)

print("\n[+] Scanning for Cross Site Scripting (XSS)")
scan_xss(url)

print("\n[+] Scanning for SQL Injection (SQLi)")
scan_sql()

print("\n[+] Scanning for any Misconfigurations")
find_misconfigs(url)

print("\n[+] Scanning for Vulnerable and Outdated Components")
check_php_version(url)
