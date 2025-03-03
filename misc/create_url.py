import requests
import logging

logging.basicConfig(level=logging.INFO)

def create_url(url):
    php_file = "misc/files.txt"
    n1file = "misc/files.txt"
    payload_file = "misc/payload.txt"

    with open(payload_file, "r") as payloads, open('misc/url.txt', 'w') as url_file:
        for payload in payloads:
            payload = payload.strip()
            with open(n1file, "r") as files:
                for file in files:
                    file = file.strip()
                    with open(php_file, "r") as php_files:
                        for php in php_files:
                            php = php.strip()
                            target_url = f"{url}{php}?{file}={payload}"
                            try:
                                response = requests.get(target_url)
                                if response.status_code != 404:
                                    url_file.write(f"{target_url}\n")
                            except requests.exceptions.RequestException as e:
                                logging.error(f"Failed to scan URL: {target_url}, {e}")
                                continue
