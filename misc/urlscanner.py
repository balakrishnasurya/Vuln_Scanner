import requests

def validate_url(url):
    # Ensure URL starts with http/https
    if not url.startswith('http'):
        url = 'http://' + url
    # Ensure URL ends with a slash
    if not url.endswith('/'):
        url += '/'
    response = requests.get(url)
    response.raise_for_status()
    return url
