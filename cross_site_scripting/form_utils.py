import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def get_all_forms(url):
    """
    Returns a list of all forms in the given URL
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return []


def get_form_details(form):
    """
    Returns the details of the given form
    """
    details = {}
    action = form.attrs.get('action', '').lower()
    method = form.attrs.get('method', 'get').lower()
    inputs = []
    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get('type', 'text')
        input_name = input_tag.attrs.get('name')
        inputs.append({'type': input_type, 'name': input_name})
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details


def submit_form(form_details, url, value):
    """
    Submits the given form with a malicious payload
    """
    target_url = urljoin(url, form_details['action'])
    inputs = form_details['inputs']
    data = {}
    for input in inputs:
        modified_input = input.copy()
        if modified_input['type'] == 'text' or modified_input['type'] == 'search':
            modified_input['value'] = value
        input_name = modified_input.get('name')
        input_value = modified_input.get('value')
        if input_name and input_value:
            data[input_name] = input_value
    try:
        #print(f"[+] Submitting malicious payload to {target_url}")
        if form_details['method'] == 'post':
            response = requests.post(target_url, data=data)
        else:
            response = requests.get(target_url, params=data)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None
