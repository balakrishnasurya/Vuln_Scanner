import requests
from urllib.parse import urljoin
from cross_site_scripting.form_utils import get_form_details

def submit_form(form_details, url, value):
    """
    Submit a form with a modified payload.

    :param form_details: details of the form to submit.
    :param url: base URL of the form.
    :param value: payload to be submitted.
    :return: response of the form submission.
    """

    target_url = urljoin(url, form_details["action"])

    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        modified_input = input.copy()

        if modified_input["type"] == "text" or modified_input["type"] == "search":
            # Modify the payload for text and search input types
            modified_input["value"] = value

        input_name = modified_input.get("name")
        input_value = modified_input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    #print(f"[+] Submitting payload to {target_url}")
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error submitting form: {e}")
        return None
