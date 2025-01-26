import requests
from bs4 import BeautifulSoup

# List of payloads for vulnerability testing
payloads = {
    "sql_injection": ["' OR 1=1 --", "'; DROP TABLE users --"],
    "xss": ['<script>alert(1)</script>', '"><script>alert(1)</script>'],
    "open_redirect": ["https://evil.com", "//evil.com"]
}

# Function to scan a URL for vulnerabilities
def scan_url(url):
    print(f"Scanning {url}...\n")

    try:
        # Send a GET request to the URL
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all form elements on the page
        forms = soup.find_all("form")
        print(f"Found {len(forms)} form(s) on the page.\n")

        for i, form in enumerate(forms):
            print(f"Scanning form {i + 1}...")
            action = form.get("action")
            method = form.get("method", "get").lower()

            # Collect all input fields from the form
            inputs = form.find_all("input")
            form_data = {input.get("name", ""): input.get("value", "") for input in inputs if input.get("name")}

            for vul_type, payload_list in payloads.items():
                for payload in payload_list:
                    # Inject payload into form data
                    test_data = {key: payload for key in form_data.keys()}
                    target_url = url if action is None or action == "#" else action

                    if method == "post":
                        test_response = requests.post(target_url, data=test_data)
                    else:
                        test_response = requests.get(target_url, params=test_data)

                    if payload in test_response.text:
                        print(f"[!] Potential {vul_type.upper()} vulnerability detected with payload: {payload}")
                    else:
                        print(f"[-] {vul_type} not found with payload: {payload}")
            print("-" * 50)

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {url}: {e}")

# Entry point for the scanner
if __name__ == "__main__":
    target_url = input("Enter the URL to scan (e.g., http://example.com): ")
    scan_url(target_url)
