import shodan
import socket
import os
import requests
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# Load credentials from .env file
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# Shodan API setup
api = shodan.Shodan(SHODAN_API_KEY)

def is_ip_reachable(ip, port=80, timeout=7):
    """Check if the given IP address is reachable and does not return 502 Bad Gateway."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.create_connection((ip, port))
        
        # Check HTTP response status code
        url = f"http://{ip}"
        response = requests.get(url, timeout=timeout)
        
        if response.status_code in [502, 404]:
            print(f"IP {ip} returned 502 Bad Gateway or 404.")
            return False
        return response
    except (socket.timeout, ConnectionRefusedError, OSError, requests.RequestException) as e:
        print(f"Unreachable IP: {ip}, Error: {e}")
        return False

def has_input_fields(response):
    """Check if the web page has input fields, indicating a form page."""
    try:
        soup = BeautifulSoup(response.text, 'html.parser')
        input_fields = soup.find_all('input')
        if input_fields:
            print(f"Input fields found: {len(input_fields)}")
            return True
        else:
            print("No input fields found.")
            return False
    except Exception as e:
        print(f"Error parsing HTML: {e}")
        return False

def fetch_reachable_ips(query='http'):
    """Fetch reachable IP addresses of active web servers using Shodan."""
    try:
        results = api.search(query)
        reachable_ips = []
        for result in results['matches']:
            ip = result.get('ip_str')
            if ip:
                response = is_ip_reachable(ip)
                if response and has_input_fields(response):
                    reachable_ips.append(ip)
                    print(f"Reachable IP with input fields found: {ip}")
                else:
                    print(f"Unreachable or no input fields found for IP: {ip}")
        return reachable_ips
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
        return []

def save_ips_to_file(ip_list, filename="reachable_ips.txt"):
    """Save the list of reachable IPs to a text file."""
    try:
        with open(filename, "a") as file:
            for ip in ip_list:
                print(f"Writing IP: {ip} to file.")
                file.write(ip + "\n")
        print(f"Reachable IPs successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving IPs to file: {e}")

def main():
    # Fetch reachable IP addresses using Shodan
    reachable_ips = fetch_reachable_ips()
    
    # Save the reachable IPs to a file
    save_ips_to_file(reachable_ips)

if __name__ == "__main__":
    main()
