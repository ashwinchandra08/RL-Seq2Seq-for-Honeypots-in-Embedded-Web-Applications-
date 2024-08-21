import shodan
import socket
import os
import requests
from dotenv import load_dotenv

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
        
        if response.status_code == 502 or response.status_code==404:
            print(f"IP {ip} returned 502 Bad Gateway or 404.")
            return False
        return True
        
    except (socket.timeout, ConnectionRefusedError, OSError, requests.RequestException) as e:
        print(f"Unreachable IP: {ip}, Error: {e}")
        return False

def fetch_reachable_ips(query='http'):
    """Fetch reachable IP addresses of active web servers using Shodan."""
    try:
        results = api.search(query)
        reachable_ips = []
        for result in results['matches']:
            ip = result.get('ip_str')
            if ip and is_ip_reachable(ip):
                reachable_ips.append(ip)
                print(f"Reachable IP found: {ip}")
            else:
                print(f"Unreachable or filtered IP: {ip}")
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
