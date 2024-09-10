from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import json
import time
import socket
from dotenv import load_dotenv
import os
load_dotenv()
# Set up Chrome options and capabilities for enabling network traffic capturing
chrome_options = Options()
chrome_options.add_argument("--start-maximized")  # Open browser in maximized mode
chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

# Specify the path to chromedriver
chromedriver_path = os.getenv('CHROMEDRIVER_PATH')  # Replace with your chromedriver path
service = Service(chromedriver_path)

# Initialize WebDriver
driver = webdriver.Chrome(service=service, options=chrome_options)

# Define a function to find login elements dynamically
def find_login_elements(driver):
    # Common locators to try for username and password fields
    locators = [
        {'username': (By.NAME, 'username'), 'password': (By.NAME, 'password')},
        {'username': (By.ID, 'username'), 'password': (By.ID, 'password')},
        {'username': (By.CSS_SELECTOR, 'input[name="username"]'), 'password': (By.CSS_SELECTOR, 'input[name="password"]')},
        {'username': (By.XPATH, '//input[@name="username"]'), 'password': (By.XPATH, '//input[@name="password"]')},
    ]

    # Try each locator set
    for locator in locators:
        try:
            username_field = driver.find_element(*locator['username'])
            password_field = driver.find_element(*locator['password'])
            return username_field, password_field
        except:
            pass
    return None, None

# Function to capture network traffic
def capture_network_traffic(driver):
    logs = driver.get_log('performance')
    post_requests = {}
    for entry in logs:
        log = json.loads(entry['message'])['message']
        try:
            if log['method'] == 'Network.requestWillBeSent':
                request_url = log['params']['request']['url']
                request_method = log['params']['request']['method']
                if request_method == 'POST':
                    post_data = log['params']['request'].get('postData', '')
                    post_requests[request_url] = {'data': post_data, 'response': {'status': None, 'body': '', 'requestId': None}}
                    print(f"Captured POST request: {request_url}")
                    print(f"POST data: {post_data}")

            elif log['method'] == 'Network.responseReceived':
                response_url = log['params']['response']['url']
                response_status = log['params']['response']['status']
                request_id = log['params']['requestId']
                if response_url in post_requests:
                    post_requests[response_url]['response']['status'] = response_status
                    post_requests[response_url]['response']['requestId'] = request_id
                    print(f"Captured HTTP response (POST): {response_url}")
                    print(f"Response status: {response_status}")
                    response_body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                    post_requests[response_url]['response']['body'] = response_body.get('body', '')
                    print(f"Captured response body for {response_url}: {post_requests[response_url]['response']['body']}")
        except KeyError as e:
            print(f"KeyError: {e} - Entry: {log}")
    for url, data in post_requests.items():
        print(f"\nFinal data for POST request to {url}:")
        print(f"Request data: {data['data']}")
        if data['response']['body']:
            print(f"Response body: {data['response']['body']}")
        else:
            print("Response body: No data captured")

# Load IPs from a file
def load_ips_from_file(filename):
    with open(filename, 'r') as file:
        ips = file.readlines()
    return [ip.strip() for ip in ips]

# Visit each IP from the .txt file
ip_list = load_ips_from_file('reachable_ips.txt')  # Make sure to replace with the actual path of your IP file

for ip in ip_list:
    target_url = f"http://{ip}/"  # Access each IP over HTTP

    print(f"Visiting: {target_url}")
    try:
        driver.get(target_url)
        time.sleep(3)  # Allow page to load

        # Find login elements dynamically
        username_field, password_field = find_login_elements(driver)
        if username_field and password_field:
            # Enter credentials
            username_field.send_keys('your_username')  # Replace with actual username
            password_field.send_keys('your_password')  # Replace with actual password

            # Submit the form (try common button types)
            try:
                login_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
                login_button.click()
            except:
                print("Could not find a submit button.")

            # Wait for requests to be captured after form submission
            time.sleep(5)
            capture_network_traffic(driver)
        else:
            print("Login elements not found.")
    except Exception as e:
        print(f"Failed to load {target_url}: {e}")

# Close the browser
driver.quit()
