from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import json
import time
import socket
from dotenv import load_dotenv
import os
import mysql.connector
from urllib.parse import urlparse

#Load Credentials from .env 
load_dotenv()

#global id counter 
id_counter = 1

# MySQL database connection
db_connection = mysql.connector.connect(
    host='127.0.0.1',
    user='root',
    password=os.getenv('MYSQL_PASSWORD'),
    database='honeypotdb'
)

#Create a cursor object using the cursor() method
c_rsp = db_connection.cursor()
c_lrn = db_connection.cursor()
c_main = db_connection.cursor()


#Set up Chrome options and capabilities for enabling network traffic capturing
chrome_options = Options()
chrome_options.add_argument("--start-maximized")  # Open browser in maximized mode
chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
chrome_options.add_argument('--ignore-certificate-errors')

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
        {'username': (By.XPATH, '//input[@placeholder="username"]'), 'password': (By.XPATH, '//input[@placeholder="password"]')},
        {'username': (By.XPATH, '//input[@placeholder="Username"]'), 'password': (By.XPATH, '//input[@placeholder="Password"]')}
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

def find_internal_links(driver, base_url):
    links = driver.find_elements(By.TAG_NAME, 'a')
    internal_links = []
    for link in links:
        href = link.get_attribute('href')
        if href and urlparse(href).netloc == urlparse(base_url).netloc:
            internal_links.append(href)
    return internal_links

def navigate_to_login_page(driver, base_url):
    internal_links = find_internal_links(driver, base_url)
    for link in internal_links:
        driver.get(link)
        username_field, password_field = find_login_elements(driver)
        if username_field and password_field:
            return username_field, password_field
    return None, None

def save_to_db(req_method, req_path, req_headers, req_body, res_status, res_headers, res_body):
    """Save request and response data to the database."""
    global id_counter

    try:
        # Print debug information
        print("Saving to DB:")
        print(f"Request Method: {req_method}")
        print(f"Request Path: {req_path}")
        print(f"Request Headers: {req_headers}")
        print(f"Request Body: {req_body}")
        print(f"Response Status: {res_status}")
        print(f"Response Headers: {res_headers}")
        print(f"Response Body: {res_body}")

        # Convert headers to JSON strings if they are dictionaries
        if isinstance(req_headers, dict):
            req_headers = json.dumps(req_headers)
        if isinstance(res_headers, dict):
            res_headers = json.dumps(res_headers)

        # Ensure body is a string
        if isinstance(req_body, bytes):
            req_body = req_body.decode('utf-8')
        if isinstance(res_body, bytes):
            res_body = res_body.decode('utf-8')

     # Check if response already exists
        c_rsp.execute('SELECT res_id FROM http_response WHERE status = %s AND headers = %s AND body = %s', 
                      (res_status, res_headers, res_body))
        result = c_rsp.fetchall()

        if result:
            res_id = result[0][0]
        else:
            sql_rsp = 'INSERT INTO http_response (status, headers, body) VALUES (%s, %s, %s)'
            c_rsp.execute(sql_rsp, (res_status, res_headers, res_body))
            res_id = c_rsp.lastrowid
            id_counter += 1

        # Insert request data
        sql_req = 'INSERT INTO request_data (method, path, headers, body, res_id) VALUES (%s, %s, %s, %s, %s)'
        c_lrn.execute(sql_req, (req_method, req_path, req_headers, req_body, res_id))
        db_connection.commit()

    except Exception as e:
        print(f"Failed to save to DB: {e}")


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
        
        # Extract parameters for save_to_db
    req_method = 'POST'
    req_path = urlparse(url).path
    req_headers = {}  # Assuming headers are not captured in this snippet
    req_body = data['data']
    res_status = data['response']['status']
    res_headers = {}  # Assuming headers are not captured in this snippet
    res_body = data['response']['body']

    # Call save_to_db
    save_to_db(req_method, req_path, req_headers, req_body, res_status, res_headers, res_body)

# Load IPs from a file
def load_ips_from_file(filename):
    with open(filename, 'r') as file:
        ips = file.readlines()
    return [ip.strip() for ip in ips]

# Visit each IP from the .txt file
ip_list = load_ips_from_file('reachable_ips.txt')  # Make sure to replace with the actual path of your IP file

for ip in ip_list:
    target_url = f"https://www.hackthissite.org/"  # Access each IP over HTTP

    print(f"Visiting: {target_url}")
    try:
        driver.get(target_url)
        time.sleep(5)  # Allow page to load

        # Find login elements dynamically
        username_field, password_field = find_login_elements(driver)
        # If login elements are not found, look for links to a login page
        if not username_field or not password_field:
            username_field, password_field = navigate_to_login_page(driver, target_url)

        if username_field and password_field:
            # Enter credentials
            username_field.send_keys('your_username')  # Replace with actual username
            password_field.send_keys('your_password')  # Replace with actual password

            # Submit the form (try common button types)
            try:
                login_button = driver.find_element(By.XPATH, '//button[@type="submit" or @value="Login" or @value="Sign in"]')
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
