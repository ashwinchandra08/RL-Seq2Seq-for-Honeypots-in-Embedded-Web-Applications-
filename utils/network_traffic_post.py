# Function to capture network traffic
import json
from urllib.parse import urlparse
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import time 
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException,NoSuchElementException
from selenium.webdriver.common.keys import Keys 

# Add the parent directory of utils to sys.path
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Code Dependencies from other files
from utils.attackPayloads import sql_injection_payloads, command_injection_payloads
from utils.savetoDB import save_to_db

# Combine SQL and command injection payloads
attack_payloads = sql_injection_payloads + command_injection_payloads
import random 
def submit_payloads(driver, username_field, password_field):
    """Submits the payloads to the login form."""
    random.shuffle(attack_payloads)
    for payload in attack_payloads:
        # Clear and enter payloads into login form
        username_field.clear()
        password_field.clear()
        username_field.send_keys(payload)
        password_field.send_keys(payload)

        # Submit the form
        try:
            login_button = WebDriverWait(driver, 5).until(EC.element_to_be_clickable(
                 (By.XPATH, '//button[@type="submit" or contains(@class, "continue-btn") or contains(text(), "Continue") or contains(text(), "Submit")] | '
                               '//input[@type="submit" or @value="Login" or @value="Sign In"] | '
                               '//button[@id="loginButton"]')
            ))
            print(login_button)
            try:
                login_button.click()
                print(f"Payload submitted: {payload}")
            except:
                password_field.send_keys(Keys.RETURN)

            
                print("Submitted credentials via Enter key.")
                
        except TimeoutException:
            print("Submit button not found.")
        
        # Wait for some time after each payload submission
        time.sleep(10)

        # Capture network traffic (you can implement this to log POST request/response details)
        capture_network_traffic_post(driver)

def capture_network_traffic_post(driver):
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
