#network_traffic_get.py
import json
from urllib.parse import urlparse
import time 
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException,NoSuchElementException


import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

#Code Dependencies from other files
from utils.attackPayloads import xss_payloads, path_traversal_payloads
from utils.savetoDB import save_to_db

# Combine all GET payloads (XSS + Path Traversal)
get_payloads = xss_payloads + path_traversal_payloads

# Function to append payloads and capture the GET requests
def perform_get_attacks(driver, base_url):
    for payload in get_payloads:
        target_url = f"{base_url}?q={payload}"
        print(f"Visiting: {target_url} with GET attack payload: {payload}")
        
        try:
            driver.get(target_url)
            time.sleep(5)  # Allow some time for the page to load
            
            # Capture the network traffic
            capture_network_traffic_get(driver)
            
        except TimeoutException:
            print(f"Timeout while trying to load {target_url}")
        except Exception as e:
            print(f"Error performing GET request with payload {payload}: {e}")


def capture_network_traffic_get(driver):
    logs = driver.get_log('performance')
    get_requests = {}
    
    for entry in logs:
        log = json.loads(entry['message'])['message']
        try:
            if log['method'] == 'Network.requestWillBeSent':
                request_url = log['params']['request']['url']
                request_method = log['params']['request']['method']
                request_headers = log['params']['request'].get('headers', {})
                
                if request_method == 'GET':
                    get_requests[log['params']['requestId']] = {
                        'url': request_url,
                        'headers': request_headers,
                        'response': {'status': None, 'body': '', 'headers': {}}
                    }
                    print(f"Captured GET request: {request_url}")
                    print(f"Request headers: {request_headers}")

            elif log['method'] == 'Network.responseReceived':
                request_id = log['params']['requestId']
                response_status = log['params']['response'].get('status', None)
                response_headers = log['params']['response'].get('headers', {})
                
                if request_id in get_requests:
                    get_requests[request_id]['response']['status'] = response_status
                    get_requests[request_id]['response']['headers'] = response_headers
                    print(f"Captured HTTP response (GET): {get_requests[request_id]['url']}")
                    print(f"Response status: {response_status}")
                    print(f"Response headers: {response_headers}")

                    # Capture response body
                    try:
                        response_body = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                        get_requests[request_id]['response']['body'] = response_body.get('body', '')
                        if response_body.get('body') != '':
                            print(f"Captured response body for {get_requests[request_id]['url']}: {get_requests[request_id]['response']['body']}")
                    except Exception as e:
                        print(f"Failed to get response body: {e}")

        except KeyError as e:
            print(f"KeyError: {e} - Entry: {log}")

    # Save captured GET requests and responses to the database
    for request_id, data in get_requests.items():
        url = data['url']
        print(f"\nFinal data for GET request to {url}:")
        print(f"Request headers: {data['headers']}")
        print(f"Response status: {data['response']['status']}")
        print(f"Response headers: {data['response']['headers']}")
        if data['response']['body']:
            print(f"Response body: {data['response']['body']}")
        else:
            print("Response body: No data captured")
        
        # Extract parameters for save_to_db
        req_method = 'GET'
        req_path = urlparse(url).path
        req_headers = data['headers']
        req_body = ''  # No body for GET requests
        res_status = data['response']['status']
        res_headers = data['response']['headers']
        res_body = data['response']['body']
        
        # Save to database
        if res_body is not None and res_body != '' and res_status is not None:
            save_to_db(req_method, req_path, req_headers, req_body, res_status, res_headers, res_body)