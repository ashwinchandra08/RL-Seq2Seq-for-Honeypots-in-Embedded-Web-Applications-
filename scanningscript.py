import os
import time
import mysql.connector
from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from dotenv import load_dotenv
import random
from urllib.parse import urlparse

# Load credentials from .env file
load_dotenv()

# MySQL database connection
db_connection = mysql.connector.connect(
    host='127.0.0.1',
    user='root',
    password=os.getenv('MYSQL_PASSWORD'),
    database='web_analysis'
)
c_rsp = db_connection.cursor()
c_lrn = db_connection.cursor()
c_main = db_connection.cursor()

# Selenium WebDriver path
driver_path = os.getenv('CHROMEDRIVER_PATH')

def fuzz_parameters():
    """Generate random fuzzing parameters for input fields."""
    fuzz_inputs = [
        "", "<script>alert(1)</script>", "../../etc/passwd", "A" * 1000, 
        "admin'--", "%00", "!@#$%^&*()", "normalInput", "1234567890",
        "'; DROP TABLE users; --", "`; exec xp_cmdshell('dir'); --"
    ]
    return random.choice(fuzz_inputs)

def fuzz_headers():
    """Generate random fuzzing headers."""
    fuzz_headers_list = [
        {"X-Injected-Header": "' OR '1'='1"},
        {"X-Exploit-Header": "<script>alert(1)</script>"},
        {"X-Path-Traversal": "../../etc/passwd"},
        {"X-Bad-Header": "A" * 1000},
        {"X-SQL-Comment": "admin'--"},
        {"X-Null-Byte": "%00"},
        {"X-Special-Char": "!@#$%^&*()"},
        {"X-Numeric": "1234567890"},
        {"X-Normal-Header": "normalInput"},
        {"X-Empty-Header": ""}
    ]
    return random.choice(fuzz_headers_list)

def apply_fuzzing_headers(driver):
    """Apply fuzzing headers using JavaScript."""
    headers = fuzz_headers()
    for header_name, header_value in headers.items():
        try:
            # Ensure correct JavaScript syntax
            js_code = f"""
            var xhr = new XMLHttpRequest();
            xhr.open('POST', window.location.href, true);
            xhr.setRequestHeader('{header_name}', `{header_value}`);
            xhr.send();
            """
            driver.execute_script(js_code)
            time.sleep(3)
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


def save_to_db(req_method, req_path, req_query, req_headers, req_body, res_status, res_headers, res_body):
    """Save request and response data to the database."""
    try:
        sql_rsp = 'INSERT INTO http_response (status, headers, body) VALUES (%s, %s, %s)'
        c_rsp.execute(sql_rsp, (res_status, res_headers, res_body))
        res_id = c_rsp.lastrowid
        
        sql_req = 'INSERT INTO request_data (method, path, query, headers, body, res_id) VALUES (%s, %s, %s, %s, %s, %s)'
        c_lrn.execute(sql_req, (req_method, req_path, req_query, req_headers, req_body, res_id))
        
        db_connection.commit()
    except Exception as e:
        print(f"Failed to save to DB: {e}")

def get_internal_links(driver, base_url):
    """Extract all internal links from the current page."""
    links = set()
    anchor_elements = driver.find_elements(By.TAG_NAME, "a")
    
    for element in anchor_elements:
        href = element.get_attribute("href")
        if href and href.startswith(base_url):
            links.add(href)
    
    return links

def crawl_by_selenium(url, driver, visited_urls):
    """Crawl and fuzz a website recursively."""
    if url in visited_urls:
        return
    
    print("[*] Accessing web server:", url)
    visited_urls.add(url)
    
    try:
        driver.get(url)
        time.sleep(10)  # Wait for the page to load completely
    except Exception as e:
        print(f"Error loading page: {e}")
        return

    # Fuzz input fields and submit form
    input_fields = driver.find_elements(By.TAG_NAME, "input")
    form_data = {}
    
    for field in input_fields:
        try:
            field_name = field.get_attribute('name')
            if field_name:
                fuzz_input = fuzz_parameters()
                form_data[field_name] = fuzz_input
                field.send_keys(fuzz_input)
                ActionChains(driver).send_keys_to_element(field, fuzz_input).perform()
        except Exception as e:
            print(f"Fuzzing error: {e}")

    # Find and submit the form
    try:
        forms = driver.find_elements(By.TAG_NAME, "form")
        if forms:
            form = forms[0]
            form.submit()  # Submit the first form found on the page
            print(f"[*] Submitted form with fuzzed data: {form_data}")
    except Exception as e:
        print(f"Form submission error: {e}")

    # Apply fuzzing headers using JavaScript
    apply_fuzzing_headers(driver)

    # Log the requests and responses
    for request in driver.requests:
        if url in request.url:
            req_method = request.method
            req_path = request.path
            req_query = request.querystring if request.querystring else "<EMP>"
            req_headers = decode_safe(str(request.headers))
            req_body = decode_safe(request.body) if request.body else "<EMP>"

            try:
                res_status = int(request.response.status_code)
                res_headers = decode_safe(str(request.response.headers))
                res_body = decode_safe(request.response.body)

            except:
                res_status = 400
                res_headers = "<ERROR>"
                res_body = "Bad Request."

            save_to_db(req_method, req_path, req_query, req_headers, req_body, res_status, res_headers, res_body)

    # Extract all internal links and crawl them recursively
    internal_links = get_internal_links(driver, url)
    for link in internal_links:
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
    
    with open('reachable_ips.txt', 'r') as file:
        ip_addresses = file.readlines()

    for ip in ip_addresses:
        url = f"http://{ip.strip()}"
        crawl_by_selenium(url, driver, visited_urls)

    driver.quit()
    print("[*] Crawling Time:", time.time() - start_time)

    c_lrn.close()
    c_rsp.close()
    db_connection.close()

if __name__ == "__main__":
    main()
