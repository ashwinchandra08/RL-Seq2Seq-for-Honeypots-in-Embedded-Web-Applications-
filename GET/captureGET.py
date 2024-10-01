import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
import mysql.connector
import os
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Function to capture GET request and response and store them in MySQL
def capture_get_request(url, db_cursor, db_conn):
    try:
        response = requests.get(url)
        
        # Insert request data into http_request table
        request_query = """
            INSERT INTO http_request (method, url, payload, headers)
            VALUES (%s, %s, %s, %s)
        """
        request_values = (
            "GET",  # The HTTP method is always GET in this case
            url,
            json.dumps({}),  # Payload is empty for GET
            json.dumps(dict(response.request.headers))  # Convert headers to JSON string
        )
        db_cursor.execute(request_query, request_values)
        request_id = db_cursor.lastrowid  # Get the inserted request ID

        # Insert response data into http_response table
        response_query = """
            INSERT INTO http_response (request_id, status_code, headers, body)
            VALUES (%s, %s, %s, %s)
        """
        response_values = (
            request_id,
            response.status_code,
            json.dumps(dict(response.headers)),  # Convert headers to JSON string
            response.text  # Store the entire response body
        )
        db_cursor.execute(response_query, response_values)

        # Commit the transaction
        db_conn.commit()

        return {"request_id": request_id, "url": url}
    except requests.exceptions.RequestException as e:
        print(f"Error making request to {url}: {e}")
        return None

# Function to crawl a website and store GET request/response in MySQL
def crawl_website(base_url, db_cursor=None, db_conn=None):
    visited = set()
    to_visit = [base_url]

    while to_visit:
        url = to_visit.pop(0)
        if url in visited:
            continue

        print(f"Crawling {url}...")

        # Capture the GET request and response for the URL and store in MySQL
        request_data = capture_get_request(url, db_cursor, db_conn)

        # Mark the URL as visited
        visited.add(url)

        # Fetch the HTML content and extract internal links
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links on the page
            for link in soup.find_all('a', href=True):
                href = link['href']
                # Resolve relative URLs and only follow internal links
                full_url = urllib.parse.urljoin(base_url, href)
                parsed_base = urllib.parse.urlparse(base_url)
                parsed_full = urllib.parse.urlparse(full_url)

                if parsed_base.netloc == parsed_full.netloc and full_url not in visited:
                    to_visit.append(full_url)
        except Exception as e:
            print(f"Error processing {url}: {e}")

# Worker function to be used with ThreadPoolExecutor
def crawl_website_worker(base_url, db_conn_params):
    # Create a new database connection for each thread
    db_conn = mysql.connector.connect(**db_conn_params)
    db_cursor = db_conn.cursor()
    
    crawl_website(base_url, db_cursor=db_cursor, db_conn=db_conn)
    
    # Close the database connection after crawling
    db_cursor.close()
    db_conn.close()

# Main function to connect to MySQL and crawl websites from CSV (in reverse order) concurrently
def main():
    # Database connection parameters
    db_conn_params = {
        'host': '127.0.0.1',
        'user': 'root',
        'password': os.getenv('MYSQL_PASSWORD'),
        'database': 'web_crawler'
    }

    # Read URLs from a CSV file, with URLs in the "Domain" column (using utf-8 encoding)
    with open('GET/majestic_million.csv', newline='', encoding='utf-8') as csvfile:
        csv_reader = csv.DictReader(csvfile)  # Read CSV as a dictionary
        rows = list(csv_reader)  # Load all rows into a list

    # Using ThreadPoolExecutor for concurrent crawling
    max_threads = 5  # You can adjust the number of threads
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit tasks for each URL in reverse order
        futures = []
        for row in reversed(rows):
            base_url = row['Domain']  # Assume the URL is in the "Domain" column
            if not base_url.startswith("http"):  # Ensure the URL has http/https prefix
                base_url = "https://" + base_url

            futures.append(executor.submit(crawl_website_worker, base_url, db_conn_params))

        # As each task is completed, print its result
        for future in as_completed(futures):
            result = future.result()
            print(f"Crawled: {result}")

if __name__ == "__main__":
    main()
