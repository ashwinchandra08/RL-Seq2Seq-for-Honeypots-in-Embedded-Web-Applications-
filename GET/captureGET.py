import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
import mysql.connector
import os
import csv

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

# Main function to connect to MySQL and crawl websites from CSV
def main():
    # Database connection setup
    db_conn = mysql.connector.connect(
        host='127.0.0.1',
        user='root',
        password=os.getenv('MYSQL_PASSWORD'),
        database='web_crawler'
    )
    db_cursor = db_conn.cursor()

     # Read URLs from a CSV file, with URLs in the "Domain" column
    with open('GET/majestic_million.csv', newline='', encoding='utf-8') as csvfile:
        csv_reader = csv.DictReader(csvfile)  # Read CSV as a dictionary
        rows = list(csv_reader)  # Load all rows into a list

    # Iterate over the list in reverse order
    for row in reversed(rows):
        base_url = row['Domain']  # Assume the URL is in the "Domain" column
        if not base_url.startswith("http"):  # Ensure the URL has http/https prefix
            base_url = "https://" + base_url

        print(f"Starting crawl for {base_url}")
        crawl_website(base_url, db_cursor=db_cursor, db_conn=db_conn)

    # Close the database connection
    db_cursor.close()
    db_conn.close()

if __name__ == "__main__":
    main()
