import json
import mysql.connector
import os

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