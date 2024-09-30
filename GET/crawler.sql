CREATE DATABASE IF NOT EXISTS web_crawler;
USE web_crawler;

CREATE TABLE IF NOT EXISTS http_request (
    id INT AUTO_INCREMENT PRIMARY KEY,
    method VARCHAR(10),
    url TEXT,
    payload JSON,
    headers JSON
);

CREATE TABLE IF NOT EXISTS http_response (
    id INT AUTO_INCREMENT PRIMARY KEY,
    request_id INT,
    status_code INT,
    headers JSON,
    body LONGTEXT,
    FOREIGN KEY (request_id) REFERENCES http_request(id)
);
