import json
import jsonschema
from jsonschema import validate

# Define the HTTP request schema
http_request_schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "id": { "type": "integer" },
        "method": { "type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"] },
        "url": { "type": "string" },
        "payload": { "type": "string" },
        "headers": { "type": "string" }
    },
    "required": ["id", "method", "url", "payload", "headers"]
}

# Define the HTTP response schema
http_response_schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "id": { "type": "integer" },
        "status_code": { "type": "integer", "minimum": 100, "maximum": 599 },
        "headers": { "type": "string" },
        "body": { "type": ["string", "null"] },
        "request_id": { "type": "integer" }
    },
    "required": ["id", "status_code", "headers", "body", "request_id"]
}

# Load data from JSON files
with open("httpRequestPOST.json", "r") as req_file, open("httpResponsePOST.json", "r") as resp_file:
    http_requests = json.load(req_file)
    http_responses = json.load(resp_file)

# Validation functions
def validate_data(data, schema):
    for entry in data:
        try:
            validate(instance=entry, schema=schema)
            print(f"Entry {entry['id']} passed validation.")
        except jsonschema.exceptions.ValidationError as e:
            print(f"Entry {entry['id']} failed validation: {e.message}")

# Validate HTTP requests
print("Validating HTTP Requests...")
validate_data(http_requests, http_request_schema)

# Validate HTTP responses
print("Validating HTTP Responses...")
validate_data(http_responses, http_response_schema)
