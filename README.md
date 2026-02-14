# test_gh_bot_repo
to test gh bot actions

## Vulnerabilities

This project is intentionally vulnerable for educational purposes.

### 1. Command Injection
- Endpoint: `/ping`
- Parameter: `host`
- Description: Executes shell commands directly.

### 2. Directory Traversal
- Endpoint: `/`
- Description: Allows accessing files outside the web root.

### 3. Reflected XSS
- Endpoint: `/greet`
- Parameter: `name`
- Description: Reflects user input into HTML without sanitization.

### 4. Broken Access Control
- Endpoint: `/admin`
- Header: `X-Admin-Token`
- Description: Hardcoded credentials.

### 5. Insecure Deserialization
- Endpoint: `/process_data` (POST)
- Description: Unpickles untrusted data.

### 6. SQL Injection
- Endpoint: `/login`
- Parameter: `username`
- Description: Vulnerable to SQL injection.

### 7. Server-Side Request Forgery (SSRF)
- Endpoint: `/proxy`
- Parameter: `url`
- Description: Fetches arbitrary URLs from the server.

### 8. Open Redirect
- Endpoint: `/redirect`
- Parameter: `url`
- Description: Redirects to arbitrary URLs.
