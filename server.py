import http.server
import socketserver
import os
import urllib.parse
import subprocess
import pickle
import base64

PORT = 8000
WEB_ROOT = os.path.join(os.getcwd(), 'public')

class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        # Vulnerability 1: Command Injection
        if path == '/ping':
            host = query.get('host', [''])[0]
            if host:
                # VULNERABLE: Direct command execution without sanitization
                try:
                    # Using shell=True and formatting the command string directly
                    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(output)
                except subprocess.CalledProcessError as e:
                    self.send_response(500)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(e.output)
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(e).encode())
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing 'host' parameter")
            return

        # Vulnerability 3: Reflected XSS
        if path == '/greet':
            name = query.get('name', ['Guest'])[0]
            # VULNERABLE: Reflecting input directly into HTML
            html = f"<html><body><h1>Hello, {name}!</h1></body></html>"
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html.encode())
            return

        # Vulnerability 4: Broken Access Control / Hardcoded Credentials
        if path == '/admin':
             # Check for a specific header "X-Admin-Token"
             token = self.headers.get('X-Admin-Token')
             if token == 'admin123': # VULNERABLE: Hardcoded token
                 self.send_response(200)
                 self.end_headers()
                 self.wfile.write(b"Welcome Admin! Here is the flag: FLAG{hardcoded_creds}")
             else:
                 self.send_response(403)
                 self.end_headers()
                 self.wfile.write(b"Access Denied")
             return

        # Vulnerability 2: Directory Traversal
        # Intentionally flawed path handling

        # Default to index.html
        if path == '/':
            path = '/index.html'

        # VULNERABLE: path.lstrip('/') removes leading slash, but doesn't resolve '..'
        # os.path.join will keep '..' allowing traversal out of WEB_ROOT
        file_path = os.path.join(WEB_ROOT, path.lstrip('/'))

        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found")
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def do_POST(self):
        # Vulnerability 5: Insecure Deserialization
        if self.path == '/process_data':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                # VULNERABLE: Unpickling untrusted data
                # Expecting base64 encoded pickle data
                data = pickle.loads(base64.b64decode(post_data))
                response = f"Processed data: {data}"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(response.encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

if __name__ == "__main__":
    # Ensure public directory exists
    if not os.path.exists(WEB_ROOT):
        os.makedirs(WEB_ROOT)

    print(f"Serving at port {PORT}")
    with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
        httpd.serve_forever()
