import http.server
import socketserver
import os
import urllib.parse
import subprocess

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

if __name__ == "__main__":
    # Ensure public directory exists
    if not os.path.exists(WEB_ROOT):
        os.makedirs(WEB_ROOT)

    print(f"Serving at port {PORT}")
    with socketserver.TCPServer(("", PORT), VulnerableHandler) as httpd:
        httpd.serve_forever()
