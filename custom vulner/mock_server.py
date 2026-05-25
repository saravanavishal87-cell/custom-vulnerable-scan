import http.server
import socketserver

PORT = 8080

class VulnerableMockHandler(http.server.SimpleHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Override to suppress standard HTTP logging to keep console clean
        pass

    def do_GET(self):
        # 1. Handle robots.txt request
        if self.path == '/robots.txt':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            # Intentional verbose server signature
            self.send_header('Server', 'MockServer/1.2.3-Beta (Ubuntu)')
            self.send_header('X-Powered-By', 'CustomPHP-Legacy')
            self.end_headers()
            
            robots_content = """User-agent: *
Disallow: /admin/
Disallow: /private/config.json
Disallow: /backup/db.sql
"""
            self.wfile.write(robots_content.encode('utf-8'))
            return

        # 2. Handle base endpoint
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        
        # Intentional verbose/leakage headers
        self.send_header('Server', 'MockServer/1.2.3-Beta (Ubuntu)')
        self.send_header('X-Powered-By', 'CustomPHP-Legacy')
        self.send_header('X-AspNet-Version', '4.0.30319')
        
        # Intentional CORS misconfiguration (wildcard with credentials allowed)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        
        # Setting highly insecure cookies (no HttpOnly, no Secure, no SameSite)
        self.send_header('Set-Cookie', 'session_token=secret_val_12345; Path=/')
        self.send_header('Set-Cookie', 'user_preference=dark_mode; Path=/')
        
        # Note: We deliberately DO NOT send any secure headers:
        # (Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, etc.)
        
        self.end_headers()
        
        html_response = """<!DOCTYPE html>
<html>
<head>
    <title>Mock Target Web Application</title>
    <style>
        body { font-family: sans-serif; background-color: #1e1e24; color: #f5f5f6; text-align: center; padding-top: 10%; }
        .container { max-width: 600px; margin: auto; padding: 2rem; border: 1px solid #333; border-radius: 8px; background-color: #121214; }
        h1 { color: #f43f5e; }
        p { color: #a1a1aa; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerable Mock Target Active</h1>
        <p>This local server simulates typical server misconfigurations:</p>
        <ul style="text-align: left; display: inline-block;">
            <li>Missing crucial protective security headers</li>
            <li>Exposed infrastructure and framework versions</li>
            <li>Insecurely configured session cookies (no HttpOnly or Secure flags)</li>
            <li>A robots.txt file disclosing sensitive configuration routes</li>
        </ul>
        <p style="margin-top: 1.5rem; font-size: 0.9rem; color: #71717a;">Listening locally on http://127.0.0.1:8080</p>
    </div>
</body>
</html>
"""
        self.wfile.write(html_response.encode('utf-8'))

def run_server():
    # Allow port reuse to prevent "Address already in use" errors during quick restarts
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), VulnerableMockHandler) as httpd:
        print(f"[*] Starting local vulnerable mock server on http://127.0.0.1:{PORT}")
        print("[*] Press Ctrl+C to terminate.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Mock server terminated.")

if __name__ == "__main__":
    run_server()
