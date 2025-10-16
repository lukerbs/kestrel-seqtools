"""
HTTPS to HTTP Redirect Server
Redirects https://www.bankofamerica.com to http://www.bankofamerica.com
Run this alongside your Flask app to handle HTTPS requests
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl


class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Redirect all GET requests to HTTP version"""
        # Build HTTP URL
        http_url = f"http://{self.headers.get('Host', 'www.bankofamerica.com')}{self.path}"

        # Send redirect response
        self.send_response(301)  # Permanent redirect
        self.send_header("Location", http_url)
        self.end_headers()

    def do_POST(self):
        """Redirect all POST requests to HTTP version"""
        self.do_GET()

    def log_message(self, format, *args):
        """Suppress log messages"""
        pass


def create_self_signed_cert():
    """Instructions to create self-signed certificate"""
    print("=" * 60)
    print("HTTPS Redirect Server")
    print("=" * 60)
    print()
    print("ERROR: SSL certificate files not found!")
    print()
    print("You need to generate a self-signed certificate first:")
    print()
    print("Run this command in PowerShell or Git Bash:")
    print()
    print("  openssl req -x509 -newkey rsa:2048 -nodes \\")
    print("    -keyout key.pem -out cert.pem -days 365 \\")
    print('    -subj "/CN=www.bankofamerica.com"')
    print()
    print("Or download OpenSSL for Windows from:")
    print("  https://slproweb.com/products/Win32OpenSSL.html")
    print()
    print("After generating cert.pem and key.pem, run this script again.")
    print("=" * 60)


def main():
    import os

    # Check if certificate files exist
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        create_self_signed_cert()
        return

    # Create HTTPS server
    server_address = ("", 443)  # Port 443 for HTTPS
    httpd = HTTPServer(server_address, RedirectHandler)

    # Wrap with SSL
    try:
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile="cert.pem", keyfile="key.pem", server_side=True)
    except Exception as e:
        print(f"ERROR: Could not setup SSL: {e}")
        print()
        create_self_signed_cert()
        return

    print("=" * 60)
    print("HTTPS Redirect Server Running")
    print("=" * 60)
    print()
    print("Listening on: https://0.0.0.0:443")
    print("Redirecting to: http://www.bankofamerica.com")
    print()
    print("Press Ctrl+C to stop")
    print()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        httpd.shutdown()


if __name__ == "__main__":
    main()
