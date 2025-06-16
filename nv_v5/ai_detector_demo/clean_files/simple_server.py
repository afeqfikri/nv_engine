#!/usr/bin/env python3
"""Simple HTTP server for development"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket

class CustomHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{self.date_time_string()}] {format % args}")

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def main():
    port = find_free_port()
    server = HTTPServer(('localhost', port), CustomHandler)
    print(f"Server running on http://localhost:{port}")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")

if __name__ == "__main__":
    main()
