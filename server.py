#!/usr/bin/env python3
"""
Simple HTTP server for local development of the password analyzer.
Run with: python3 server.py
"""

import http.server
import socketserver
import os
import webbrowser
from pathlib import Path

PORT = 8000

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add security headers
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        super().end_headers()

def main():
    # Change to the directory containing this script
    os.chdir(Path(__file__).parent)
    
    with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
        print(f"🚀 Password Analyzer server starting...")
        print(f"📱 Local URL: http://localhost:{PORT}")
        print(f"🌐 Network URL: http://0.0.0.0:{PORT}")
        print(f"⏹️  Press Ctrl+C to stop the server")
        print(f"📁 Serving files from: {os.getcwd()}")
        
        # Open browser automatically
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except:
            print("⚠️  Could not open browser automatically")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n🛑 Server stopped. Goodbye!")
            httpd.shutdown()

if __name__ == "__main__":
    main() 