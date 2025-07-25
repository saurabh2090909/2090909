# app/server.py
# This Python script serves index.html and a JSON endpoint.

from http.server import SimpleHTTPRequestHandler, HTTPServer
import os
import json
import datetime
import urllib.parse

# Get the unique identifier for this node from an environment variable.
NODE_ID = os.environ.get('NODE_ID', 'unknown_node')

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Parse the URL path
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == '/data':
            # Handle the /data API endpoint
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            # Get X-User-ID from headers
            user_id = self.headers.get('X-User-ID', 'Not Provided')

            # Prepare JSON response
            response_data = {
                "message": f"Data from Application Server on {NODE_ID}!",
                "received_user_id": user_id,
                "processed_by_node": NODE_ID,
                "timestamp": datetime.datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            print(f"[{datetime.datetime.now()}] Data request received on {NODE_ID} for X-User-ID: {user_id}")
        elif path == '/':
            # Serve index.html for the root path
            self.path = '/index.html' # Change the path to serve index.html
            return SimpleHTTPRequestHandler.do_GET(self)
        else:
            # For any other path, try to serve it as a static file
            return SimpleHTTPRequestHandler.do_GET(self)

    def end_headers(self):
        # Add custom headers here if needed, before calling super
        self.send_header('Access-Control-Allow-Origin', '*') # Allow CORS for testing
        super().end_headers()

if __name__ == '__main__':
    # Change the current directory to 'app' so SimpleHTTPRequestHandler can find index.html
    # This assumes server.py is run from the project root.
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Server address and port
    HOST = '0.0.0.0'
    PORT = 8000

    # Create and start the HTTP server
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, CustomHandler)
    print(f"[{datetime.datetime.now()}] Starting HTTP server on {HOST}:{PORT} for NODE_ID: {NODE_ID}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"[{datetime.datetime.now()}] Stopping HTTP server on {NODE_ID}")
        httpd.server_close()
