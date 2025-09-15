import socket
import json
import threading
from datetime import datetime

class DNSServer:
    def __init__(self, host='localhost', port=5353):
        # Initialize server host and port
        self.host = host
        self.port = port
        self.load_rules()       # Load routing rules from rules.json
        self.running = True     # Flag to keep server running
    
    def load_rules(self):
        """Load IP pool and routing rules from JSON file"""
        with open('rules.json', 'r') as f:
            self.rules = json.load(f)
        self.ip_pool = self.rules['ip_pool']   # Available IP addresses for mapping
    
    def get_time_period(self, hour):
        """Determine time period (morning/afternoon/night) based on hour"""
        if 4 <= hour < 12:
            return 'morning'
        elif 12 <= hour < 20:
            return 'afternoon'
        else:
            return 'night'
    
    def resolve_ip(self, custom_header):
        """Resolve IP using the custom header and routing rules"""
        try:
            # Custom header format: HHMMSSID
            hour = int(custom_header[:2])   # Hours (00-23)
            minute = int(custom_header[2:4])# Minutes (00-59)
            second = int(custom_header[4:6])# Seconds (00-59)
            query_id = int(custom_header[6:8]) # Sequence ID
            
            # Get time period (morning/afternoon/night)
            time_period = self.get_time_period(hour)
            
            # Fetch rules for that time period
            rules = self.rules['timestamp_rules']['time_based_routing'][time_period]
            
            # Compute index of IP in pool
            hash_mod = rules['hash_mod']
            ip_pool_start = rules['ip_pool_start']
            ip_index = ip_pool_start + (query_id % hash_mod)
            
            # Return resolved IP address
            return self.ip_pool[ip_index]
        
        except (ValueError, IndexError, KeyError) as e:
            # If something goes wrong, fallback to default IP
            print(f"Error resolving IP: {e}")
            return "192.168.1.1"
    
    def handle_client(self, client_socket, address):
        """Handle a client request in a separate thread"""
        print(f"Connection from {address}")
        
        try:
            # Receive up to 1024 bytes of data
            data = client_socket.recv(1024)
            if not data:
                return
            
            # Extract first 8 bytes as custom header (string)
            custom_header = data[:8].decode('utf-8')
            
            # Remaining bytes = original DNS packet
            dns_packet = data[8:]
            
            print(f"Received custom header: {custom_header}")
            
            # Resolve IP using rules
            resolved_ip = self.resolve_ip(custom_header)
            
            # Prepare response as "custom_header|resolved_ip"
            response = f"{custom_header}|{resolved_ip}"
            client_socket.send(response.encode('utf-8'))
            
            print(f"Resolved IP for header {custom_header}: {resolved_ip}")
        
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            # Close socket after serving client
            client_socket.close()
    
    def start(self):
        """Start the DNS server (multi-threaded)"""
        # Create TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Allow address reuse (avoid "address already in use" errors)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to host:port and start listening
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)  # Allow up to 5 queued connections
        
        print(f"DNS Server listening on {self.host}:{self.port}")
        
        try:
            # Accept incoming clients in a loop
            while self.running:
                client_socket, address = server_socket.accept()
                
                # Handle client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True  # Daemon thread exits when main program exits
                client_thread.start()
        
        except KeyboardInterrupt:
            print("Shutting down server...")
        finally:
            # Close server socket when shutting down
            server_socket.close()

if __name__ == "__main__":
    # Start the DNS server
    server = DNSServer()
    server.start()
