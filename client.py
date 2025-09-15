import socket
import dpkt
from datetime import datetime
import sys
import time

class DNSClient:
    def __init__(self, server_host='localhost', server_port=5353):
        # Initialize client with server host/port details
        self.server_host = server_host
        self.server_port = server_port
        self.results = []  # To store results after processing

    def parse_pcap(self, pcap_file):
        """Parse PCAP file and extract DNS query packets"""
        dns_queries = []
        
        try:
            with open(pcap_file, 'rb') as f:
                # Read the pcap file using dpkt
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    try:
                        # Parse the Ethernet frame
                        eth = dpkt.ethernet.Ethernet(buf)
                        
                        # Check if it's an IP packet
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            
                            # Check if it's a UDP packet
                            if isinstance(ip.data, dpkt.udp.UDP):
                                udp = ip.data
                                
                                # Check if destination port is 53 (DNS) and data exists
                                if udp.dport == 53 and len(udp.data) > 0:
                                    try:
                                        # Try to parse DNS packet
                                        dns = dpkt.dns.DNS(udp.data)
                                        
                                        # qr = 0 means it's a DNS query (not a response)
                                        if dns.qr == 0:
                                            dns_queries.append({
                                                'timestamp': timestamp,       # Packet timestamp
                                                'dns_packet': udp.data,       # Raw DNS packet bytes
                                                'query': dns.qd[0].name if dns.qd else 'unknown' # Domain name
                                            })
                                    except:
                                        # If not valid DNS data, skip
                                        continue
                    except:
                        # If parsing fails at any stage, skip this packet
                        continue
            
            return dns_queries
        
        except FileNotFoundError:
            print(f"Error: PCAP file {pcap_file} not found")
            return []
        except Exception as e:
            print(f"Error parsing PCAP file: {e}")
            return []

    def create_custom_header(self, packet_timestamp, sequence_id):
        """Create custom header in HHMMSSID format using packet timestamp"""
        # Convert Unix timestamp to datetime
        packet_time = datetime.fromtimestamp(packet_timestamp)
        
        # Extract hour, minute, second
        hour = packet_time.strftime("%H")
        minute = packet_time.strftime("%M")
        second = packet_time.strftime("%S")
        
        # Sequence number padded to 2 digits
        seq_str = str(sequence_id).zfill(2)
        
        # Final format: HHMMSS + SequenceID
        return f"{hour}{minute}{second}{seq_str}"

    def send_to_server(self, custom_header, dns_packet):
        """Send DNS query + custom header to server and receive response"""
        try:
            # Create TCP socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            
            # Prepend custom header to raw DNS packet
            message = custom_header.encode('utf-8') + dns_packet
            client_socket.send(message)
            
            # Wait for response from server
            response = client_socket.recv(1024).decode('utf-8')
            client_socket.close()
            
            return response
        except Exception as e:
            print(f"Error communicating with server: {e}")
            return None

    def process_pcap(self, pcap_file):
        """Main method to process PCAP file and resolve DNS queries"""
        print(f"Processing PCAP file: {pcap_file}")
        
        # Step 1: Extract DNS queries from pcap
        dns_queries = self.parse_pcap(pcap_file)
        print(f"Found {len(dns_queries)} DNS queries")
        
        # If no queries found, show hints
        if not dns_queries:
            print("No DNS queries found in the PCAP file.")
            print("Please check if:")
            print("1. The file contains DNS traffic")
            print("2. You're using the correct PCAP file (X = your calculated value)")
            return
        
        # Step 2: Process each query
        for i, query in enumerate(dns_queries):
            # Build custom header from timestamp + sequence ID
            custom_header = self.create_custom_header(query['timestamp'], i)
            
            print(f"Processing query {i+1}: {query['query']} at {datetime.fromtimestamp(query['timestamp'])}")
            
            # Send packet to server
            response = self.send_to_server(custom_header, query['dns_packet'])
            
            if response:
                # Expected format: custom_header|resolved_ip
                parts = response.split('|')
                if len(parts) == 2:
                    resolved_header, resolved_ip = parts
                    # Save result in list
                    self.results.append({
                        'custom_header': custom_header,
                        'domain': query['query'],
                        'resolved_ip': resolved_ip,
                        'packet_time': datetime.fromtimestamp(query['timestamp']).strftime("%H:%M:%S")
                    })
                    print(f"  Resolved: {resolved_ip}")
                else:
                    print(f"  Unexpected response format: {response}")
            else:
                print(f"  No response from server")
        
        # Step 3: Generate summary report
        self.generate_report()

    def generate_report(self):
        """Generate a summary report of all DNS resolutions"""
        if not self.results:
            print("No results to generate report")
            return
        
        # Print nicely formatted table to console
        print("\n" + "="*80)
        print("DNS RESOLUTION REPORT")
        print("="*80)
        print(f"{'Custom Header':<12} {'Time':<10} {'Domain':<30} {'Resolved IP':<15}")
        print("-" * 80)
        
        for result in self.results:
            print(f"{result['custom_header']:<12} {result['packet_time']:<10} {result['domain']:<30} {result['resolved_ip']:<15}")
        
        # Save report to file
        with open('dns_report.txt', 'w') as f:
            f.write("Custom Header, Packet Time, Domain, Resolved IP\n")
            for result in self.results:
                f.write(f"{result['custom_header']}, {result['packet_time']}, {result['domain']}, {result['resolved_ip']}\n")
        
        print(f"\nReport saved to 'dns_report.txt'")

if __name__ == "__main__":
    # Expect exactly 1 argument: the PCAP file path
    if len(sys.argv) != 2:
        print("Usage: python client.py <pcap_file>")
        print("Example: python client.py 5.pcap")
        sys.exit(1)
    
    # Run the client
    pcap_file = sys.argv[1]
    client = DNSClient()
    client.process_pcap(pcap_file)
