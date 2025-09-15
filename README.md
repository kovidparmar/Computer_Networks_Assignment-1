# Custom DNS Resolver (Client-Server)

This project implements a **custom DNS resolver** using a client-server architecture.  
The client reads DNS query packets from a **PCAP file**, attaches a custom header, and sends them to the server.  
The server applies time-based routing rules (from `rules.json`) and responds with a resolved IP address.  
Finally, the client generates a **DNS resolution report**.

---

## 📂 Project Structure

.
├── client.py # DNS Client implementation
├── server.py # DNS Server implementation
├── rules.json # IP pool and time-based routing rules
├── sample.pcap # PCAP file with DNS queries
├── dns_report.txt # Auto-generated report (after running client)
└── README.md # Project documentation

---

## ⚙️ Requirements

- Python **3.8+**
- Required libraries:
  - [`dpkt`](https://pypi.org/project/dpkt/) (for parsing PCAP files)
  - Standard libraries: `socket`, `json`, `threading`, `datetime`, `sys`

Install `dpkt` using:
pip install dpkt


▶️ How to Run
You will need two terminals:

1. Start the Server
In the first terminal, run:
python server.py
Expected output:
DNS Server listening on localhost:5353

2. Run the Client
In the second terminal, run:
python client.py sample.pcap
Expected output:
Processing PCAP file: sample.pcap
Found 3 DNS queries
Processing query 1: example.com at 12:05:30
  Resolved: 192.168.1.10
...
Report saved to 'dns_report.txt'


📑 Report
After running, the client generates a DNS Resolution Report in both console and dns_report.txt (created in the project root).
Example (dns_report.txt):
Custom Header, Packet Time, Domain, Resolved IP
12053000, 12:05:30, example.com, 192.168.1.10
12053101, 12:05:31, google.com, 192.168.1.11

⚖️ Rules Configuration
The rules.json file defines how IPs are resolved based on time periods.

Example:

{
  "ip_pool": [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13"
  ],
  "timestamp_rules": {
    "time_based_routing": {
      "morning":   { "hash_mod": 2, "ip_pool_start": 0 },
      "afternoon": { "hash_mod": 2, "ip_pool_start": 1 },
      "night":     { "hash_mod": 2, "ip_pool_start": 2 }
    }
  }
}
ip_pool: List of available IP addresses.

hash_mod: Modulus for query ID (distributes requests).

ip_pool_start: Starting index in the pool for this time period.

Time periods:

morning → 04:00–11:59

afternoon → 12:00–19:59

night → 20:00–03:59

📡 PCAP File (sample.pcap)
The project includes a sample PCAP file containing captured DNS queries.
You can open this file in Wireshark to inspect the packets.

To capture your own PCAP file:

Use Wireshark while making DNS queries (e.g., visiting websites).
Save the capture and provide its path to client.py.

👨‍💻 Authors
Kovid Parmar (23110172)
Vinod Kumar Reddy (23110178)

CS331 – Computer Networks, Assignment 1