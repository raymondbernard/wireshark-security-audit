

# Network Packet Analysis Tool

## Overview

This tool analyzes network traffic to identify potential security threats and suspicious activity in captured packets. It processes network capture files in `.pcapng` format, created with Wireshark, and detects various issues such as unencrypted data transmission, suspicious IP addresses, DNS anomalies, and ARP spoofing attempts. This guide is designed for entry-level tech users.

## Getting Started

### Clone the Repository

To get started, clone this repository to your local machine:

```bash
git clone https://github.com/raymondbernard/wireshark-security-audit
cd wireshark-security-audit
```

### Software Requirements

1. **Python 3**: Ensure Python is installed on your system.
2. **Wireshark**: To create `.pcapng` files that contain network traffic data for analysis.

### Install Dependencies

Install the necessary Python libraries by running:
```bash
pip install -r requirements.txt
```

The `requirements.txt` file includes all the required dependencies for this project.

### GeoLite2 GeoIP Database

This tool uses the GeoLite2 database to determine the geographical location of IP addresses. Download it from the MaxMind website:

1. Visit [MaxMind's GeoLite2 Download page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Download the **GeoLite2-Country** database.
3. Place the downloaded `GeoLite2-Country.mmdb` file in the same directory as `main.py`.

## Creating a pcapng File with Wireshark

Wireshark is a popular network analysis tool that can capture and save network traffic in `.pcapng` format. Here’s how to create a `.pcapng` file:

1. **Download and Install Wireshark**: If you haven't already, get Wireshark from [Wireshark.org](https://www.wireshark.org/download.html).
2. **Capture Network Traffic**:
   - Open Wireshark and choose the network interface you want to monitor (e.g., Wi-Fi or Ethernet).
   - Click **Start Capture** to begin recording network packets.
3. **Stop and Save the Capture**:
   - When you've collected enough data, click **Stop Capture**.
   - Go to **File > Save As** and save the file in `.pcapng` format.
4. **Place the File**: Move the saved `.pcapng` file into the same directory as `main.py` to analyze it.

## Usage

Once your `.pcapng` file and GeoIP database are in place, run the tool by executing:
```bash
python main.py
```

### Output Files

- **security.log**: A log file recording detailed information about detected security issues, suspicious IPs, and traceroute results for flagged destinations. Logs are rotated when they exceed 1 MB to save space.

## How It Works

The tool examines packets in the `.pcapng` file and identifies various protocols and any potential security concerns associated with them. Here’s a breakdown of the main functions:

### Key Protocols

- **HTTP**: Used for web traffic; traffic here is unencrypted.
- **TCP/UDP**: Transport protocols; TCP is reliable and connection-oriented, while UDP is faster but connectionless.
- **ARP**: Maps IP addresses to MAC addresses within a network.
- **ICMP**: Used for network diagnostics, like `ping`.

### Suspicious Activity Detection

The tool flags various types of suspicious network activity, including:

- **Unencrypted Protocols**: Identifies packets using unencrypted protocols such as HTTP, FTP, and Telnet.
- **Suspicious IP Activity**:
  - **SYN Scans**: Detects scans that probe open ports.
  - **Known Hackable Ports**: Monitors for traffic on commonly targeted ports.
  - **DNS Anomalies**: Detects unusually long domain names or suspicious top-level domains that may indicate data exfiltration.
  - **ARP Spoofing**: Flags cases where an IP address is associated with more than one MAC address, suggesting a potential spoofing attempt.
  - **ICMP Anomalies**: Detects unexpected ICMP traffic types and large payloads, which can signal abnormal activity.

## Example Output

The following is an example of the security log file created during analysis:

```
2024-11-02T12:51:02.121950-0400 INFO Analysis Summary: {'protocol_usage': {'IP': 19986, 'IPv6': 16, 'ARP': 6, '192.168.2.34': '18:7f:88:6a:23:ef', '192.168.2.14': 'f0:2f:74:cc:4a:91'}, 'unencrypted_traffic_count': 0, 'suspicious_activity_count': 3271, 'arp_spoofing_attempts_count': 0, 'dns_exfiltration_attempts_count': 15} 
2024-11-02T12:51:02.122950-0400 INFO Unencrypted Traffic Packets: 0
2024-11-02T12:51:02.122950-0400 INFO Suspicious Packets: 3271
2024-11-02T12:51:02.122950-0400 INFO ARP Spoofing Attempts: 0
2024-11-02T12:51:02.123952-0400 INFO DNS Exfiltration Attempts: 15
...
2024-11-02T12:51:18.042324-0400 INFO Suspicious Destination IP: 3.131.122.151, Number of Suspicious Packets: 16, Domain: ec2-3-131-122-151.us-east-2.compute.amazonaws.com, Country: United States
2024-11-02T12:52:39.454285-0400 INFO Traceroute to 52.182.143.215: Hop 15 -> 104.44.54.108
```

## Troubleshooting

- **GeoIP Database Not Found**: Ensure `GeoLite2-Country.mmdb` is in the same directory as `main.py`.
- **pcapng File Not Found**: Confirm `wireshark.pcapng` is in the same folder as `main.py`.

