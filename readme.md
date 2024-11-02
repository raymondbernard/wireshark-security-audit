# Comprehensive PCAP Analysis Tool

This tool is a Python-based network traffic analysis solution that reads a `pcapng` file, identifies security concerns, and generates a detailed report. The program is particularly useful for network administrators, security analysts, and researchers who need to investigate network activities and detect potential threats.

## Features

- **Protocol Analysis**: Identifies the protocols used in the captured traffic.
- **Unusual Traffic Patterns**: Detects potentially malicious traffic, such as unusual port usage, SYN scans, and suspicious ICMP packets.
- **Sensitive Data Identification**: Flags unencrypted sensitive data transfers.
- **Anomaly Detection**: Identifies anomalies like ARP spoofing, DNS tunneling, and non-standard ICMP types.
- **Domain and Country Lookups**: Uses GeoIP to trace suspicious IPs to their country of origin and resolve domain names.
- **Traceroute**: Traces the path to suspicious IP addresses to understand the network hops involved.
- **Logging**: Uses `loguru` to create a comprehensive `security.log` file, storing all analysis results and details.

## Prerequisites

- **Python 3.x**
- **Scapy**: For packet analysis and tracerouting
- **Loguru**: For detailed logging
- **GeoIP2**: For country lookups of IP addresses (requires the `GeoLite2-Country.mmdb` database file)
- **GeoLite2-Country.mmdb**: Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

## Installation

1. **Clone the Repository**
   ```sh
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Create and Activate a Virtual Environment**
   ```sh
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```sh
   pip install -r requirements.txt
   ```

   Make sure to also place the `GeoLite2-Country.mmdb` file in the same directory as the script.

## Usage

1. **Run the Script**
   ```sh
   python main.py
   ```

   The program will read the `wireshark.pcapng` file, analyze it, and output the results in `security.log`.

2. **Key Output Details**
   - **Analysis Summary**: Summary of protocols, unencrypted traffic, suspicious activity, ARP spoofing, and DNS exfiltration attempts.
   - **Suspicious Packet Details**: Details about packets flagged as suspicious, including source and destination IPs, protocols, and reasons for flagging.
   - **Suspicious IP Reports**: Information about suspicious source and destination IPs, including domain names and country information.
   - **Traceroute Information**: Path tracing to suspicious IPs to understand their network hops.

## Logging

All details are logged in a file named `security.log`. This log file includes:
- Analysis summary
- Detailed information for unencrypted traffic, suspicious packets, ARP spoofing attempts, DNS exfiltration attempts
- Information about suspicious IP addresses (source and destination)
- Traceroute results for suspicious IP addresses

## Example Output

A sample snippet of the `security.log` file:
```
2024-11-01 12:00:00 INFO Analysis Summary: {'protocol_usage': {...}, 'unencrypted_traffic_count': 10, ...}
2024-11-01 12:01:00 INFO Suspicious Packet Details:
2024-11-01 12:01:01 INFO Reason: Suspicious port usage: 4444, Source IP: 192.168.1.100, Destination IP: 10.0.0.50, Packet Summary: ...
2024-11-01 12:02:00 INFO Suspicious Destination IP Address Report:
2024-11-01 12:02:01 INFO Suspicious Destination IP: 8.8.8.8, Number of Suspicious Packets: 5, Domain: google-public-dns-a.google.com, Country: United States
2024-11-01 12:03:00 INFO Tracing Suspicious Destination IP Addresses:
2024-11-01 12:03:01 INFO Traceroute to 8.8.8.8: Hop 1 -> 192.168.1.1
```

## GeoIP Database

The tool uses the `GeoLite2-Country.mmdb` database from MaxMind to determine the country of origin for suspicious IP addresses. You must download the database and place it in the same directory as the script for the country lookup to function correctly.

## Troubleshooting

- **FileNotFoundError**: Ensure the `GeoLite2-Country.mmdb` file is present in the correct directory.
- **Dependencies Issues**: Make sure all the dependencies are installed correctly using the provided `requirements.txt`.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contributing

Feel free to submit issues, fork the repository, and make pull requests. Contributions are always welcome!

## Acknowledgements

- **Scapy**: For packet analysis
- **Loguru**: For simplified logging
- **GeoIP2**: For IP geolocation data
- **MaxMind**: For providing the GeoLite2 Country database

