from scapy.all import rdpcap, IP, TCP, UDP, ARP, ICMP, DNS, traceroute
from loguru import logger
from collections import Counter
import socket
import geoip2.database

# Set up logger to write to a file
logger.add("security.log", format="{time} {level} {message}", level="DEBUG", rotation="1 MB", compression="zip")

# Load the GeoIP database for country lookup
geoip_db_path = 'GeoLite2-Country.mmdb'
geoip_reader = geoip2.database.Reader(geoip_db_path)

# Load the uploaded pcapng file for analysis
file_path = 'cosmic.pcapng'

# Read the pcapng file
packets = rdpcap(file_path)

# Analyze for common security concerns, such as:
# - Protocol analysis (identify protocols used in the capture)
# - Check for any unusual or potentially malicious traffic patterns
# - Identify any unencrypted sensitive data
# - Check for any IP address anomalies, such as private IPs in public address spaces
# - Look for any suspicious port usage or known insecure protocols
# - Detect ARP spoofing or unusual ICMP requests
# - Identify potential DNS tunneling or exfiltration attempts

# Initialize variables for the analysis summary
protocols_summary = {}
suspicious_packets = []
unencrypted_packets = []
arp_spoofing_attempts = []
dns_exfiltration_attempts = []
suspicious_ips = Counter()
suspicious_dest_ips = Counter()

# List of commonly hacked ports
hackable_ports = [20, 21, 22, 23, 25, 53, 69, 80, 109, 110, 111, 135, 137, 139, 143, 161, 389, 443, 445, 512, 513, 514, 543, 544, 548, 631, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 4444, 5432, 5900, 5984, 6379, 8080, 8443, 9000]

# Iterate through packets and gather information
for packet in packets:
    # Capture protocol information
    protocol = packet.payload.name
    if protocol in protocols_summary:
        protocols_summary[protocol] += 1
    else:
        protocols_summary[protocol] = 1
    
    # Check for potential issues:
    # 1. Identify unencrypted traffic (e.g., HTTP, FTP without SSL, Telnet)
    if protocol in ["HTTP", "FTP", "Telnet"] and not packet.haslayer("SSL") and not packet.haslayer("TLS"):
        unencrypted_packets.append(packet)
    
    # 2. Flag potential suspicious activity (unusual ports, IPs, or flags)
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.dport in hackable_ports:  # Check against list of commonly hacked ports
            suspicious_packets.append((packet, f"Suspicious port usage: {tcp_layer.dport}"))
            if packet.haslayer(IP):
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1
        if tcp_layer.flags == "S" and tcp_layer.dport > 1024:  # Potential SYN scan
            suspicious_packets.append((packet, "Potential SYN scan"))
            if packet.haslayer(IP):
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1
    
    # 3. Check for ARP spoofing (multiple IPs mapping to the same MAC address)
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        if arp_layer.op == 2:  # ARP response
            if arp_layer.psrc in protocols_summary and protocols_summary[arp_layer.psrc] != arp_layer.hwsrc:
                arp_spoofing_attempts.append(packet)
            protocols_summary[arp_layer.psrc] = arp_layer.hwsrc
    
    # 4. Detect DNS exfiltration or anomalies (e.g., large DNS requests or unusual domains)
    if packet.haslayer(UDP) and packet.haslayer(DNS):
        udp_layer = packet[UDP]
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:  # DNS query
            if len(dns_layer.qd.qname) > 50:  # Suspiciously long DNS names
                dns_exfiltration_attempts.append(packet)
            # Check for unusual domain patterns, such as multiple subdomains or non-standard TLDs
            domain_name = dns_layer.qd.qname.decode("utf-8")
            subdomain_count = domain_name.count(".")
            if subdomain_count > 3 or domain_name.endswith(('.xyz', '.top', '.info')):
                dns_exfiltration_attempts.append(packet)
    
    # 5. Identify suspicious ICMP packets (e.g., ICMP tunneling or unusual types)
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        if icmp_layer.type not in [0, 8]:  # ICMP types other than Echo Request/Reply
            suspicious_packets.append((packet, f"Suspicious ICMP type: {icmp_layer.type}"))
            if packet.haslayer(IP):
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1
        # Check for unusually large ICMP payloads, which may indicate tunneling
        if len(packet[ICMP].payload) > 100:  # Arbitrary threshold for large payload
            suspicious_packets.append((packet, "Large ICMP payload"))
            if packet.haslayer(IP):
                suspicious_ips[packet[IP].src] += 1
                suspicious_dest_ips[packet[IP].dst] += 1

# Summarize findings for potential issues and security concerns
analysis_summary = {
    "protocol_usage": protocols_summary,
    "unencrypted_traffic_count": len(unencrypted_packets),
    "suspicious_activity_count": len(suspicious_packets),
    "arp_spoofing_attempts_count": len(arp_spoofing_attempts),
    "dns_exfiltration_attempts_count": len(dns_exfiltration_attempts),
}

logger.info(f"Analysis Summary: {analysis_summary}")

# Additional detailed reporting for specific issues
logger.info(f"Unencrypted Traffic Packets: {len(unencrypted_packets)}")
logger.info(f"Suspicious Packets: {len(suspicious_packets)}")
logger.info(f"ARP Spoofing Attempts: {len(arp_spoofing_attempts)}")
logger.info(f"DNS Exfiltration Attempts: {len(dns_exfiltration_attempts)}")

# Provide more details for suspicious packets
if suspicious_packets:
    logger.info("Suspicious Packet Details:")
    for pkt, reason in suspicious_packets:
        if pkt.haslayer(IP):
            logger.info(f"Reason: {reason}, Source IP: {pkt[IP].src}, Destination IP: {pkt[IP].dst}, Packet Summary: {pkt.summary()}")
        else:
            logger.info(f"Reason: {reason}, Packet Summary: {pkt.summary()}")

# Provide more details for DNS exfiltration attempts
if dns_exfiltration_attempts:
    logger.info("DNS Exfiltration Attempt Details:")
    for pkt in dns_exfiltration_attempts:
        dns_layer = pkt[DNS]
        domain_name = dns_layer.qd.qname.decode("utf-8")
        if pkt.haslayer(IP):
            logger.info(f"Domain: {domain_name}, Source IP: {pkt[IP].src}")
        elif domain_name.endswith(".local."):  # Likely mDNS traffic
            logger.info(f"Domain: {domain_name}, Source IP: Multicast (mDNS)")
        else:
            logger.info(f"Domain: {domain_name}, Source IP: Not available")

# Report on the origin of suspicious IP addresses
if suspicious_ips:
    logger.info("Suspicious IP Address Report:")
    for ip, count in suspicious_ips.items():
        logger.info(f"Suspicious IP: {ip}, Number of Suspicious Packets: {count}")

# Report on the destination of suspicious IP addresses
if suspicious_dest_ips:
    logger.info("Suspicious Destination IP Address Report:")
    for ip, count in suspicious_dest_ips.items():
        try:
            # Perform domain name lookup
            domain_name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            domain_name = "Unknown"
        try:
            # Get country information using GeoIP
            response = geoip_reader.country(ip)
            country = response.country.name
        except geoip2.errors.AddressNotFoundError:
            country = "Unknown"
        logger.info(f"Suspicious Destination IP: {ip}, Number of Suspicious Packets: {count}, Domain: {domain_name}, Country: {country}")

# Trace the path of suspicious destination IP addresses
if suspicious_dest_ips:
    logger.info("Tracing Suspicious Destination IP Addresses:")
    for ip in suspicious_dest_ips.keys():
        try:
            res, _ = traceroute([ip], maxttl=20, verbose=False)
            for snd, rcv in res:
                logger.info(f"Traceroute to {ip}: Hop {snd.ttl} -> {rcv.src}")
        except Exception as e:
            logger.error(f"Failed to trace IP {ip}: {e}")

# Close the GeoIP reader
geoip_reader.close()
