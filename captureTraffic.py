from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import pandas as pd
import math
import time

# Dictionary to store statistics for inter-packet timing and entropy
traffic_stats = defaultdict(lambda: {"count": 0, "ports": set(), "timestamps": [], "packet_sizes": []})

# Thresholds for attack detection
PING_THRESHOLD = 100  # ICMP packets per second
SYN_THRESHOLD = 50    # SYN packets per second
SCAN_THRESHOLD = 20   # Different ports accessed per second

# List to store labeled packet data
labeled_data = []

# Function to calculate entropy
def calculate_entropy(data):
    if not data:
        return 0
    frequency = defaultdict(int)
    for item in data:
        frequency[item] += 1
    entropy = -sum((freq / len(data)) * math.log2(freq / len(data)) for freq in frequency.values())
    return entropy

# Callback function to analyze packets
def analyze_packet(packet):
    global traffic_stats, labeled_data
    current_time = time.time()
    label = "Normal"  # Default label

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_length = len(packet)

            # Update traffic stats
            traffic_stats[src_ip]["count"] += 1
            traffic_stats[src_ip]["packet_sizes"].append(packet_length)
            traffic_stats[src_ip]["timestamps"].append(current_time)

            # Inter-packet timing
            if len(traffic_stats[src_ip]["timestamps"]) > 1:
                inter_packet_time = current_time - traffic_stats[src_ip]["timestamps"][-2]
            else:
                inter_packet_time = 0

            # Calculate packet entropy
            size_entropy = calculate_entropy(traffic_stats[src_ip]["packet_sizes"])

            # Analyze ICMP (Ping Flood)
            if ICMP in packet:
                if traffic_stats[src_ip]["count"] > PING_THRESHOLD:
                    label = "Ping Flood"

            # Analyze TCP SYN (SYN Flood)
            elif TCP in packet and packet[TCP].flags == "S":
                if traffic_stats[src_ip]["count"] > SYN_THRESHOLD:
                    label = "SYN Flood"

            # Port Scan Detection
            if TCP in packet or UDP in packet:
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                traffic_stats[src_ip]["ports"].add(dst_port)
                if len(traffic_stats[src_ip]["ports"]) > SCAN_THRESHOLD:
                    label = "Port Scan"

            # Log packet details with features
            labeled_data.append({
                "timestamp": packet.time,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": packet.summary().split(" ")[0],  # Extract protocol
                "length": packet_length,
                "tcp_flags": packet[TCP].flags if TCP in packet else None,
                "duration": packet.time - traffic_stats[src_ip]["timestamps"][0],
                "src_bytes": src_bytes,
                "dst_bytes": dst_bytes,
                "serror_rate": serror_rate,
                "srv_count": srv_count,
                "inter_packet_time": inter_packet_time,
                "size_entropy": size_entropy,
                "label": label
            })

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing packets
print("Capturing traffic... Press Ctrl+C to stop.")
try:
    sniff(filter="ip", iface="enp0s3", prn=analyze_packet, store=False)
except KeyboardInterrupt:
    print("Packet capture stopped.")

# Save labeled data to CSV
df = pd.DataFrame(labeled_data)
df.to_csv("labeled_traffic_dataset.csv", index=False)
print("Enhanced labeled traffic saved to 'labeled_traffic_dataset.csv'.")

