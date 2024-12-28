import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.preprocessing import StandardScaler
#from sklearn.metrics import pairwise_distances_argmin_min
import matplotlib.pyplot as plt
#import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix
import time
import math
from collections import defaultdict
import logging

# veri setini yükle
df = pd.read_csv("input.csv")
#df.drop(columns=["attack_type"])

# 2. veri önişleme
# verisetinde boş değer olup olmadığını kontrol et
#print(df.isnull().sum())
#tcp flag sütununda bulunan boş verileri yenii bir kategori ile doldur
df["tcp_flags"] = df["tcp_flags"].fillna("NOFLAG")
# sns.countplot(x='label', data=df)
# plt.title('Distribution of TCP Flags')
# plt.show()

# 2.1 ketegorik verileri etiketle (label encoding)
label_encoder = LabelEncoder()
categorical_columns = df.select_dtypes(include=["object", "category"]).columns
for col in categorical_columns:
    df[col] = label_encoder.fit_transform(df[col])

# 2.2 normalizasyon
numerical_columns = (
    df.drop(columns=["label"])
    .select_dtypes(include=["int64", "float64"])
    .columns
)
scaler = StandardScaler()
df[numerical_columns] = scaler.fit_transform(df[numerical_columns])

#print(df.tail())

kmeans = KMeans(n_clusters=2, max_iter=500, random_state=42, algorithm="lloyd")  
kmeans.fit(df)


#df['cluster'] = kmeans.labels_
distances = kmeans.transform(df)
distances = np.linalg.norm(distances, axis=1)
threshold = np.percentile(distances, 90)
df['cluster'] = kmeans.predict(df)
df['anomaly'] = distances > threshold
#print(df.tail())
# print(df.tail())
#true_labels = df['label']
#predicted_labels = df['anomaly'].astype(int)
print("Confusion Matrix:")
print(confusion_matrix(df['label'], df['cluster']))

print("\nClassification Report:")
print(classification_report(df['label'], df['cluster'], target_names=['Normal', 'Anormal']))

plt.scatter(df.index, distances, c=df['cluster'], cmap='coolwarm', alpha=0.7)
plt.axhline(threshold, color='red', linestyle='--')
plt.title('Anomaly Detection in Network Traffic')
plt.xlabel('Data Points')
plt.ylabel('Distance from Cluster Center')
plt.show()

def calculate_entropy(data):
    if not data:
        return 0
    frequency = defaultdict(int)
    for item in data:
        frequency[item] += 1
    entropy = -sum((freq / len(data)) * math.log2(freq / len(data)) for freq in frequency.values())
    return entropy

def preprocess_packet(packet):
    global traffic_stats, labeled_data
    current_time = time.time()
    # Extract features (adjust based on your model's requirements)
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_length = len(packet)

        traffic_stats[src_ip]["count"] += 1
        traffic_stats[src_ip]["packet_sizes"].append(packet_length)
        traffic_stats[src_ip]["timestamps"].append(current_time)
        if len(traffic_stats[src_ip]["timestamps"]) > 1:
            inter_packet_time = current_time - traffic_stats[src_ip]["timestamps"][-2]
        else:
            inter_packet_time = 0
        size_entropy = calculate_entropy(traffic_stats[src_ip]["packet_sizes"])
    features = {
        "timestamp": packet.time,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": packet.summary().split(" ")[0], 
        "length": packet_length,
        "tcp_flags": packet[TCP].flags if TCP in packet else None,
        "duration": packet.time - traffic_stats[src_ip]["timestamps"][0],
        "inter_packet_time": inter_packet_time,
        "size_entropy": size_entropy,
    }

    # Create a feature array
    #feature_array = np.array([features["src_port"], features["dst_port"], features["packet_length"], features["flags"]]).reshape(1, -1)
    feature_array = np.array([features[key] for key in features.keys()]).reshape(1, -1)
    # Scale features
    return scaler.transform(feature_array)


logging.basicConfig(filename="anomaly_log.txt", level=logging.WARNING, 
                    format="%(asctime)s - %(message)s")

def analyze_packet(packet):
    try:
        # Preprocess the packet
        features = preprocess_packet(packet)

        # Predict cluster and calculate distance
        cluster = kmeans.predict(features)[0]
        distance = np.linalg.norm(kmeans.transform(features))
        is_anomaly = distance > threshold

        if is_anomaly:
            warning_message = f"WARNING: Anomaly detected! Packet Info: {packet.summary()}, Distance={distance:.2f}"
            print(warning_message)
            logging.warning(warning_message)
        else:
            print(f"Normal Packet: Distance={distance:.2f}, Cluster={cluster}")
    except Exception as e:
        print(f"Error processing packet: {e}")

# Define a function to sniff and analyze packets
def packet_sniffer(packet):
    if IP in packet:  # Ensure it's an IP packet
        analyze_packet(packet)

# Start sniffing packets (e.g., on eth0)
print("Starting packet sniffing...")
sniff(filter="ip", iface="eth0", prn=packet_sniffer, store=0)
