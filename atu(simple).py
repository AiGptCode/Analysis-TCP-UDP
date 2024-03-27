from scapy.all import *
import threading
from sklearn.ensemble import IsolationForest
import numpy as np

# Global variables for storing features and model
features = []
model = IsolationForest(contamination=0.05)

# Function to process packets and extract features
def process_packet(packet):
    if IP in packet:
        if TCP in packet:
            features.append([packet[IP].len, packet[TCP].sport, packet[TCP].dport])
        elif UDP in packet:
            features.append([packet[IP].len, packet[UDP].sport, packet[UDP].dport])

# Function to train the anomaly detection model
def train_model():
    global model
    X_train = np.array(features)
    model.fit(X_train)

# Function to monitor traffic and detect anomalies
def traffic_monitor():
    sniff(filter="(tcp or udp)", prn=process_packet)
    train_model()

# Function to send alerts
def send_alert(alert_type, description):
    print(f"Alert: {alert_type} - {description}")

# Start a separate thread to monitor traffic and train the model
traffic_thread = threading.Thread(target=traffic_monitor)
traffic_thread.start()

# Function to detect anomalies in real-time traffic
def detect_anomalies(packet):
    global model
    if IP in packet:
        if TCP in packet:
            features_test = [[packet[IP].len, packet[TCP].sport, packet[TCP].dport]]
            y_pred = model.predict(features_test)
            if y_pred[0] == -1:
                send_alert("Anomaly detected", f"Possible malicious TCP connection from {packet[IP].src} to {packet[IP].dst}")
        elif UDP in packet:
            features_test = [[packet[IP].len, packet[UDP].sport, packet[UDP].dport]]
            y_pred = model.predict(features_test)
            if y_pred[0] == -1:
                send_alert("Anomaly detected", f"Possible malicious UDP connection from {packet[IP].src} to {packet[IP].dst}")

# Start sniffing in real-time and detect anomalies
sniff(filter="(tcp or udp)", prn=detect_anomalies)
