import time
import random
import csv
import os
import psutil
import joblib
import pandas as pd
import threading
import signal
import sys
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, send
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from collections import deque

# Enhanced configuration
CONFIG = {
    "TRAINING_DURATION": 30,  # seconds per traffic type
    "WINDOW_SIZE": 5,         # seconds for real-time analysis
    "RETRAIN_INTERVAL": 3600, # seconds
    "ANOMALY_THRESHOLD": 0.85, # confidence threshold
    "INTERFACE": "\\Device\\NPF_{ACC2A539-726B-4E5D-9F05-2DD5D12B9301}",
    "MAX_PACKETS": 1000,      # max packets per window
    "SYSTEM_METRICS_INTERVAL": 0.5 # seconds between system metric samples
}

# --- Traffic Simulation and Data Collection Functions ---
def simulate_enterprise_traffic(label, duration=10):
    """More realistic enterprise traffic patterns"""
    print(f"Simulating {label} traffic for {duration} seconds...")
    end = time.time() + duration
    while time.time() < end:
        if label == "normal":
            # Mixed normal traffic (HTTP, DNS, etc)
            if random.random() < 0.7:  # 70% HTTP
                pkt = IP(dst="192.168.1." + str(random.randint(1, 254))) / \
                      TCP(dport=random.choice([80, 443, 8080])) / \
                      Raw(load=random.choice(["GET / HTTP/1.1", "POST /login HTTP/1.1"]))
            else:  # 30% other protocols
                pkt = IP(dst="192.168.1." + str(random.randint(1, 254))) / \
                      random.choice([
                          UDP(dport=53)/Raw(load="DNS Query"),
                          ICMP(),
                          TCP(dport=22)/Raw(load="SSH")
                      ])
        elif label == "ddos":
            # DDoS patterns (UDP flood, SYN flood)
            if random.random() < 0.7:  # 70% UDP flood
                pkt = IP(dst="192.168.1." + str(random.randint(1, 254))) / \
                      UDP(dport=random.randint(1, 65535)) / \
                      Raw(load="X" * random.randint(500, 1500))
            else:  # 30% SYN flood
                pkt = IP(dst="192.168.1." + str(random.randint(1, 254))) / \
                      TCP(flags="S", dport=random.randint(1, 65535))
        elif label == "data_integrity":
            # Data tampering patterns
            if random.random() < 0.5:  # 50% malformed packets
                pkt = IP(dst="192.168.1." + str(random.randint(1, 254))) / \
                      TCP(dport=80) / \
                      Raw(load=random.choice(["INJECTED", "CORRUPT\x00\x01", "EVIL"]))
            else:  # 50% protocol violations
                pkt = IP(dst="192.168.1." + str(random.randint(1, 254))) / \
                      TCP(flags="FA", dport=80) / \
                      Raw(load="GET / HTTP/1.1\r\nHost: badguy.com\r\n\r\n")
        
        send(pkt, verbose=False)
        time.sleep(random.uniform(0.01, 0.2) if label == "ddos" else random.uniform(0.1, 0.5))

def capture_features(label, duration=10):
    """Capture system metrics during traffic simulation"""
    print(f"Capturing system features for {label}...")
    data = []
    end = time.time() + duration
    
    # Start traffic simulation in background
    sim_thread = threading.Thread(target=simulate_enterprise_traffic, args=(label, duration))
    sim_thread.daemon = True
    sim_thread.start()
    
    while time.time() < end:
        # Get system metrics
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_io_counters().read_time + psutil.disk_io_counters().write_time
        net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        
        # Simulate packet capture
        if label == "normal":
            pkt_size = random.randint(64, 300)
            proto = random.choice(['TCP', 'UDP', 'ICMP'])
        elif label == "ddos":
            pkt_size = random.randint(500, 1500)
            proto = random.choice(['UDP', 'TCP'])  # Both UDP floods and SYN floods
        elif label == "data_integrity":
            pkt_size = random.randint(64, 500)
            proto = 'TCP'  # Most data integrity attacks are TCP-based
        
        data.append([time.time(), cpu, mem, disk, net, pkt_size, proto, label])
        time.sleep(0.1)  # Don't sample too frequently
    
    df = pd.DataFrame(data, columns=[
        "timestamp", "cpu", "memory", "disk_io", "network_io", 
        "packet_size", "protocol", "label"
    ])
    return df

class FeatureExtractor:
    def __init__(self):
        self.packet_history = deque(maxlen=1000)
        self.metrics_history = deque(maxlen=100)
        
    def extract_packet_features(self, pkt):
        """Extract comprehensive packet features"""
        features = {
            'size': len(pkt),
            'proto': 'OTHER',
            'flags': 0,
            'src': '0.0.0.0',
            'dst': '0.0.0.0',
            'sport': 0,
            'dport': 0,
            'payload_len': 0
        }
        
        if IP in pkt:
            features['src'] = pkt[IP].src
            features['dst'] = pkt[IP].dst
            
        if TCP in pkt:
            features['proto'] = 'TCP'
            # Convert flags to integer representation
            flags = pkt[TCP].flags
            if isinstance(flags, str):
                # Convert flag string to numeric value
                flag_val = 0
                if 'F' in flags: flag_val += 1
                if 'S' in flags: flag_val += 2
                if 'R' in flags: flag_val += 4
                if 'P' in flags: flag_val += 8
                if 'A' in flags: flag_val += 16
                if 'U' in flags: flag_val += 32
                if 'E' in flags: flag_val += 64
                if 'C' in flags: flag_val += 128
                features['flags'] = flag_val
            else:
                features['flags'] = int(flags)
            features['sport'] = pkt[TCP].sport
            features['dport'] = pkt[TCP].dport
            if Raw in pkt:
                features['payload_len'] = len(pkt[Raw].load)
        elif UDP in pkt:
            features['proto'] = 'UDP'
            features['sport'] = pkt[UDP].sport
            features['dport'] = pkt[UDP].dport
            if Raw in pkt:
                features['payload_len'] = len(pkt[Raw].load)
        elif ICMP in pkt:
            features['proto'] = 'ICMP'
            
        return features
    
    def get_system_metrics(self):
        """Get comprehensive system metrics"""
        return {
            'timestamp': time.time(),
            'cpu': psutil.cpu_percent(interval=0.1),
            'memory': psutil.virtual_memory().percent,
            'disk': psutil.disk_io_counters().read_time + psutil.disk_io_counters().write_time,
            'network': psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv,
            'process_count': len(psutil.pids())
        }

class EnterpriseSecurityTrainer:
    def __init__(self):
        self.scaler = StandardScaler()
        self.protocol_le = LabelEncoder()
        self.label_le = LabelEncoder()
        self.models = {
            "XGBoost": XGBClassifier(
                use_label_encoder=False, 
                eval_metric='mlogloss',
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42
            ),
            "RandomForest": RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                min_samples_split=5,
                class_weight='balanced',
                random_state=42
            ),
            "AnomalyDetector": IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
        }
    
    def preprocess_data(self, df):
        """Enhanced preprocessing with feature engineering"""
        # Protocol encoding
        df['protocol_enc'] = self.protocol_le.fit_transform(df['protocol'])
        
        # Label encoding
        df['label_enc'] = self.label_le.fit_transform(df['label'])
        
        # Feature engineering - match what we'll use in monitoring
        df['cpu_avg'] = df['cpu']
        df['cpu_std'] = df['cpu'].rolling(5).std().fillna(0)
        df['mem_avg'] = df['memory']
        df['packet_count'] = 1  # Will be summed in window
        df['avg_pkt_size'] = df['packet_size']
        df['proto_tcp'] = (df['protocol'] == 'TCP').astype(int)
        df['proto_udp'] = (df['protocol'] == 'UDP').astype(int)
        df['proto_icmp'] = (df['protocol'] == 'ICMP').astype(int)
        df['flag_count'] = 0  # Will be updated in monitoring
        df['unique_ports'] = 1  # Will be calculated in monitoring
        df['payload_ratio'] = 0  # Will be calculated in monitoring
        df['cpu_mem_ratio'] = df['cpu'] / (df['memory'] + 1)
        df['disk_io'] = df['disk_io']
        df['network_io'] = df['network_io']
        
        # Select features that match monitoring features
        features = [
            'cpu_avg', 'cpu_std', 'mem_avg', 'packet_count',
            'avg_pkt_size', 'proto_tcp', 'proto_udp', 'proto_icmp',
            'flag_count', 'unique_ports', 'payload_ratio', 
            'cpu_mem_ratio', 'protocol_enc', 'disk_io', 'network_io'
        ]
        
        X = df[features]
        y = df['label_enc']
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled, y, features
    
    def train(self, df):
        """Train models and save the best one"""
        X, y, features = self.preprocess_data(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
        
        best_model = None
        best_score = 0
        best_name = ""
        
        # Train and evaluate each model
        for name, model in self.models.items():
            print(f"\n--- Training {name} ---")
            
            if name == "AnomalyDetector":
                # Anomaly detector is unsupervised
                model.fit(X_train)
                y_pred = model.predict(X_test)
                y_pred = [1 if x == -1 else 0 for x in y_pred]  # Convert to binary
                y_test_bin = [1 if x != 0 else 0 for x in y_test]  # 0=normal, 1=attack
                
                print("Anomaly Detection Report:")
                print(classification_report(y_test_bin, y_pred))
                score = model.score_samples(X_test).mean()
            else:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                
                print("Classification Report:")
                print(classification_report(y_test, y_pred, target_names=self.label_le.classes_))
                print("Confusion Matrix:")
                print(confusion_matrix(y_test, y_pred))
                
                score = model.score(X_test, y_test)
            
            if score > best_score:
                best_score = score
                best_model = model
                best_name = name
        
        print(f"\n✅ Best model: {best_name} with score: {best_score:.2f}")
        
        # Save artifacts
        joblib.dump(best_model, "enterprise_security_model.pkl")
        joblib.dump(self.scaler, "feature_scaler.pkl")
        joblib.dump(self.protocol_le, "protocol_encoder.pkl")
        joblib.dump(self.label_le, "label_encoder.pkl")
        
        return best_model, best_name, best_score

class EnterpriseSecurityMonitor:
    def __init__(self):
        try:
            self.model = joblib.load("enterprise_security_model.pkl")
            self.scaler = joblib.load("feature_scaler.pkl")
            self.protocol_le = joblib.load("protocol_encoder.pkl")
            self.label_le = joblib.load("label_encoder.pkl")
            self.feature_extractor = FeatureExtractor()
            self.window_start = time.time()
            self.current_window = []
            self.attack_log = []
            self.metrics_buffer = []
            self.alert_thresholds = {
                'ddos': 0.85,
                'data_integrity': 0.9,
                'other': 0.8
            }
        except FileNotFoundError:
            print("Model files not found. Please train models first.")
            sys.exit(1)
    
    def process_packet(self, pkt):
        """Process each packet and manage analysis windows"""
        try:
            # Extract packet features
            pkt_features = self.feature_extractor.extract_packet_features(pkt)
            sys_metrics = self.feature_extractor.get_system_metrics()
            
            # Combine features
            combined = {
                **pkt_features,
                **sys_metrics,
                'timestamp': time.time()
            }
            
            self.current_window.append(combined)
            self.metrics_buffer.append(sys_metrics)
            
            # Check if window should be processed
            if time.time() - self.window_start >= CONFIG['WINDOW_SIZE']:
                self.analyze_window()
                self.current_window.clear()
                self.metrics_buffer.clear()
                self.window_start = time.time()
        except Exception as e:
            print(f"Error processing packet: {e}")

    def analyze_window(self):
        """Analyze the collected window of traffic"""
        if not self.current_window:
            return
            
        try:
            # Calculate window aggregates
            df = pd.DataFrame(self.current_window)
            metrics_df = pd.DataFrame(self.metrics_buffer)
            
            # Feature engineering - must match training features exactly
            features = {
                'cpu_avg': metrics_df['cpu'].mean(),
                'cpu_std': metrics_df['cpu'].std(),
                'mem_avg': metrics_df['memory'].mean(),
                'packet_count': len(df),
                'avg_pkt_size': df['size'].mean(),
                'proto_tcp': len(df[df['proto'] == 'TCP']),
                'proto_udp': len(df[df['proto'] == 'UDP']),
                'proto_icmp': len(df[df['proto'] == 'ICMP']),
                'flag_count': df['flags'].sum(),
                'unique_ports': df['dport'].nunique(),
                'payload_ratio': df['payload_len'].sum() / (df['size'].sum() + 1),
                'cpu_mem_ratio': metrics_df['cpu'].mean() / (metrics_df['memory'].mean() + 1),
                'disk_io': metrics_df['disk'].mean(),
                'network_io': metrics_df['network'].mean()
            }
            
            # Protocol encoding
            most_common_proto = df['proto'].mode()[0] if len(df['proto'].mode()) > 0 else 'TCP'
            if most_common_proto not in self.protocol_le.classes_:
                most_common_proto = 'TCP'
            features['protocol_enc'] = self.protocol_le.transform([most_common_proto])[0]
            
            # Create feature vector in correct order
            feature_order = [
                'cpu_avg', 'cpu_std', 'mem_avg', 'packet_count',
                'avg_pkt_size', 'proto_tcp', 'proto_udp', 'proto_icmp',
                'flag_count', 'unique_ports', 'payload_ratio', 
                'cpu_mem_ratio', 'protocol_enc', 'disk_io', 'network_io'
            ]
            feature_vector = pd.DataFrame([features], columns=feature_order)
            
            # Scale features
            scaled_features = self.scaler.transform(feature_vector)
            
            # Make prediction
            if isinstance(self.model, IsolationForest):
                # Anomaly detection approach
                anomaly_score = self.model.score_samples(scaled_features)[0]
                is_anomaly = anomaly_score < -0.5  # Threshold for anomaly
                
                if is_anomaly:
                    print(f"🚨 ANOMALY DETECTED! Score: {anomaly_score:.2f}")
                    self.log_attack({
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'type': 'ANOMALY',
                        'confidence': 1 - anomaly_score,
                        'features': features
                    })
            else:
                # Classification approach
                proba = self.model.predict_proba(scaled_features)[0]
                pred_class = self.model.predict(scaled_features)[0]
                pred_label = self.label_le.inverse_transform([pred_class])[0]
                confidence = proba.max()
                
                if confidence > self.alert_thresholds.get(pred_label, 0.8):
                    print(f"[{time.strftime('%H:%M:%S')}] Detected: {pred_label} (Confidence: {confidence:.2%})")
                    self.log_attack({
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'type': pred_label,
                        'confidence': confidence,
                        'features': features
                    })
        except Exception as e:
            print(f"Error analyzing window: {e}")

    def log_attack(self, attack_info):
        """Log detected attacks with mitigation suggestions"""
        self.attack_log.append(attack_info)
        
        # Generate mitigation suggestions
        suggestions = {
            'ddos': [
                "Activate rate limiting on network devices",
                "Enable DDoS protection on firewall",
                "Contact ISP about potential attack"
            ],
            'data_integrity': [
                "Inspect network for man-in-the-middle attacks",
                "Verify TLS/SSL certificates",
                "Check for unauthorized protocol modifications"
            ],
            'ANOMALY': [
                "Investigate unusual traffic patterns",
                "Check system logs for suspicious activity",
                "Review recent network changes"
            ]
        }
        
        print(f"\n🚨 SECURITY ALERT: {attack_info['type']}")
        print(f"⏱️ Timestamp: {attack_info['timestamp']}")
        print(f"🛡️ Confidence: {attack_info['confidence']:.2%}")
        print("\n🔍 Recommended Actions:")
        for suggestion in suggestions.get(attack_info['type'], ["Investigate further"]):
            print(f" - {suggestion}")
        
        # Save to CSV
        with open('security_alerts.csv', 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=attack_info.keys())
            if f.tell() == 0:
                writer.writeheader()
            writer.writerow(attack_info)
    
    def start_monitoring(self, interface=None):
        """Start the monitoring system"""
        print(f"🚀 Starting enterprise security monitoring on {interface or 'default interface'}")
        print("Press Ctrl+C to stop...\n")
        
        # Start background metrics collection
        metrics_thread = threading.Thread(target=self.collect_system_metrics, daemon=True)
        metrics_thread.start()
        
        # Start packet capture
        sniff(iface=interface, prn=self.process_packet, store=False)
    
    def collect_system_metrics(self):
        """Continuously collect system metrics in background"""
        while True:
            try:
                metrics = self.feature_extractor.get_system_metrics()
                self.metrics_buffer.append(metrics)
                time.sleep(CONFIG['SYSTEM_METRICS_INTERVAL'])
            except Exception as e:
                print(f"Error collecting metrics: {e}")

def main():
    # Signal handling
    def graceful_exit(signum, frame):
        print("\n🛑 Shutting down enterprise security monitor...")
        if 'monitor' in locals():
            print(f"Total alerts detected: {len(monitor.attack_log)}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    
    # Check if we need to train models
    if not os.path.exists("enterprise_security_model.pkl"):
        print("=== Training Enterprise Security Models ===")
        
        # Generate comprehensive training data
        print("Generating training scenarios...")
        df_normal = capture_features("normal", CONFIG['TRAINING_DURATION'])
        df_ddos = capture_features("ddos", CONFIG['TRAINING_DURATION'])
        df_integrity = capture_features("data_integrity", CONFIG['TRAINING_DURATION'])
        
        df_all = pd.concat([df_normal, df_ddos, df_integrity])
        df_all.to_csv("enterprise_training_data.csv", index=False)
        
        # Train models
        trainer = EnterpriseSecurityTrainer()
        trainer.train(df_all)
    
    # Start monitoring
    print("\n=== Starting Enterprise Security Monitor ===")
    monitor = EnterpriseSecurityMonitor()
    monitor.start_monitoring(interface=CONFIG['INTERFACE'])

if __name__ == "__main__":
    main()