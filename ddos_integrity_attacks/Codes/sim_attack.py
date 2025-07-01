import time
import random
import pandas as pd
import psutil
import joblib
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, send
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler

# --- Step 1: Traffic simulation and feature capture ---
def simulate_traffic(label, duration=10):
    print(f"Simulating {label} traffic for {duration} seconds...")
    end = time.time() + duration
    while time.time() < end:
        if label == "normal":
            pkt = IP(dst="127.0.0.1") / TCP(dport=80) / Raw(load="GET / HTTP/1.1")
        elif label == "ddos":
            pkt = IP(dst="127.0.0.1") / UDP(dport=80) / Raw(load="X" * 512)
        elif label == "data_integrity":
            pkt = IP(dst="127.0.0.1") / TCP(dport=80) / Raw(load="CORRUPTED DATA")
        else:
            continue
        send(pkt, verbose=False)
        time.sleep(0.1 if label != "ddos" else 0.01)

def capture_features(label, duration=10):
    print(f"Capturing system features for {label}...")
    data = []
    end = time.time() + duration
    while time.time() < end:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent

        if label == "normal":
            pkt_size = random.randint(64, 300)
            proto = random.choice(['TCP', 'UDP'])
        elif label == "ddos":
            pkt_size = random.randint(500, 1500)
            proto = 'UDP'
        elif label == "data_integrity":
            pkt_size = random.randint(64, 500)
            proto = 'TCP'
        else:
            pkt_size = random.randint(64, 1500)
            proto = random.choice(['TCP', 'UDP', 'ICMP'])

        data.append([time.time(), cpu, mem, pkt_size, proto, label])

    df = pd.DataFrame(data, columns=["timestamp", "cpu", "memory", "packet_size", "protocol", "label"])
    return df

def run_and_save(label, duration=10):
    simulate_traffic(label, duration)
    df = capture_features(label, duration)
    filename = f"{label}_traffic.csv"
    df.to_csv(filename, index=False)
    print(f" {label.capitalize()} data saved to {filename}")
    return df

# --- Step 2: Train models and save best ---
def train_models(df):
    print("Training ML models...\n")

    protocol_le = LabelEncoder()
    df['protocol_enc'] = protocol_le.fit_transform(df['protocol'])

    label_le = LabelEncoder()
    df['label_enc'] = label_le.fit_transform(df['label'])

    X = df[["cpu", "memory", "packet_size", "protocol_enc"]]
    y = df["label_enc"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    # Feature scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        "RandomForest": RandomForestClassifier(random_state=42),
        "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42),
        "MLP": MLPClassifier(max_iter=500, random_state=42)
    }

    best_model = None
    best_score = 0
    best_model_name = ""

    for name, model in models.items():
        print(f"\n--- Training: {name} ---")
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
        print(f" Evaluation for {name}")
        print(classification_report(y_test, y_pred, target_names=label_le.classes_))

        score = model.score(X_test_scaled, y_test)
        if score > best_score:
            best_score = score
            best_model = model
            best_model_name = name

    print(f"\n Best model: {best_model_name} with accuracy: {best_score:.2f}")

    # Save model, encoders, and scaler
    joblib.dump(best_model, "best_model.pkl")
    joblib.dump(protocol_le, "protocol_label_encoder.pkl")
    joblib.dump(label_le, "label_label_encoder.pkl")
    joblib.dump(scaler, "scaler.pkl")

# --- Step 3: Real-time classification ---
class RealTimeClassifier:
    def __init__(self, model_path="best_model.pkl",
                 protocol_le_path="protocol_label_encoder.pkl",
                 label_le_path="label_label_encoder.pkl",
                 scaler_path="scaler.pkl",
                 window_duration=5):
        self.model = joblib.load(model_path)
        self.protocol_le = joblib.load(protocol_le_path)
        self.label_le = joblib.load(label_le_path)
        self.scaler = joblib.load(scaler_path)
        self.window_duration = window_duration
        self.feature_buffer = []
        self.window_start = time.time()

    def extract_packet_features(self, pkt):
        pkt_size = len(pkt)
        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "OTHER"
        return pkt_size, proto

    def aggregate_features(self):
        if not self.feature_buffer:
            return None

        cpu_avg = sum(f['cpu'] for f in self.feature_buffer) / len(self.feature_buffer)
        mem_avg = sum(f['mem'] for f in self.feature_buffer) / len(self.feature_buffer)
        avg_pkt_size = sum(f['pkt_size'] for f in self.feature_buffer) / len(self.feature_buffer)

        proto_counts = {"TCP":0, "UDP":0, "ICMP":0, "OTHER":0}
        for f in self.feature_buffer:
            proto_counts[f['proto']] += 1

        most_common_proto = max(proto_counts, key=proto_counts.get)
        if most_common_proto not in self.protocol_le.classes_:
            most_common_proto = "TCP"  # fallback

        proto_enc = self.protocol_le.transform([most_common_proto])[0]
        return [cpu_avg, mem_avg, avg_pkt_size, proto_enc]

    def classify_window(self):
        features = self.aggregate_features()
        if features is None:
            print("No packets captured.")
            return

        X_input = pd.DataFrame([features], columns=["cpu", "memory", "packet_size", "protocol_enc"])
        X_input_scaled = self.scaler.transform(X_input)

        y_pred_enc = self.model.predict(X_input_scaled)[0]
        y_pred_label = self.label_le.inverse_transform([y_pred_enc])[0]
        print(f"[{time.strftime('%X')}] Detected traffic type: {y_pred_label}")

    def packet_handler(self, pkt):
        pkt_size, proto = self.extract_packet_features(pkt)
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory().percent

        self.feature_buffer.append({
            'pkt_size': pkt_size,
            'proto': proto,
            'cpu': cpu,
            'mem': mem,
            'timestamp': time.time()
        })

        if time.time() - self.window_start >= self.window_duration:
            self.classify_window()
            self.feature_buffer.clear()
            self.window_start = time.time()

    def start_sniffing(self, iface=None):
        print(f"🚀 Starting real-time sniffing on interface: {iface if iface else 'default'}")
        sniff(iface=iface, prn=self.packet_handler, store=False)

# --- Main Execution ---
if __name__ == "__main__":
    df_normal = run_and_save("normal", duration=10)
    df_ddos = run_and_save("ddos", duration=10)
    df_data_integrity = run_and_save("data_integrity", duration=10)

    df_all = pd.concat([df_normal, df_ddos, df_data_integrity], ignore_index=True)
    df_all.to_csv("combined_attack_data.csv", index=False)
    print(" All traffic saved to combined_attack_data.csv")

    train_models(df_all)

    rtc = RealTimeClassifier(window_duration=5)
    rtc.start_sniffing(iface="\\Device\\NPF_{ACC2A539-726B-4E5D-9F05-2DD5D12B9301}")  # You can set iface="Wi-Fi" or "Ethernet" if needed
