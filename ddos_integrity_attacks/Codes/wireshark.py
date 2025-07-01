import time
import csv
import os
import psutil
import joblib
import pandas as pd
import threading
import signal
import sys
from scapy.all import sniff, TCP, UDP, ICMP
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder

# --- Training Function ---
def train_models(df):
    print("🚀 Training models on provided dataset...")
    protocol_le = LabelEncoder()
    df['protocol_enc'] = protocol_le.fit_transform(df['protocol'])

    label_le = LabelEncoder()
    df['label_enc'] = label_le.fit_transform(df['label'])

    X = df[["cpu", "memory", "packet_size", "protocol_enc"]]
    y = df["label_enc"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    models = {
        "RandomForest": RandomForestClassifier(random_state=42),
        "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42),
        "MLP": MLPClassifier(max_iter=500, random_state=42)
    }

    best_model = None
    best_score = 0

    for name, model in models.items():
        print(f"\n--- Training: {name} ---")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        print(f"✅ Evaluation for {name}")
        print(classification_report(y_test, y_pred, target_names=label_le.classes_))

        score = model.score(X_test, y_test)
        if score > best_score:
            best_score = score
            best_model = model
            best_model_name = name

    print(f"\n🔥 Best model: {best_model_name} with accuracy: {best_score:.2f}")
    joblib.dump(best_model, "best_model.pkl")
    joblib.dump(protocol_le, "protocol_label_encoder.pkl")
    joblib.dump(label_le, "label_label_encoder.pkl")
    print("✅ Model and encoders saved.")


# --- Real-time Classifier ---
class RealTimeClassifier:
    def __init__(self, window_duration=5, csv_path="realtime_classified_traffic.csv"):
        print("📦 Loading model and encoders...")
        if not os.path.exists("best_model.pkl"):
            print("❌ Model not found. Please train first using 'train' mode.")
            sys.exit(1)
        self.model = joblib.load("best_model.pkl")
        self.protocol_le = joblib.load("protocol_label_encoder.pkl")
        self.label_le = joblib.load("label_label_encoder.pkl")

        self.window_duration = window_duration
        self.feature_buffer = []
        self.window_start = time.time()
        self.csv_path = csv_path

        if not os.path.exists(self.csv_path):
            with open(self.csv_path, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'cpu', 'memory', 'packet_size', 'protocol', 'predicted_label'])

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
        pkt_sizes = [f['pkt_size'] for f in self.feature_buffer]
        avg_pkt_size = sum(pkt_sizes) / len(pkt_sizes)

        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        for f in self.feature_buffer:
            proto_counts[f['proto']] += 1

        features = [
            cpu_avg, mem_avg, avg_pkt_size,
            proto_counts["TCP"], proto_counts["UDP"], proto_counts["ICMP"], proto_counts["OTHER"]
        ]
        return features

    def classify_window(self):
        features = self.aggregate_features()
        if features is None:
            print("No packets captured in window.")
            return

        proto_counts = features[3:]
        max_proto_index = proto_counts.index(max(proto_counts))
        proto_mapping = {0: "TCP", 1: "UDP", 2: "ICMP", 3: "OTHER"}
        most_common_proto = proto_mapping[max_proto_index]

        proto_enc = self.protocol_le.transform([most_common_proto])[0]
        X = pd.DataFrame([[features[0], features[1], features[2], proto_enc]],
                         columns=["cpu", "memory", "packet_size", "protocol_enc"])

        y_pred_enc = self.model.predict(X)[0]
        y_pred_label = self.label_le.inverse_transform([y_pred_enc])[0]

        print(f"[{time.strftime('%X')}] Detected traffic type: {y_pred_label}")

        with open(self.csv_path, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                time.strftime('%Y-%m-%d %H:%M:%S'),
                features[0], features[1], features[2],
                most_common_proto,
                y_pred_label
            ])

    def packet_handler(self, pkt):
        pkt_size, proto = self.extract_packet_features(pkt)
        cpu = psutil.cpu_percent(interval=0)
        mem = psutil.virtual_memory().percent

        self.feature_buffer.append({'pkt_size': pkt_size, 'proto': proto, 'cpu': cpu, 'mem': mem})

        if time.time() - self.window_start >= self.window_duration:
            self.classify_window()
            self.feature_buffer.clear()
            self.window_start = time.time()

    def start_sniffing(self, iface=None):
        print(f"📡 Starting real-time sniffing on: {iface if iface else 'default'}")
        sniff(iface=iface, prn=self.packet_handler, store=False)


# --- Retraining ---
def retrain_from_realtime(csv_file="realtime_classified_traffic.csv"):
    if not os.path.exists(csv_file):
        print(f"No CSV file '{csv_file}' found for retraining.")
        return
    df = pd.read_csv(csv_file)
    if df.empty:
        print(f"CSV file '{csv_file}' is empty, skipping retraining.")
        return
    df = df.rename(columns={"predicted_label": "label"})
    train_models(df)
    print("✅ Model retrained with real-time traffic.")


def periodic_retraining(interval_sec=3600):
    while True:
        time.sleep(interval_sec)
        print(f"⏳ Retraining model from real-time CSV after {interval_sec} seconds...")
        retrain_from_realtime()


def graceful_exit(signum, frame):
    print("\n🛑 Signal received, stopping sniffing and retraining before exit...")
    retrain_from_realtime()
    print("👋 Exiting now.")
    sys.exit(0)


def classify_wireshark_csv(csv_file):
    print(f"🔍 Classifying Wireshark CSV traffic from: {csv_file}")

    if not os.path.exists("best_model.pkl"):
        print("❌ Model not found. Please train first using 'train' mode.")
        sys.exit(1)

    model = joblib.load("best_model.pkl")
    protocol_le = joblib.load("protocol_label_encoder.pkl")
    label_le = joblib.load("label_label_encoder.pkl")

    df = pd.read_csv(csv_file)
    df = df.rename(columns={'Protocol': 'protocol', 'Length': 'packet_size'})

    known_protocols = set(protocol_le.classes_)
    df['protocol'] = df['protocol'].apply(lambda x: x if x in known_protocols else protocol_le.classes_[0])

    df['cpu'] = 0
    df['memory'] = 0
    df['protocol_enc'] = protocol_le.transform(df['protocol'])

    X = df[['cpu', 'memory', 'packet_size', 'protocol_enc']]
    y_pred_enc = model.predict(X)
    y_pred_label = label_le.inverse_transform(y_pred_enc)

    df['predicted_label'] = y_pred_label
    print(df[['protocol', 'packet_size', 'predicted_label']].head(20))

    df.to_csv("classified_wireshark_traffic.csv", index=False)
    print(f"✅ Classified results saved to 'classified_wireshark_traffic.csv'.")


# --- MAIN ---
if __name__ == "__main__":
    import argparse

    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    parser = argparse.ArgumentParser(description="Network Traffic Classifier")
    parser.add_argument('mode', choices=['train', 'sniff', 'classify', 'retrain'], help="Mode to run")
    parser.add_argument('--file', help="CSV file for 'train' or 'classify' mode")
    args = parser.parse_args()

    if args.mode == "train":
        if not args.file:
            print("❌ Please provide a dataset CSV with --file")
            sys.exit(1)
        train_models(pd.read_csv(args.file))

    elif args.mode == "sniff":
        rtc = RealTimeClassifier(window_duration=5)
        threading.Thread(target=periodic_retraining, args=(3600,), daemon=True).start()
        rtc.start_sniffing(iface=None)

    elif args.mode == "classify":
        if not args.file:
            print("❌ Please provide a Wireshark CSV with --file")
            sys.exit(1)
        classify_wireshark_csv(args.file)

    elif args.mode == "retrain":
        retrain_from_realtime()
