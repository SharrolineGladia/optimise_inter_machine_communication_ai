import socket
import time
import psutil
import csv
from datetime import datetime
import os

SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432
NUM_REQUESTS = 100  
BASE_DIR = 'scenario_logs'

# Step 1: Let user choose a scenario
def choose_scenario():
    print("\nChoose a scenario to simulate:")
    print("1. Normal")
    print("2. High Latency")
    print("3. Packet Loss")
    print("4. Low Bandwidth")
    print("5. Mixed Anomalies")

    choice = input("Enter option number: ").strip()
    scenarios = {
        "1": "Normal",
        "2": "High Latency",
        "3": "Packet Loss",
        "4": "Low Bandwidth",
        "5": "Mixed Anomalies"
    }
    return scenarios.get(choice, "Normal")

def get_network_throughput():
    net1 = psutil.net_io_counters()
    time.sleep(1)
    net2 = psutil.net_io_counters()
    bytes_sent = net2.bytes_sent - net1.bytes_sent
    bytes_recv = net2.bytes_recv - net1.bytes_recv
    return bytes_sent + bytes_recv

def run_client():
    scenario = choose_scenario()
    print(f"\n🧪 Scenario selected: {scenario}")
    packet_loss_count = 0
    data_logged = []

    # Create directory if not exists
    os.makedirs(BASE_DIR, exist_ok=True)
    file_path = os.path.join(BASE_DIR, f"{scenario.lower().replace(' ', '_')}_metrics.csv")
    file_exists = os.path.isfile(file_path)

    for i in range(NUM_REQUESTS):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)  # 2 seconds timeout
            start = time.time()
            s.connect((SERVER_IP, SERVER_PORT))
            end = time.time()
            latency = round((end - start) * 1000, 2)  # ms
            connection_status = 'Success'

            # Send larger message to simulate real traffic
            message = "X" * 10000  # 10 KB
            s.sendall(message.encode())
            recv_data = s.recv(10240)
            data_size_bytes = len(recv_data)

            # Data Rate in Mbps with higher precision
            data_rate_mbps = round((data_size_bytes * 8) / (latency / 1000) / 1e6, 5) if latency > 0 else 0.0

            source_ip = s.getsockname()[0]
            dest_ip = SERVER_IP

            s.close()

        except (socket.timeout, ConnectionRefusedError, socket.error):
            latency = 0
            data_rate_mbps = 0.0
            connection_status = 'Fail'
            packet_loss_count += 1
            source_ip = 'N/A'
            dest_ip = 'N/A'
            data_size_bytes = 0

        cpu_usage = psutil.cpu_percent(interval=0.5)
        mem_usage = psutil.virtual_memory().percent
        net_throughput = get_network_throughput()
        timestamp = datetime.now().strftime("%H:%M:%S")

        data_logged.append([
            timestamp, latency, round((packet_loss_count / (i + 1)) * 100, 2),
            data_rate_mbps, connection_status, source_ip, dest_ip,
            cpu_usage, mem_usage, net_throughput, scenario
        ])

        time.sleep(1)

    # Write or append data to CSV
    with open(file_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow([
                "Timestamp", "Latency(ms)", "Packet Loss(%)", "Data Rate(Mbps)",
                "Connection Status", "Source IP", "Destination IP",
                "CPU Usage(%)", "Memory Usage(%)", "Network Throughput(Bytes)", "Scenario"
            ])
        writer.writerows(data_logged)

    print(f"\nMetrics collection complete. Data saved to '{file_path}'")

if __name__ == '__main__':
    run_client()
