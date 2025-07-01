import grpc
import time
import machine_monitor_pb2
import machine_monitor_pb2_grpc

def send_batch_metrics(stub):
    machines = [
        machine_monitor_pb2.MachineInfo(id="M01", location="Rack A1"),
        machine_monitor_pb2.MachineInfo(id="M02", location="Rack B3"),
        machine_monitor_pb2.MachineInfo(id="M03", location="Rack C2"),
    ]
    
    request = machine_monitor_pb2.MetricsBatchRequest(machines=machines)
    response = stub.SendBatchMetrics(request)
    print(f"Batch Metrics Response:\n{response.summary}")

def stream_live_metrics(stub):
    def metrics_generator():
        for i in range(5):
            yield machine_monitor_pb2.MachineMetrics(
                machine_id="M01", 
                cpu_usage=30.0 + i,
                memory_usage=50.0 + (i * 2),
                network_usage=5.0 + (i * 1.5)
            )
            time.sleep(1)

    responses = stub.StreamLiveMetrics(metrics_generator())
    for response in responses:
        print(f"Live Status Update: {response.status}")

def run():
    with open("certs/client.crt", "rb") as f:
        client_cert = f.read()
    with open("certs/client.key", "rb") as f:
        client_key = f.read()
    with open("certs/ca.crt", "rb") as f:
        ca_cert = f.read()

    credentials = grpc.ssl_channel_credentials(root_certificates=ca_cert, private_key=client_key, certificate_chain=client_cert)
    
    with grpc.secure_channel("localhost:50051", credentials) as channel:
        stub = machine_monitor_pb2_grpc.MachineMonitorStub(channel)
        
        print("Sending batch metrics data...")
        send_batch_metrics(stub)

        print("\nStarting live metrics stream...")
        stream_live_metrics(stub)

if __name__ == "__main__":
    run()
