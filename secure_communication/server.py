import grpc
from concurrent import futures
import time
import machine_monitor_pb2
import machine_monitor_pb2_grpc

# Mock performance summary generator
def generate_machine_summary(machine):
    return f"Machine {machine.id} in {machine.location}: CPU 35%, Memory 60%, Network 10%"

class MachineMonitorServicer(machine_monitor_pb2_grpc.MachineMonitorServicer):
    def SendBatchMetrics(self, request, context):
        print("Processing batch metrics request...")
        summaries = [generate_machine_summary(machine) for machine in request.machines]
        summary_text = "\n".join(summaries)
        return machine_monitor_pb2.MetricsBatchResponse(summary=summary_text)

    def StreamLiveMetrics(self, request_iterator, context):
        for metrics in request_iterator:
            print(f"Live Metrics from {metrics.machine_id} -> CPU: {metrics.cpu_usage}%, Memory: {metrics.memory_usage}%, Network: {metrics.network_usage}%")
            yield machine_monitor_pb2.StatusUpdate(status=f"Machine {metrics.machine_id}: OK")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    machine_monitor_pb2_grpc.add_MachineMonitorServicer_to_server(MachineMonitorServicer(), server)

    server_credentials = grpc.ssl_server_credentials((
        (open("certs/server.key", "rb").read(), open("certs/server.crt", "rb").read()),
    ))
    server.add_secure_port("[::]:50051", server_credentials)

    print("Machine Monitor Server is running securely on port 50051...")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
