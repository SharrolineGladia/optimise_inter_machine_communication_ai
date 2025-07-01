# Secure Inter-Machine Communication with gRPC and mTLS

This project demonstrates secure, authenticated, and encrypted communication between machines using **gRPC** and **mutual TLS (mTLS)** in Python.

## Features

- **gRPC** for efficient, language-agnostic RPC communication.
- **Mutual TLS (mTLS)** for strong authentication and encrypted data transfer.
- Example client and server implementations.
- Protobuf-based message definitions.

---

## Prerequisites

- Python 3.7+
- `pip` (Python package manager)
- OpenSSL (for generating certificates)

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/SharrolineGladia/optimise_inter_machine_communication_ai.git
cd optimise_inter_machine_communication_ai/secure_communication
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 3. Generate Certificates for mTLS

You need a CA, server, and client certificates. Here’s a quick guide using OpenSSL:

```bash
# Create certs directory
mkdir certs

# Generate CA key and certificate
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 -out certs/ca.crt -subj "/CN=Test CA"

# Generate server key and CSR
openssl genrsa -out certs/server.key 4096
openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=localhost"

# Sign server CSR with CA
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 3650 -sha256

# Generate client key and CSR
openssl genrsa -out certs/client.key 4096
openssl req -new -key certs/client.key -out certs/client.csr -subj "/CN=client"

# Sign client CSR with CA
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client.crt -days 3650 -sha256
```

**Note:**  
- The server and client will look for certificates in the `certs/` directory.

---

### 4. (Optional) Regenerate gRPC Python files

If you modify `machine_monitor.proto`, regenerate the Python files:

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. machine_monitor.proto
```

---

## Running the Server

```bash
python server.py
```

## Running the Client

In a separate terminal:

```bash
python client.py
```

---

## File Structure

- `client.py` — Example gRPC client with mTLS
- `server.py` — Example gRPC server with mTLS
- `machine_monitor.proto` — Protobuf service and message definitions
- `machine_monitor_pb2.py`, `machine_monitor_pb2_grpc.py` — Generated gRPC Python files
- `requirements.txt` — Python dependencies
- `.gitignore` — Files and folders to ignore in git
- `certs/` — Place your generated certificates and keys here

---

## About mTLS

**Mutual TLS (mTLS)** ensures that both the client and server authenticate each other using certificates, providing strong security for inter-machine communication.

- The server verifies the client’s certificate.
- The client verifies the server’s certificate.
- All data is encrypted in transit.

---

## References

- [gRPC Python Documentation](https://grpc.io/docs/languages/python/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Protobuf Language Guide](https://developers.google.com/protocol-buffers/docs/overview)

---

Feel free to copy, modify, and use this template for your project! If you want it saved as your `README.md`, just let me know.
