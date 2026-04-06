# Veeam MCP Relay Proxy

This service acts as an HTTP proxy in front of the `veeam-intelligence-mcp-server` Docker container. This proxy makes it reachable over a standard HTTPS API.

When a request comes in, the proxy starts a short-lived container, passes the credentials and question to it via stdin as JSON-RPC, and returns the answer to the caller. The container is removed automatically after each request.

Supported products: Veeam Backup & Replication (`vbr`) and Veeam ONE (`vone`).

---

## Prerequisites

- Python 3.11 or later
- Docker with the `veeam-intelligence-mcp-server` image available locally
- A TLS certificate and private key
- A Linux host with systemd

---

## Setup

### 1. Download the script

```bash
mkdir -p /home/analyst/veeam-intelligence/veeam-relay/certs
cd /home/analyst/veeam-intelligence/veeam-relay
curl -O https://raw.githubusercontent.com/yetanothermightytool/python/main/misc/veeam-proxy/veeam-relay.py
```

### 2. Create the Python virtual environment and install dependencies

```bash
python3 -m venv venv
venv/bin/pip install fastapi uvicorn[standard] pydantic
```

### 3. Provide TLS certificates

Place your certificate and private key in the `certs/` directory:

```
certs/cert.pem
certs/key.pem
```

For testing, a self-signed certificate can be generated with:

```bash
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/CN=veeam-relay"
```

### 4. Install the systemd service

```bash
sudo cp veeam-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable veeam-proxy
sudo systemctl start veeam-proxy
```

Verify the service is running:

```bash
sudo systemctl status veeamy-proxy
```

---

## API Reference

### POST /ask

Sends a question to the Veeam Intelligence container and returns the answer.

**Required headers**

```
admin-username: <veeam admin user>
admin-password: <veeam admin password>
```

**Request body**

```json
{
  "question": "How many backup jobs failed last night?",
  "web_url": "https://veeam.example.com",
  "product_name": "vbr"
}
```

- `product_name` accepts `"vbr"` (Veeam Backup & Replication) or `"vone"` (Veeam ONE)

**Response**

```json
{
  "success": true,
  "result": { ... }
}
```

---

### GET /health

Returns the service status. Use this for uptime monitoring or load balancer health checks.

```json
{ "status": "healthy" }
```

---

## Version History
