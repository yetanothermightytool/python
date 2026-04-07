Service Configuration

/etc/systemd/system/veeamy-proxy.service 

```
[Unit]
Description=Veeam MCP Proxy Service
After=network.target

[Service]
Type=simple
User=analyst
WorkingDirectory=/home/analyst/veeam-intelligence/veeam-relay
Environment="PATH=/home/analyst/veeam-intelligence/veeam-relay/venv/bin"
ExecStart=/home/analyst/veeam-intelligence/veeam-relay/venv/bin/uvicorn veeam-relay:app --host 0.0.0.0 --port 8443 --ssl-certfile=/home/analyst/veeam-intelligence/veeam-relay/certs/cert.pem --ssl-keyfile=/home/analyst/veeam-intelligence/veeam-relay/certs/key.pem
Restart=always
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```
