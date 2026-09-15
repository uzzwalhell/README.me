# Automated Vulnerability & SIEM Log Ingestion Pipeline (AVLIP)

An automated security orchestration script built in Python designed to audit network assets for open ports/vulnerabilities, structure telemetry data into standardized enterprise JSON formats, and securely forward logs to a SIEM platform.

## 🚀 Core Features
- **Network Asset Auditing:** Modular network discovery logic simulating vulnerability management scans across critical service ports (SSH, HTTP, HTTPS).
- **SIEM Telemetry Formatting:** Automates raw scan transformations into structured JSON payloads tracking `target_vm`, `service mappings`, and `risk_severity`.
- **Splunk HEC Integration:** Utilizes secure HTTPS protocols to ship events directly to Splunk's HTTP Event Collector (HEC) API endpoint.
- **Fail-Safe Exception Handling:** Built with robust API exception handling to capture connection failures gracefully without disrupting production automation pipelines.

## 🛠️ Tech Stack & Compliance
- **Language:** Python 3 (Sockets, Requests, JSON modules)
- **Environment Isolation:** Python Virtual Environments (`venv`) managed in compliance with **PEP 668** standards.
- **Target SIEM:** Splunk Core / Splunk Enterprise (HEC Port 8088)

## 📋 Terminal Execution & Simulation Output

```bash
(venv) uzzwalhell@UzzwalHell Python % python3 shipper.py   
🚀 Initializing AVLIP Security Pipeline...

📦 Formatted Security Payload Generated:
{
    "timestamp": "2026-09-15T16:40:00Z",
    "target_vm": "192.168.1.50",
    "scanned_by": "UzzwalHell-SecBot",
    "results": [
        { "port": 22, "service": "SSH", "status": "OPEN", "severity": "HIGH" },
        { "port": 80, "service": "HTTP", "status": "CLOSED", "severity": "NONE" },
        { "port": 443, "service": "HTTPS", "status": "OPEN", "severity": "LOW" }
    ]
}

📡 Attempting SIEM Transmission...
📈 Forwarding security logs to SIEM...
❌ Connection error: HTTPSConnectionPool(host='localhost', port=8088): Connection refused
```
*(Note: Connection exception gracefully caught; infrastructure operates as intended pending live lab SIEM collector state).*
