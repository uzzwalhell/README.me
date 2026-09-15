import requests
import json

def ship_to_siem(scan_data, splunk_host, hec_token):
    print("📈 Forwarding security logs to SIEM...")
    
    # Splunk HEC endpoint formatting
    url = f"https://{splunk_host}:8088/services/collector/event"
    headers = {
        "Authorization": f"Splunk {hec_token}"
    }
    
    payload = {
        "sourcetype": "_json",
        "event": scan_data
    }
    
    try:
        # In a real environment, verify=False handles self-signed lab certs
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
        if response.status_code == 200:
            print("✅ Logs successfully ingested by Splunk.")
        else:
            print(f"⚠️ Failed to forward logs: {response.text}")
    except Exception as e:
        print(f"❌ Connection error: {e}")# ==========================================
# EXECUTION BLOCK (Add this to the bottom)
# ==========================================
if __name__ == "__main__":
    print("🚀 Initializing AVLIP Security Pipeline...")
    
    # 1. Simulate finding open ports on a local target VM
    # Let's say we checked common ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
    # We will simulate that port 22 and 443 are open
    simulated_scan_data = {
        "timestamp": "2026-09-15T16:40:00Z",
        "target_vm": "192.168.1.50",
        "scanned_by": "UzzwalHell-SecBot",
        "results": [
            {"port": 22, "service": "SSH", "status": "OPEN", "severity": "HIGH"},
            {"port": 80, "service": "HTTP", "status": "CLOSED", "severity": "NONE"},
            {"port": 443, "service": "HTTPS", "status": "OPEN", "severity": "LOW"}
        ]
    }
    
    # 2. Print the formatted JSON object to the terminal (so you can see it)
    import json
    print("\n📦 Formatted Security Payload Generated:")
    print(json.dumps(simulated_scan_data, indent=4))
    
    # 3. Attempt to forward it to your SIEM setup
    # (Using dummy values for now so it doesn't crash your terminal)
    print("\n📡 Attempting SIEM Transmission...")
    ship_to_siem(
        scan_data=simulated_scan_data, 
        splunk_host="localhost", 
        hec_token="12345-dummy-token-abcde"
    )
