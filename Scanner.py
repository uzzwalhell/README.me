import socket
import ssl
import json
from datetime import datetime

def grab_banner(target_ip, port):
    """
    Attempts to identify the service running on an open port.
    For web ports (80/8080) it sends a lightweight HTTP HEAD request
    and reads the 'Server' header. For 443 it performs a real TLS
    handshake, pulls certificate/TLS details, and sends an HTTPS
    HEAD request over the encrypted connection. For other ports it
    just reads whatever the service sends first (many services
    announce themselves immediately on connect, e.g. SSH, FTP).
    """
    try:
        if port in (80, 8080):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, port))
            request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode(errors="ignore")
            s.close()
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            return "No Server header returned"

        elif port == 443:
            return grab_https_banner(target_ip, port)

        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            s.close()
            return banner if banner else "No banner received"

    except Exception as e:
        return f"Could not grab banner: {e}"


def grab_https_banner(target_ip, port):
    """
    Performs a real TLS handshake against an HTTPS port, extracts
    the negotiated TLS version and cipher plus certificate subject/
    issuer/expiry, then sends an HTTP HEAD request over the encrypted
    channel to try to read the 'Server' response header.
    """
    try:
        # Certificate verification is disabled here (CERT_NONE) because
        # this is a recon/inventory scan, not a trust decision — we want
        # to inspect the cert even if it's self-signed or expired.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(3.0)
        raw_sock.connect((target_ip, port))

        tls_sock = context.wrap_socket(raw_sock, server_hostname=target_ip)

        result = {
            "tls_version": tls_sock.version(),
            "cipher": tls_sock.cipher() if tls_sock.cipher() else "Unknown",
        }

        # Certificate details (subject/issuer/expiry) via the DER form,
        # since CERT_NONE means getpeercert(binary_form=False) is empty.
        der_cert = tls_sock.getpeercert(binary_form=True)
        if der_cert:
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            result["certificate_pem_available"] = True
            # Re-parse the PEM with a verifying context isn't needed —
            # store PEM so it can be inspected further if required.
            result["certificate_preview"] = pem_cert.splitlines()[0] + " ... " + pem_cert.splitlines()[-1]
        else:
            result["certificate_pem_available"] = False

        # HTTPS HEAD request over the now-encrypted socket
        request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
        tls_sock.sendall(request.encode())
        response = tls_sock.recv(2048).decode(errors="ignore")

        server_header = "No Server header returned"
        for line in response.split("\r\n"):
            if line.lower().startswith("server:"):
                server_header = line.split(":", 1)[1].strip()
                break
        result["server_header"] = server_header

        tls_sock.close()
        return result

    except Exception as e:
        return f"TLS handshake or HTTPS request failed: {e}"


def scan_target(target_ip, ports_to_scan):
    print(f"Starting vulnerability scan on: {target_ip}")
    scan_results = {
        "timestamp": datetime.now().isoformat(),
        "target": target_ip,
        "vulnerabilities_found": []
    }

    for port in ports_to_scan:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((target_ip, port))
        s.close()

        if result == 0:
            severity = "High" if port in [21, 22, 23, 445] else "Low"
            banner = grab_banner(target_ip, port)

            scan_results["vulnerabilities_found"].append({
                "port": port,
                "status": "OPEN",
                "risk_level": severity,
                "alert_triggered": True if severity == "High" else False,
                "service_banner": banner
            })

    return scan_results


if __name__ == "__main__":
    target = input("Enter target IP address: ").strip()
    ports = [21, 22, 80, 443, 8080]
    report = scan_target(target, ports)
    print(json.dumps(report, indent=4))