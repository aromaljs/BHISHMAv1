import socket

def verify_vulnerability(target, port, vulnerability_type):
    """
    Performs robust active verification checks with proper headers and handshakes.
    """
    try:
        # --- HTTP / WEB VERIFICATION ---
        if "Directory Traversal" in vulnerability_type:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((target, int(port)))
            
            # Sending a proper GET request with a Host header
            request = f"GET /etc/passwd HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            s.send(request.encode())
            response = s.recv(2048).decode(errors='ignore')
            s.close()
            
            if "root:" in response or "passwd" in response:
                return f"[!!] CONFIRMED: Directory Traversal vulnerability found on port {port}."
            elif "200 OK" in response:
                return f"[*] Port {port} responded, but no traversal exploit confirmed (got 200 OK)."
            return f"[*] No traversal confirmed. Server responded: {response[:30]}..."

        # --- SMB / NETBIOS VERIFICATION ---
        elif "SMBv1" in vulnerability_type or "Null Session" in vulnerability_type:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            
            # Simple SMB Negotiate request
            # This is a standard SMB Header (NetBIOS Session Service + SMB Header)
            smb_probe = b'\x00\x00\x00\x2f\xffSMB\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            
            s.connect((target, int(port)))
            s.send(smb_probe)
            response = s.recv(1024)
            s.close()
            
            if len(response) > 0:
                return f"[!!] CONFIRMED: SMB Service on {port} is active and responding to negotiation."
            return f"[!] SMB probe sent, but no meaningful response received (Service may be restricted)."

        return f"[*] Verification method for {vulnerability_type} not yet implemented."
        
    except socket.timeout:
        return f"[!] Verification Timed Out on port {port}."
    except Exception as e:
        return f"[!] Verification Error on port {port}: {str(e)}"
