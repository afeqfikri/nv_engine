#!/usr/bin/env python3
"""Network connectivity checker"""

import socket
import subprocess
import sys
import platform

def check_port(host, port, timeout=3):
    """Check if port is open on host"""
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except (OSError, socket.timeout):
        return False

def ping_host(host):
    """Ping a host to check connectivity"""
    try:
        # Use ping command
        if platform.system() == 'Windows':
            result = subprocess.run(['ping', '-n', '1', host], 
                                  capture_output=True, text=True, timeout=5)
        else:
            result = subprocess.run(['ping', '-c', '1', host], 
                                  capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        print(f"[ERROR] Ping failed: {e}")
        return False

def scan_common_ports(host):
    """Scan common ports on host"""
    common_ports = [22, 23, 53, 80, 110, 143, 443, 993, 995]
    open_ports = []
    
    print(f"Scanning {host}...")
    for port in common_ports:
        if check_port(host, port):
            open_ports.append(port)
            print(f"Port {port}: OPEN")
    
    return open_ports

def main():
    if len(sys.argv) != 2:
        print("Usage: python network_scanner.py <host>")
        sys.exit(1)
    
    host = sys.argv[1]
    
    # Check basic connectivity
    if ping_host(host):
        print(f"{host} is reachable")
        scan_common_ports(host)
    else:
        print(f"{host} is not reachable")

if __name__ == "__main__":
    main()
