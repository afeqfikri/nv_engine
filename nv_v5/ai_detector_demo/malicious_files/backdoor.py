#!/usr/bin/env python3
"""
DEMO ONLY - Simulated backdoor (does not actually connect)
This file contains malicious patterns for detection testing
"""

import socket
import subprocess
import base64
import os

# Encoded payload (harmless demo data)
PAYLOAD = "ZWNobyAiSGFybWxlc3MgZGVtbyBwYXlsb2FkIg=="

def establish_connection():
    """Simulate establishing reverse connection"""
    try:
        # This would normally connect to attacker server
        # For demo: just print what would happen
        print("[DEMO] Would connect to: 192.168.1.100:4444")
        print("[DEMO] Connection simulation - no actual network activity")
        return None  # Return None instead of actual socket
    except:
        return None

def execute_commands(connection):
    """Simulate command execution"""
    if connection is None:  # Demo mode
        print("[DEMO] Would execute remote commands")
        return
    
    # Dangerous command execution patterns
    commands = [
        "whoami",
        "pwd", 
        "ls -la",
        "cat /etc/passwd"  # Sensitive file access
    ]
    
    for cmd in commands:
        print(f"[DEMO] Would execute: {cmd}")
        # In real malware: subprocess.run(cmd, shell=True)

def decode_payload():
    """Decode and execute hidden payload"""
    try:
        decoded = base64.b64decode(PAYLOAD)
        print(f"[DEMO] Decoded payload: {decoded.decode()}")
        # In real malware: exec(decoded)
    except:
        pass

def persistence_mechanism():
    """Simulate persistence installation"""
    print("[DEMO] Would install persistence via:")
    print("  - Registry modification (Windows)")
    print("  - Crontab entry (Linux)")
    print("  - Startup folder (Windows)")

def main():
    print("DEMO BACKDOOR - Educational Purpose Only")
    print("This file contains malicious patterns but is harmless")
    
    # Simulate malicious workflow
    connection = establish_connection()
    execute_commands(connection)
    decode_payload()
    persistence_mechanism()
    
    print("[DEMO] Backdoor simulation complete")

if __name__ == "__main__":
    main()
