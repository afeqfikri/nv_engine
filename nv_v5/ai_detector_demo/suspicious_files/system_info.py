#!/usr/bin/env python3
"""System information collection tool"""

import os
import platform
import subprocess

def get_system_info():
    """Collect basic system information"""
    if platform.system() == 'Windows':
        current_user = os.environ.get('USERNAME', 'unknown')
        home_directory = os.environ.get('USERPROFILE', 'unknown')
    else:
        current_user = os.environ.get('USER', 'unknown')
        home_directory = os.environ.get('HOME', 'unknown')
    info = {
        'platform': platform.platform(),
        'system': platform.system(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'current_user': current_user,
        'home_directory': home_directory,
        'path': os.environ.get('PATH', '')[:100] + '...'
    }
    return info

def get_running_processes():
    """Get list of running processes (safe implementation)"""
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['tasklist'], capture_output=True, text=True)
        else:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        return result.stdout.split('
')[:10]  # First 10 lines only
    except Exception as e:
        return [f"Could not retrieve process list: {e}"]

def main():
    print("System Information Report")
    print("=" * 40)
    
    # Basic system info
    sys_info = get_system_info()
    for key, value in sys_info.items():
        print(f"{key}: {value}")
    
    print("
Running Processes (sample):")
    processes = get_running_processes()
    for proc in processes[:5]:  # Show only first 5
        print(f"  {proc}")

if __name__ == "__main__":
    main()
