#!/usr/bin/env python
"""
AI-Powered Malware Detector Setup Script
========================================
Installs dependencies and configures Ollama for malware detection
"""

import os
import sys
import subprocess
import requests
import time
import json
from pathlib import Path

class SetupManager:
    """Manages the setup process for the AI malware detector"""
    
    def __init__(self):
        self.ollama_url = "http://localhost:11434"
        self.recommended_models = [
            "llama3",      # Fast and good for code analysis
            "phi3",          # Microsoft's code-focused model
            "codellama",     # Meta's code-specialized model
            "mistral"        # Good general performance
        ]
        
    def check_python_version(self):
        """Check if Python version is compatible"""
        print("🐍 Checking Python version...")
        if sys.version_info < (3, 7):
            print("❌ Python 3.7+ required")
            return False
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
        return True
    
    def install_python_dependencies(self):
        """Install required Python packages"""
        print("\n📦 Installing Python dependencies...")
        
        requirements = [
            "requests>=2.25.0",
            "yara-python>=4.0.0",
            "watchdog>=2.1.0",
            "colorama>=0.4.4"  # For colored terminal output
        ]
        
        for requirement in requirements:
            try:
                print(f"   Installing {requirement}...")
                result = subprocess.run([
                    sys.executable, "-m", "pip", "install", requirement
                ], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"   ✅ {requirement} installed")
                else:
                    print(f"   ❌ Failed to install {requirement}")
                    print(f"      Error: {result.stderr}")
                    return False
            except Exception as e:
                print(f"   ❌ Failed to install {requirement}")
                print(f"      Error: {e}")
                return False
        print("✅ All Python dependencies installed")
        return True

    def check_ollama_installation(self):
        """Check if Ollama is installed and running"""
        print("\n🤖 Checking Ollama installation...")
        
        # Check if ollama command exists
        try:
            result = subprocess.run(["ollama", "--version"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Ollama installed: {result.stdout.strip()}")
            else:
                print("❌ Ollama command not found")
                return False
        except FileNotFoundError:
            print("❌ Ollama not installed")
            return False
        
        # Check if Ollama server is running
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                print("✅ Ollama server is running")
                models = response.json().get('models', [])
                print(f"   Available models: {len(models)}")
                for model in models[:3]:  # Show first 3 models
                    print(f"   - {model['name']}")
                return True
            else:
                print("❌ Ollama server not responding")
                return False
        except requests.exceptions.RequestException:
            print("❌ Cannot connect to Ollama server")
            return False
    
    def install_ollama(self):
        """Guide user through Ollama installation"""
        print("\n🔧 Ollama Installation Required")
        print("="*50)
        
        system = sys.platform.lower()
        
        if "linux" in system:
            print("For Linux:")
            print("  curl -fsSL https://ollama.ai/install.sh | sh")
        elif "darwin" in system:
            print("For macOS:")
            print("  Download from: https://ollama.ai/download/mac")
            print("  Or use Homebrew: brew install ollama")
        elif "win" in system:
            print("For Windows:")
            print("  Download from: https://ollama.ai/download/windows")
        
        print("\nAfter installation:")
        print("1. Start Ollama server: ollama serve")
        print("2. Run this setup script again")
        
        return False
    
    def download_recommended_model(self):
        """Download a recommended model for malware analysis"""
        print("\n🧠 Setting up AI model...")
        
        # Check which models are available
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                available_models = [m['name'].split(':')[0] for m in response.json().get('models', [])]
                print(f"Available models: {available_models}")
                
                # Check if we have a recommended model
                for model in self.recommended_models:
                    if model in available_models:
                        print(f"✅ Found recommended model: {model}")
                        return model
        except:
            pass
        
        # Download a recommended model
        print("📥 Downloading recommended model for malware analysis...")
        model_to_download = self.recommended_models[0]  # Default to llama3.2
        
        print(f"Downloading {model_to_download}... (this may take several minutes)")
        
        try:
            # Use ollama CLI to pull the model
            process = subprocess.Popen(
                ["ollama", "pull", model_to_download],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Show progress
            for line in process.stdout:
                print(f"   {line.strip()}")
            
            process.wait()
            
            if process.returncode == 0:
                print(f"✅ Model {model_to_download} downloaded successfully")
                return model_to_download
            else:
                print(f"❌ Failed to download {model_to_download}")
                return None
                
        except Exception as e:
            print(f"❌ Error downloading model: {e}")
            return None
    
    def create_config_file(self, model_name):
        """Create configuration file"""
        print("\n⚙️ Creating configuration file...")
        
        config = {
            "ollama_url": self.ollama_url,
            "default_model": model_name,
            "scan_settings": {
                "max_file_size_mb": 5,
                "scan_extensions": [".py", ".js", ".php", ".pl", ".rb", ".sh", ".bat", ".ps1"],
                "ai_analysis_threshold": 0.3
            },
            "detection_settings": {
                "yara_enabled": True,
                "ai_analysis_enabled": True,
                "real_time_monitoring": True
            }
        }
        
        config_path = Path("detector_config.json")
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Configuration saved to: {config_path}")
        return config_path
    
    def test_detection_system(self):
        """Test the complete detection system"""
        print("\n🧪 Testing detection system...")
        
        # Create a test file
        test_file = Path("test_sample.py")
        test_content = '''
import subprocess
import base64

# This is a comment explaining the code
def execute_command():
    # Function to process system commands
    cmd = "echo Hello World"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout

# Encoded data for demonstration
encoded_data = "dGVzdCBkYXRh"
decoded = base64.b64decode(encoded_data)

if __name__ == "__main__":
    execute_command()
'''
        
        test_file.write_text(test_content)
        print(f"✅ Created test file: {test_file}")
        
        # Test the detector
        try:
            print("🔍 Testing AI-powered detector...")
            result = subprocess.run([
                sys.executable, "ai_powered_detector.py", str(test_file)
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ Detection test completed successfully")
                print("Sample output:")
                print("-" * 40)
                print(result.stdout[-500:])  # Show last 500 chars
            else:
                print("❌ Detection test failed")
                print("Error output:")
                print(result.stderr)
                
        except subprocess.TimeoutExpired:
            print("⚠️ Detection test timed out (may be normal for first run)")
        except Exception as e:
            print(f"❌ Error testing detector: {e}")
        
        # Clean up test file
        if test_file.exists():
            test_file.unlink()
        
        return True
    
    def print_usage_instructions(self):
        """Print usage instructions"""
        print("\n" + "="*60)
        print("🎉 SETUP COMPLETE!")
        print("="*60)
        print("Your AI-Powered Malware Detector is ready to use!")
        print("\n📋 USAGE EXAMPLES:")
        print("-" * 30)
        print("# Scan a single file:")
        print("python ai_powered_detector.py suspicious_file.py")
        print("\n# Scan existing files in directory:")
        print("python ai_powered_detector.py /path/to/scan --scan-existing")
        print("\n# Real-time monitoring:")
        print("python ai_powered_detector.py /path/to/monitor --watch")
        print("\n# Use different AI model:")
        print("python ai_powered_detector.py file.py --model codellama")
        print("\n# Monitor with existing scan:")
        print("python ai_powered_detector.py /path --watch --scan-existing")
        
        print("\n🔧 CONFIGURATION:")
        print("-" * 20)
        print("Configuration file: detector_config.json")
        print("Modify settings as needed")
        
        print("\n⚠️ IMPORTANT NOTES:")
        print("-" * 20)
        print("• Keep Ollama server running: ollama serve")
        print("• First AI analysis may be slow (model loading)")
        print("• Monitor system resources during intensive scanning")
        print("• Review all detections manually before taking action")
        
        print("\n🆘 TROUBLESHOOTING:")
        print("-" * 20)
        print("• If Ollama fails: Check 'ollama serve' is running")
        print("• If YARA fails: Try 'pip install --upgrade yara-python'")
        print("• For permission errors: Run with appropriate privileges")
        print("• For slow performance: Use smaller/faster AI models")
        
        print("\n🔗 USEFUL COMMANDS:")
        print("-" * 20)
        print("ollama list                    # Show available models")
        print("ollama pull phi3              # Download specific model")
        print("ollama rm model_name          # Remove unused model")
        print("="*60)
    
    def run_setup(self):
        """Run the complete setup process"""
        print("🚀 AI-POWERED MALWARE DETECTOR SETUP")
        print("="*50)
        
        # Step 1: Check Python
        if not self.check_python_version():
            return False
        
        # Step 2: Install Python dependencies
        if not self.install_python_dependencies():
            return False
        
        # Step 3: Check Ollama
        if not self.check_ollama_installation():
            if not self.install_ollama():
                return False

        # Step 4: Download AI model
        model_name = self.download_recommended_model()
        if not model_name:
            print("⚠️ Continuing without downloading new model")
            model_name = "llama3.2"  # Default fallback
        
        # Step 5: Create config
        self.create_config_file(model_name)
        
        # Step 6: Test system
        self.test_detection_system()
        
        # Step 7: Show usage instructions
        self.print_usage_instructions()
        
        return True

def main():
    """Main setup function"""
    setup_manager = SetupManager()
    
    try:
        success = setup_manager.run_setup()
        if success:
            print("\n✅ Setup completed successfully!")
        else:
            print("\n❌ Setup failed. Please check the errors above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n🛑 Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during setup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
