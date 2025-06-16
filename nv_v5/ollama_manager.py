#!/usr/bin/env python3
"""
Ollama Model Manager for AI Malware Detection
==============================================
Manages Ollama models optimized for malware analysis and code review
"""

import os
import sys
import json
import time
import subprocess
import requests
from pathlib import Path
from datetime import datetime

class OllamaModelManager:
    """Manages Ollama models for malware detection"""
    
    def __init__(self, ollama_url="http://localhost:11434"):
        self.ollama_url = ollama_url.rstrip('/')
        self.models_info = {
            "llama3.2": {
                "size": "2.0GB",
                "description": "Fast general-purpose model, good for code analysis",
                "specialization": "General code understanding",
                "recommended_for": "Balanced performance and accuracy"
            },
            "phi3": {
                "size": "2.3GB", 
                "description": "Microsoft's code-focused model",
                "specialization": "Code analysis and reasoning",
                "recommended_for": "Code-heavy malware detection"
            },
            "codellama": {
                "size": "3.8GB",
                "description": "Meta's specialized code model",
                "specialization": "Code understanding and generation",
                "recommended_for": "Deep code analysis"
            },
            "mistral": {
                "size": "4.1GB",
                "description": "High-performance general model",
                "specialization": "Advanced reasoning",
                "recommended_for": "Complex threat analysis"
            },
            "llama3.2:1b": {
                "size": "1.3GB",
                "description": "Lightweight version for resource-constrained systems",
                "specialization": "Basic code analysis",
                "recommended_for": "Low-resource environments"
            },
            "granite-code": {
                "size": "2.6GB",
                "description": "IBM's code-specialized model",
                "specialization": "Code vulnerability detection",
                "recommended_for": "Security-focused analysis"
            }
        }
    
    def check_ollama_status(self):
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_installed_models(self):
        """Get list of installed models"""
        try:
            response = requests.get(f"{self.ollama_url}/api/tags", timeout=10)
            if response.status_code == 200:
                return response.json().get('models', [])
            return []
        except:
            return []
    
    def list_available_models(self):
        """List all available models with details"""
        print("🤖 AVAILABLE MODELS FOR MALWARE DETECTION")
        print("=" * 60)
        
        installed_models = [m['name'].split(':')[0] for m in self.get_installed_models()]
        
        for model_name, info in self.models_info.items():
            base_name = model_name.split(':')[0]
            status = "✅ INSTALLED" if base_name in installed_models else "📥 AVAILABLE"
            
            print(f"\n🔸 {model_name}")
            print(f"   Status: {status}")
            print(f"   Size: {info['size']}")
            print(f"   Description: {info['description']}")
            print(f"   Specialization: {info['specialization']}")
            print(f"   Best for: {info['recommended_for']}")
    
    def install_model(self, model_name):
        """Install a specific model"""
        if not self.check_ollama_status():
            print("❌ Ollama server not running. Start with: ollama serve")
            return False
        
        if model_name not in self.models_info:
            print(f"❌ Unknown model: {model_name}")
            print("Available models:", list(self.models_info.keys()))
            return False
        
        print(f"📥 Installing {model_name}...")
        print(f"Size: {self.models_info[model_name]['size']}")
        print("This may take several minutes depending on your internet connection.")
        
        try:
            # Use Ollama CLI to pull the model
            process = subprocess.Popen(
                ["ollama", "pull", model_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Show progress
            print("\nDownload progress:")
            for line in process.stdout:
                print(f"   {line.strip().encode(sys.stdout.encoding, errors='replace').decode()}")

            
            process.wait()
            
            if process.returncode == 0:
                print(f"✅ {model_name} installed successfully!")
                return True
            else:
                print(f"❌ Failed to install {model_name}")
                return False
                
        except FileNotFoundError:
            print("❌ Ollama CLI not found. Please install Ollama first.")
            return False
        except Exception as e:
            print(f"❌ Error installing model: {e}")
            return False
    
    def remove_model(self, model_name):
        """Remove an installed model"""
        if not self.check_ollama_status():
            print("❌ Ollama server not running. Start with: ollama serve")
            return False
        
        print(f"🗑️ Removing {model_name}...")
        
        try:
            result = subprocess.run(
                ["ollama", "rm", model_name],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"✅ {model_name} removed successfully!")
                return True
            else:
                print(f"❌ Failed to remove {model_name}")
                print(f"Error: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error removing model: {e}")
            return False
    
    def test_model(self, model_name):
        """Test a model with a sample malware detection prompt"""
        if not self.check_ollama_status():
            print("❌ Ollama server not running. Start with: ollama serve")
            return False
        
        test_code = '''
import subprocess
import base64

def execute_command():
    cmd = "rm -rf /"  # Dangerous command
    subprocess.run(cmd, shell=True)

encoded = "cm0gLXJmIC8="  # base64 encoded malicious command
decoded = base64.b64decode(encoded)
'''
        
        prompt = f"""
Analyze this code for malicious behavior. Rate threat level as LOW/MEDIUM/HIGH/CRITICAL:

{test_code}

Provide analysis in format:
THREAT_LEVEL: [level]
MALICIOUS_INDICATORS: [list indicators]
EXPLANATION: [brief explanation]
"""
        
        print(f"🧪 Testing {model_name} with sample malicious code...")
        
        try:
            payload = {
                "model": model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 200
                }
            }
            
            start_time = time.time()
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=30
            )
            end_time = time.time()
            
            if response.status_code == 200:
                result = response.json()
                analysis = result.get('response', '')
                
                print(f"✅ Test completed in {end_time - start_time:.1f} seconds")
                print("\n📊 Sample Analysis:")
                print("-" * 40)
                print(analysis[:300] + "..." if len(analysis) > 300 else analysis)
                print("-" * 40)
                return True
            else:
                print(f"❌ Test failed with status: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            print("❌ Test timed out (model may be loading)")
            return False
        except Exception as e:
            print(f"❌ Test error: {e}")
            return False
    
    def benchmark_models(self):
        """Benchmark all installed models"""
        installed_models = self.get_installed_models()
        
        if not installed_models:
            print("❌ No models installed")
            return
        
        print("🚀 BENCHMARKING INSTALLED MODELS")
        print("=" * 50)
        
        results = []
        
        for model in installed_models:
            model_name = model['name']
            print(f"\n🔍 Testing {model_name}...")
            
            start_time = time.time()
            success = self.test_model(model_name)
            end_time = time.time()
            
            results.append({
                'model': model_name,
                'response_time': end_time - start_time,
                'success': success,
                'size': model.get('size', 0)
            })
        
        # Print benchmark summary
        print("\n📊 BENCHMARK RESULTS")
        print("=" * 50)
        print(f"{'Model':<20} {'Time (s)':<10} {'Status':<10} {'Size':<10}")
        print("-" * 50)
        
        for result in sorted(results, key=lambda x: x['response_time']):
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            size_mb = result['size'] / (1024*1024) if result['size'] > 0 else 0
            print(f"{result['model']:<20} {result['response_time']:<10.1f} {status:<10} {size_mb:<10.1f}MB")
    
    def recommend_model(self):
        """Recommend best model based on system resources"""
        print("🎯 MODEL RECOMMENDATIONS")
        print("=" * 40)
        
        # Check available RAM (simplified)
        try:
            import psutil
            available_gb = psutil.virtual_memory().available / (1024**3)
            
            if available_gb < 4:
                print("💡 Recommended for low memory systems:")
                print("   • llama3.2:1b (1.3GB) - Lightweight")
            elif available_gb < 8:
                print("💡 Recommended for standard systems:")
                print("   • llama3.2 (2.0GB) - Balanced")
                print("   • phi3 (2.3GB) - Code-focused")
            else:
                print("💡 Recommended for high-performance systems:")
                print("   • codellama (3.8GB) - Deep code analysis")
                print("   • mistral (4.1GB) - Advanced reasoning")
                
        except ImportError:
            print("💡 General recommendations:")
            print("   • llama3.2 - Good starting point")
            print("   • phi3 - For code-heavy analysis")
            print("   • codellama - For detailed code review")
        
        print("\n🔧 Installation commands:")
        print("   python ollama_manager.py --install llama3.2")
        print("   python ollama_manager.py --install phi3")
    
    def create_model_config(self):
        """Create optimized model configuration"""
        config = {
            "model_settings": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 500,
                "timeout": 30
            },
            "analysis_prompts": {
                "malware_detection": """
Analyze this code for malicious behavior. Look for:
1. System command execution
2. Network communications  
3. File system manipulation
4. Data exfiltration
5. Obfuscation techniques

Rate threat level as LOW/MEDIUM/HIGH/CRITICAL and explain findings.
""",
                "ai_generated_detection": """
Analyze if this code was likely generated by AI. Look for:
1. Excessive commenting
2. Generic variable names
3. Repetitive patterns
4. Over-engineered structure

Provide confidence percentage and reasoning.
"""
            },
            "model_priorities": [
                "phi3",      # Best for code analysis
                "llama3.2",  # Good general performance
                "codellama", # Deep code understanding
                "mistral"    # Advanced reasoning
            ]
        }
        
        config_file = Path("ollama_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Model configuration saved to: {config_file}")
        return config_file

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Ollama Model Manager for Malware Detection')
    parser.add_argument('--list', action='store_true', help='List available models')
    parser.add_argument('--install', metavar='MODEL', help='Install a model')
    parser.add_argument('--remove', metavar='MODEL', help='Remove a model')
    parser.add_argument('--test', metavar='MODEL', help='Test a model')
    parser.add_argument('--benchmark', action='store_true', help='Benchmark all installed models')
    parser.add_argument('--recommend', action='store_true', help='Get model recommendations')
    parser.add_argument('--config', action='store_true', help='Create model configuration')
    parser.add_argument('--url', default='http://localhost:11434', help='Ollama server URL')
    
    args = parser.parse_args()
    
    manager = OllamaModelManager(args.url)
    
    if not manager.check_ollama_status():
        print("❌ Cannot connect to Ollama server")
        print("Make sure Ollama is running: ollama serve")
        sys.exit(1)
    
    if args.list:
        manager.list_available_models()
    elif args.install:
        manager.install_model(args.install)
    elif args.remove:
        manager.remove_model(args.remove)
    elif args.test:
        manager.test_model(args.test)
    elif args.benchmark:
        manager.benchmark_models()
    elif args.recommend:
        manager.recommend_model()
    elif args.config:
        manager.create_model_config()
    else:
        print("🤖 Ollama Model Manager for AI Malware Detection")
        print("=" * 50)
        print("Usage examples:")
        print("  python ollama_manager.py --list")
        print("  python ollama_manager.py --install llama3.2")
        print("  python ollama_manager.py --test phi3")
        print("  python ollama_manager.py --benchmark")
        print("  python ollama_manager.py --recommend")
        print("\nFor help: python ollama_manager.py --help")

if __name__ == "__main__":
    main()
