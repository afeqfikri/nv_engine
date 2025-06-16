#!/usr/bin/env python3
"""
Ollama Troubleshooting and Diagnostic Tool
==========================================
Diagnoses and fixes common Ollama issues for malware detection
"""

import os
import sys
import time
import json
import requests
import subprocess
from pathlib import Path

class OllamaTroubleshooter:
    """Diagnoses and fixes Ollama issues"""
    
    def __init__(self, ollama_url="http://localhost:11434"):
        self.ollama_url = ollama_url.rstrip('/')
        self.session = requests.Session()
    
    def check_ollama_status(self):
        """Check if Ollama server is running"""
        print("🔍 Checking Ollama server status...")
        
        try:
            response = self.session.get(f"{self.ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                print("✅ Ollama server is running")
                models = response.json().get('models', [])
                print(f"   Available models: {len(models)}")
                return True, models
            else:
                print(f"❌ Ollama server responded with status: {response.status_code}")
                return False, []
        except requests.exceptions.ConnectionError:
            print("❌ Cannot connect to Ollama server")
            print("   Make sure Ollama is running: ollama serve")
            return False, []
        except requests.exceptions.Timeout:
            print("❌ Ollama server is not responding (timeout)")
            return False, []
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return False, []
    
    def check_model_availability(self, model_name="mistral"):
        """Check if specific model is available"""
        print(f"\n🤖 Checking model: {model_name}")
        
        is_running, models = self.check_ollama_status()
        if not is_running:
            return False
        
        # Check if model is installed
        installed_models = [m['name'].split(':')[0] for m in models]
        
        if model_name in installed_models:
            print(f"✅ Model {model_name} is installed")
            
            # Check model size and details
            for model in models:
                if model['name'].split(':')[0] == model_name:
                    size_gb = model.get('size', 0) / (1024**3)
                    print(f"   Size: {size_gb:.1f} GB")
                    print(f"   Modified: {model.get('modified_at', 'Unknown')}")
            
            return True
        else:
            print(f"❌ Model {model_name} is not installed")
            print(f"   Available models: {', '.join(installed_models)}")
            return False
    
    def test_model_performance(self, model_name="mistral"):
        """Test model response time and functionality"""
        print(f"\n⚡ Testing {model_name} performance...")
        
        # Simple test prompt
        test_prompt = "Analyze this simple code for threats: print('hello world')"
        
        payload = {
            "model": model_name,
            "prompt": test_prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 50  # Short response for testing
            }
        }
        
        try:
            print("   Sending test request...")
            start_time = time.time()
            
            response = self.session.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=60  # Longer timeout for testing
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Test successful!")
                print(f"   Response time: {response_time:.1f} seconds")
                print(f"   Response preview: {result.get('response', '')[:100]}...")
                return True, response_time
            else:
                print(f"❌ Test failed with status: {response.status_code}")
                print(f"   Error: {response.text}")
                return False, response_time
                
        except requests.exceptions.Timeout:
            print(f"❌ Test timed out after 60 seconds")
            print("   This indicates the model is too large for your system")
            return False, 60
        except Exception as e:
            print(f"❌ Test error: {e}")
            return False, 0
    
    def check_system_resources(self):
        """Check if system has enough resources"""
        print("\n💻 Checking system resources...")
        
        try:
            import psutil
            
            # Memory check
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)
            total_gb = memory.total / (1024**3)
            
            print(f"   RAM: {available_gb:.1f} GB available / {total_gb:.1f} GB total")
            
            if available_gb < 2:
                print("⚠️ Warning: Low available memory")
                print("   Consider using a smaller model like llama3.2:1b")
            
            # CPU check
            cpu_count = psutil.cpu_count()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            print(f"   CPU: {cpu_count} cores, {cpu_percent}% usage")
            
            if cpu_percent > 80:
                print("⚠️ Warning: High CPU usage")
                print("   Wait for CPU usage to decrease before running AI analysis")
            
            return True
            
        except ImportError:
            print("   psutil not available for detailed resource checking")
            print("   Install with: pip install psutil")
            return False
    
    def suggest_solutions(self, model_name="mistral"):
        """Suggest solutions based on diagnosis"""
        print(f"\n🔧 SOLUTIONS FOR {model_name.upper()} TIMEOUT:")
        print("=" * 50)
        
        # Check model availability first
        model_available = self.check_model_availability(model_name)
        
        if not model_available:
            print("📥 SOLUTION 1: Install the model")
            print(f"   ollama pull {model_name}")
            print("   This may take 10-30 minutes depending on your internet speed")
            
        print("\n⚡ SOLUTION 2: Use a faster model")
        print("   # Try lightweight model first")
        print("   python ai_powered_detector.py file.py --model llama3.2:1b")
        print("   ")
        print(