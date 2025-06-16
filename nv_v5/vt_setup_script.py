#!/usr/bin/env python3
"""
VirusTotal Integration Setup Script
===================================
Sets up VirusTotal API integration for the AI-powered malware detector
Handles API key configuration, testing, and optimization
"""

import os
import sys
import json
import requests
import time
from pathlib import Path

class VirusTotalSetup:
    """Setup and configure VirusTotal integration"""
    
    def __init__(self):
        self.api_key = None
        self.base_url = "https://www.virustotal.com/api/v3"
        self.config_file = Path("vt_config.json")
        
    def check_existing_config(self):
        """Check for existing VirusTotal configuration"""
        print("🔍 Checking for existing VirusTotal configuration...")
        
        # Check environment variable
        env_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if env_key:
            print(f"✅ Found API key in environment: {env_key[:8]}...{env_key[-4:]}")
            self.api_key = env_key
            return True
        
        # Check .env file
        env_file = Path('.env')
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    if line.startswith('VIRUSTOTAL_API_KEY='):
                        key = line.split('=', 1)[1].strip()
                        print(f"✅ Found API key in .env file: {key[:8]}...{key[-4:]}")
                        self.api_key = key
                        return True
        
        # Check config file
        if self.config_file.exists():
            try:
                with open(self.config_file) as f:
                    config = json.load(f)
                    key = config.get('api_key')
                    if key:
                        print(f"✅ Found API key in config file: {key[:8]}...{key[-4:]}")
                        self.api_key = key
                        return True
            except:
                pass
        
        print("❌ No existing VirusTotal API key found")
        return False
    
    def get_api_key_interactive(self):
        """Interactive API key setup"""
        print("\n🔑 VirusTotal API Key Setup")
        print("="*40)
        
        print("📋 To get a FREE VirusTotal API key:")
        print("1. Visit: https://www.virustotal.com/gui/join-us")
        print("2. Create a free account")
        print("3. Go to: https://www.virustotal.com/gui/my-apikey")
        print("4. Copy your API key")
        
        print("\n💡 Free tier includes:")
        print("   • 4 requests per minute")
        print("   • File hash lookups")
        print("   • Basic scan results")
        
        response = input("\nDo you have a VirusTotal API key? [y/N]: ").strip().lower()
        if response not in ['y', 'yes']:
            print("\n⚠️ VirusTotal integration will be disabled")
            print("You can still use AI + YARA detection without VirusTotal")
            return None
        
        while True:
            api_key = input("\nEnter your VirusTotal API key: ").strip()
            if not api_key:
                print("❌ API key cannot be empty")
                continue
            
            if len(api_key) < 32:
                print("❌ API key seems too short (expected 64 characters)")
                continue
            
            # Test the API key
            if self.test_api_key(api_key):
                self.api_key = api_key
                return api_key
            else:
                retry = input("❌ API key test failed. Try again? [y/N]: ").strip().lower()
                if retry not in ['y', 'yes']:
                    return None
    
    def test_api_key(self, api_key):
        """Test VirusTotal API key"""
        print(f"🧪 Testing API key: {api_key[:8]}...")
        
        try:
            headers = {
                'X-Apikey': api_key,
                'User-Agent': 'AI-Malware-Detector-Setup/1.0'
            }
            
            # Test with a known file hash (EICAR test file)
            eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            response = requests.get(
                f"{self.base_url}/files/{eicar_hash}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ API key is valid and working")
                
                # Show quota information if available
                quota_header = response.headers.get('X-API-Quota-Used')
                if quota_header:
                    print(f"📊 API quota used: {quota_header}")
                
                return True
            elif response.status_code == 401:
                print("❌ API key is invalid (401 Unauthorized)")
                return False
            elif response.status_code == 429:
                print("⚠️ Rate limit exceeded - API key is valid but throttled")
                return True
            else:
                print(f"⚠️ Unexpected response: {response.status_code}")
                print("API key might be valid but there's an issue")
                return True
                
        except requests.exceptions.Timeout:
            print("⚠️ Request timed out - network issue, but API key format looks valid")
            return len(api_key) >= 32
        except Exception as e:
            print(f"❌ Test failed: {e}")
            return False
    
    def save_configuration(self):
        """Save VirusTotal configuration"""
        if not self.api_key:
            print("❌ No API key to save")
            return False
        
        print("💾 Saving VirusTotal configuration...")
        
        # Configuration options
        print("Choose configuration method:")
        print("1. Environment variable (recommended)")
        print("2. .env file (for development)")
        print("3. Config file (JSON)")
        
        choice = input("Enter choice [1-3]: ").strip()
        
        if choice == '1':
            print(f"\n⚙️ Add this to your shell profile (~/.bashrc, ~/.zshrc):")
            print(f"export VIRUSTOTAL_API_KEY='{self.api_key}'")
            print("\nThen restart your terminal or run:")
            print(f"export VIRUSTOTAL_API_KEY='{self.api_key}'")
            
        elif choice == '2':
            with open('.env', 'w') as f:
                f.write(f'VIRUSTOTAL_API_KEY={self.api_key}\n')
            print("✅ Saved to .env file")
            
        elif choice == '3':
            config = {
                'api_key': self.api_key,
                'base_url': self.base_url,
                'rate_limit': 4,  # requests per minute
                'cache_enabled': True,
                'cache_max_age_days': 7
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"✅ Saved to {self.config_file}")
        
        else:
            print("❌ Invalid choice")
            return False
        
        return True
    
    def verify_integration(self):
        """Verify the complete integration"""
        print("\n🔧 Verifying VirusTotal integration...")
        
        # Test imports
        try:
            from virustotal_integration import VirusTotalClient, EnhancedMalwareDetector
            print("✅ VirusTotal integration modules imported successfully")
        except ImportError as e:
            print(f"❌ Failed to import VirusTotal modules: {e}")
            return False
        
        # Test client initialization
        try:
            client = VirusTotalClient(self.api_key)
            print("✅ VirusTotal client initialized")
        except Exception as e:
            print(f"❌ Failed to initialize VirusTotal client: {e}")
            return False
        
        # Test cache functionality
        try:
            cache_stats = client.get_cache_stats()
            print(f"✅ Cache system working: {cache_stats.get('total_cached', 0)} entries")
        except Exception as e:
            print(f"⚠️ Cache system issue: {e}")
        
        # Test enhanced detector
        try:
            detector = EnhancedMalwareDetector(vt_api_key=self.api_key)
            print("✅ Enhanced malware detector initialized")
        except Exception as e:
            print(f"❌ Failed to initialize enhanced detector: {e}")
            return False
        
        print("🎉 VirusTotal integration verification complete!")
        return True
    
    def show_usage_examples(self):
        """Show usage examples with VirusTotal integration"""
        print("\n📚 USAGE EXAMPLES")
        print("="*50)
        
        print("🔍 Enhanced single file analysis:")
        print("python virustotal_integration.py suspicious_file.py")
        
        print("\n🤖 AI detector with VirusTotal:")
        print("python ai_powered_detector.py file.py --vt-api-key your_key")
        
        print("\n🏠 Using environment variable:")
        print("export VIRUSTOTAL_API_KEY='your_key'")
        print("python ai_powered_detector.py file.py --comprehensive")
        
        print("\n📦 Batch processing with VirusTotal:")
        print("python batch_processor.py /malware/samples --vt-enabled")
        
        print("\n🛡️ Safe archive scanning:")
        print("python safe_archive_scanner.py malware.zip --vt-analysis")
        
        print("\n💡 Pro tips:")
        print("• Free tier: 4 requests/minute - use caching effectively")
        print("• Cache persists between runs for 7 days by default") 
        print("• Unknown files won't be in VirusTotal database")
        print("• Combine with AI analysis for best coverage")
    
    def run_setup(self):
        """Run the complete setup process"""
        print("🚀 VirusTotal Integration Setup")
        print("="*50)
        
        # Check existing configuration
        if self.check_existing_config():
            response = input("\nFound existing configuration. Reconfigure? [y/N]: ").strip().lower()
            if response not in ['y', 'yes']:
                print("✅ Using existing configuration")
                if self.verify_integration():
                    self.show_usage_examples()
                return True
        
        # Get API key
        api_key = self.get_api_key_interactive()
        if not api_key:
            print("❌ Setup cancelled - VirusTotal integration disabled")
            return False
        
        # Save configuration
        if not self.save_configuration():
            print("❌ Failed to save configuration")
            return False
        
        # Verify integration
        if not self.verify_integration():
            print("❌ Integration verification failed")
            return False
        
        # Show usage examples
        self.show_usage_examples()
        
        print("\n🎉 VirusTotal integration setup complete!")
        print("You can now use enhanced malware detection with multi-engine analysis")
        
        return True

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='VirusTotal Integration Setup')
    parser.add_argument('--verify', action='store_true', help='Verify existing setup')
    parser.add_argument('--test-key', help='Test a specific API key')
    
    args = parser.parse_args()
    
    setup = VirusTotalSetup()
    
    if args.test_key:
        if setup.test_api_key(args.test_key):
            print("✅ API key is valid")
        else:
            print("❌ API key is invalid")
        return
    
    if args.verify:
        if setup.check_existing_config():
            setup.verify_integration()
        else:
            print("❌ No VirusTotal configuration found")
        return
    
    # Run full setup
    try:
        setup.run_setup()
    except KeyboardInterrupt:
        print("\n🛑 Setup interrupted by user")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")

if __name__ == "__main__":
    main()
