#!/usr/bin/env python3
"""
VirusTotal API Integration for AI-Powered Malware Detector
==========================================================
Integrates VirusTotal's multi-engine analysis with our AI detection system
Provides comprehensive threat intelligence from 70+ antivirus engines
"""

import os
import sys
import json
import time
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import sqlite3
import threading

class VirusTotalClient:
    """VirusTotal API client with caching and rate limiting"""
    
    def __init__(self, api_key: str = None, cache_db: str = "vt_cache.db"):
        self.api_key = api_key or os.environ.get('d801c2b09edbfd9cebfd06ae6e3f2cd6f4369574d759efd4dd3df776be2c1ae1')
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        self.cache_db = cache_db
        
        # Rate limiting (free tier: 4 requests/minute)
        self.rate_limit_delay = 15  # seconds between requests
        self.last_request_time = 0
        self.rate_lock = threading.Lock()
        
        # Initialize headers
        if self.api_key:
            self.session.headers.update({
                'X-Apikey': self.api_key,
                'User-Agent': 'AI-Malware-Detector/1.0'
            })
        
        # Initialize cache database
        self._init_cache()
    
    def _init_cache(self):
        """Initialize SQLite cache database"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS vt_cache (
                        file_hash TEXT PRIMARY KEY,
                        scan_results TEXT,
                        scan_date TEXT,
                        positives INTEGER,
                        total_engines INTEGER
                    )
                ''')
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_scan_date ON vt_cache(scan_date)
                ''')
                conn.commit()
        except Exception as e:
            print(f"⚠️ Cache initialization failed: {e}")
    
    def _respect_rate_limit(self):
        """Ensure API rate limiting compliance"""
        with self.rate_lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - time_since_last
                print(f"⏱️ Rate limiting: waiting {sleep_time:.1f} seconds...")
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hasher = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"❌ Error calculating hash for {file_path}: {e}")
            return ""
    
    def get_cached_result(self, file_hash: str, max_age_days: int = 7) -> Optional[Dict]:
        """Get cached VirusTotal result if recent enough"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                cursor = conn.execute(
                    'SELECT scan_results, scan_date FROM vt_cache WHERE file_hash = ?',
                    (file_hash,)
                )
                result = cursor.fetchone()
                
                if result:
                    scan_results, scan_date = result
                    # Check if cache is still fresh
                    cache_date = datetime.fromisoformat(scan_date)
                    if datetime.now() - cache_date <= timedelta(days=max_age_days):
                        return json.loads(scan_results)
                    else:
                        # Remove stale cache
                        conn.execute('DELETE FROM vt_cache WHERE file_hash = ?', (file_hash,))
                        conn.commit()
        except Exception as e:
            print(f"⚠️ Cache read error: {e}")
        
        return None
    
    def cache_result(self, file_hash: str, scan_results: Dict):
        """Cache VirusTotal scan results"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO vt_cache 
                    (file_hash, scan_results, scan_date, positives, total_engines)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    file_hash,
                    json.dumps(scan_results),
                    datetime.now().isoformat(),
                    scan_results.get('positives', 0),
                    scan_results.get('total', 0)
                ))
                conn.commit()
        except Exception as e:
            print(f"⚠️ Cache write error: {e}")
    
    def check_file_hash(self, file_hash: str) -> Dict:
        """Check file hash against VirusTotal database"""
        if not self.api_key:
            return {'error': 'No VirusTotal API key provided'}
        
        # Check cache first
        cached_result = self.get_cached_result(file_hash)
        if cached_result:
            print(f"💾 Using cached result for {file_hash[:16]}...")
            return cached_result
        
        # Rate limiting
        self._respect_rate_limit()
        
        try:
            print(f"🔍 Querying VirusTotal for {file_hash[:16]}...")
            response = self.session.get(f"{self.base_url}/files/{file_hash}")
            
            if response.status_code == 200:
                data = response.json()
                result = self._parse_vt_response(data)
                
                # Cache the result
                self.cache_result(file_hash, result)
                return result
                
            elif response.status_code == 404:
                result = {
                    'found': False,
                    'message': 'File not found in VirusTotal database',
                    'positives': 0,
                    'total': 0,
                    'engines': {}
                }
                self.cache_result(file_hash, result)
                return result
                
            elif response.status_code == 429:
                return {
                    'error': 'VirusTotal rate limit exceeded',
                    'retry_after': response.headers.get('Retry-After', '60')
                }
            else:
                return {
                    'error': f'VirusTotal API error: {response.status_code}',
                    'message': response.text
                }
                
        except Exception as e:
            return {'error': f'VirusTotal request failed: {str(e)}'}
    
    def upload_file(self, file_path: str) -> Dict:
        """Upload file to VirusTotal for analysis (premium feature)"""
        if not self.api_key:
            return {'error': 'No VirusTotal API key provided'}
        
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 32MB limit for free tier
            return {'error': 'File too large for upload (32MB limit)'}
        
        self._respect_rate_limit()
        
        try:
            print(f"📤 Uploading {Path(file_path).name} to VirusTotal...")
            
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = self.session.post(f"{self.base_url}/files", files=files)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                
                print(f"✅ Upload successful, analysis ID: {analysis_id}")
                return {
                    'upload_successful': True,
                    'analysis_id': analysis_id,
                    'message': 'File uploaded, analysis in progress'
                }
            else:
                return {
                    'error': f'Upload failed: {response.status_code}',
                    'message': response.text
                }
                
        except Exception as e:
            return {'error': f'Upload failed: {str(e)}'}
    
    def get_analysis_result(self, analysis_id: str) -> Dict:
        """Get analysis results by analysis ID"""
        if not self.api_key:
            return {'error': 'No VirusTotal API key provided'}
        
        self._respect_rate_limit()
        
        try:
            response = self.session.get(f"{self.base_url}/analyses/{analysis_id}")
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_vt_analysis(data)
            else:
                return {
                    'error': f'Analysis retrieval failed: {response.status_code}',
                    'message': response.text
                }
                
        except Exception as e:
            return {'error': f'Analysis retrieval failed: {str(e)}'}
    
    def _parse_vt_response(self, data: Dict) -> Dict:
        """Parse VirusTotal API response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        engines = attributes.get('last_analysis_results', {})
        
        # Count detections
        positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(stats.values())
        
        # Parse engine results
        engine_results = {}
        for engine_name, result in engines.items():
            engine_results[engine_name] = {
                'category': result.get('category', 'undetected'),
                'result': result.get('result'),
                'version': result.get('version'),
                'update': result.get('update')
            }
        
        return {
            'found': True,
            'positives': positives,
            'total': total,
            'detection_ratio': f"{positives}/{total}",
            'scan_date': attributes.get('last_analysis_date'),
            'md5': attributes.get('md5'),
            'sha1': attributes.get('sha1'),
            'sha256': attributes.get('sha256'),
            'file_size': attributes.get('size'),
            'file_type': attributes.get('type_description'),
            'stats': stats,
            'engines': engine_results,
            'permalink': f"https://www.virustotal.com/gui/file/{attributes.get('sha256')}"
        }
    
    def _parse_vt_analysis(self, data: Dict) -> Dict:
        """Parse VirusTotal analysis response"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('stats', {})
        
        return {
            'status': attributes.get('status'),
            'stats': stats,
            'date': attributes.get('date')
        }
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM vt_cache')
                total_entries = cursor.fetchone()[0]
                
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM vt_cache 
                    WHERE date(scan_date) = date('now')
                ''')
                today_entries = cursor.fetchone()[0]
                
                cursor = conn.execute('''
                    SELECT AVG(positives), AVG(total_engines) FROM vt_cache
                    WHERE positives > 0
                ''')
                avg_stats = cursor.fetchone()
                
                return {
                    'total_cached': total_entries,
                    'cached_today': today_entries,
                    'avg_positives': avg_stats[0] or 0,
                    'avg_total_engines': avg_stats[1] or 0
                }
        except Exception as e:
            return {'error': f'Cache stats error: {e}'}

class EnhancedMalwareDetector:
    """Enhanced malware detector with VirusTotal integration"""
    
    def __init__(self, ai_model="llama3.2", ollama_url="http://localhost:11434", vt_api_key=None):
        # Import AI detector
        try:
            from ai_powered_detector import RealTimeMalwareDetector
            self.ai_detector = RealTimeMalwareDetector(ai_model, ollama_url)
        except ImportError:
            print("⚠️ AI detector not available")
            self.ai_detector = None
        
        # Initialize VirusTotal client
        self.vt_client = VirusTotalClient(vt_api_key)
        
        # Detection weights for final scoring
        self.weights = {
            'virustotal': 0.4,
            'ai_analysis': 0.3,
            'yara_rules': 0.3
        }
    
    def comprehensive_analysis(self, file_path: str) -> Dict:
        """Perform comprehensive analysis using multiple detection methods"""
        file_path = Path(file_path)
        
        print(f"🎯 COMPREHENSIVE MALWARE ANALYSIS")
        print("="*60)
        print(f"Target: {file_path}")
        print(f"Size: {file_path.stat().st_size / 1024:.1f} KB")
        print("="*60)
        
        result = {
            'file_path': str(file_path),
            'analysis_timestamp': datetime.now().isoformat(),
            'file_size': file_path.stat().st_size,
            'virustotal': {},
            'ai_analysis': {},
            'yara_analysis': {},
            'final_verdict': 'UNKNOWN',
            'confidence_score': 0.0,
            'threat_level': 'UNKNOWN'
        }
        
        # 1. VirusTotal Analysis
        print("🛡️ Step 1: VirusTotal Multi-Engine Analysis")
        file_hash = self.vt_client.calculate_file_hash(file_path)
        if file_hash:
            result['file_hash'] = file_hash
            vt_result = self.vt_client.check_file_hash(file_hash)
            result['virustotal'] = vt_result
            
            if 'error' not in vt_result:
                if vt_result.get('found'):
                    print(f"   ✅ VirusTotal: {vt_result['detection_ratio']} engines detected threats")
                    print(f"   🔗 Report: {vt_result.get('permalink', 'N/A')}")
                else:
                    print("   ℹ️ VirusTotal: File not found in database")
            else:
                print(f"   ❌ VirusTotal: {vt_result.get('error', 'Unknown error')}")
        
        # 2. AI-Powered Analysis
        print("\n🤖 Step 2: AI-Powered Pattern Analysis")
        if self.ai_detector:
            ai_result = self.ai_detector.scan_file_comprehensive(file_path, "comprehensive")
            result['ai_analysis'] = ai_result
            
            verdict = ai_result.get('final_verdict', 'UNKNOWN')
            confidence = ai_result.get('confidence', 0)
            print(f"   🎯 AI Analysis: {verdict} (confidence: {confidence:.1%})")
        else:
            print("   ⚠️ AI Analysis: Not available")
        
        # 3. Calculate Final Verdict
        print("\n🧮 Step 3: Multi-Engine Verdict Calculation")
        final_verdict, confidence_score, threat_level = self._calculate_final_verdict(result)
        
        result['final_verdict'] = final_verdict
        result['confidence_score'] = confidence_score
        result['threat_level'] = threat_level
        
        # 4. Print Final Assessment
        self._print_comprehensive_assessment(result)
        
        return result
    
    def _calculate_final_verdict(self, analysis_result: Dict) -> Tuple[str, float, str]:
        """Calculate final verdict based on all detection methods"""
        scores = {'vt': 0.0, 'ai': 0.0, 'yara': 0.0}
        
        # VirusTotal scoring
        vt_data = analysis_result.get('virustotal', {})
        if vt_data.get('found') and 'error' not in vt_data:
            positives = vt_data.get('positives', 0)
            total = vt_data.get('total', 1)
            
            if positives > 0:
                # Score based on detection ratio
                detection_ratio = positives / total
                if detection_ratio >= 0.3:  # 30%+ detection
                    scores['vt'] = 0.9
                elif detection_ratio >= 0.15:  # 15%+ detection
                    scores['vt'] = 0.7
                elif detection_ratio >= 0.05:  # 5%+ detection
                    scores['vt'] = 0.5
                else:
                    scores['vt'] = 0.3
        
        # AI Analysis scoring
        ai_data = analysis_result.get('ai_analysis', {})
        if ai_data.get('final_verdict'):
            verdict = ai_data['final_verdict']
            confidence = ai_data.get('confidence', 0)
            
            if verdict == 'MALICIOUS':
                scores['ai'] = 0.9 * confidence
            elif verdict == 'SUSPICIOUS':
                scores['ai'] = 0.6 * confidence
            elif verdict == 'QUESTIONABLE':
                scores['ai'] = 0.3 * confidence
        
        # YARA scoring (from AI detector)
        yara_matches = ai_data.get('yara_matches', [])
        if yara_matches:
            scores['yara'] = min(len(yara_matches) * 0.2, 0.8)
        
        # Calculate weighted final score
        final_score = (
            scores['vt'] * self.weights['virustotal'] +
            scores['ai'] * self.weights['ai_analysis'] +
            scores['yara'] * self.weights['yara_rules']
        )
        
        # Determine verdict and threat level
        if final_score >= 0.8:
            verdict = "MALICIOUS"
            threat_level = "HIGH"
        elif final_score >= 0.6:
            verdict = "SUSPICIOUS"
            threat_level = "MEDIUM"
        elif final_score >= 0.3:
            verdict = "QUESTIONABLE"
            threat_level = "LOW"
        else:
            verdict = "CLEAN"
            threat_level = "MINIMAL"
        
        return verdict, final_score, threat_level
    
    def _print_comprehensive_assessment(self, result: Dict):
        """Print comprehensive assessment results"""
        print("\n" + "="*60)
        print("🏆 COMPREHENSIVE ASSESSMENT")
        print("="*60)
        
        # Final verdict with color coding
        verdict = result['final_verdict']
        confidence = result['confidence_score']
        threat_level = result['threat_level']
        
        verdict_colors = {
            'MALICIOUS': '🔴',
            'SUSPICIOUS': '🟡',
            'QUESTIONABLE': '🟠',
            'CLEAN': '🟢'
        }
        
        color = verdict_colors.get(verdict, '⚪')
        print(f"{color} FINAL VERDICT: {verdict}")
        print(f"📊 Confidence Score: {confidence:.1%}")
        print(f"⚠️ Threat Level: {threat_level}")
        
        # VirusTotal summary
        vt_data = result.get('virustotal', {})
        if vt_data.get('found'):
            print(f"\n🛡️ VirusTotal: {vt_data['detection_ratio']} engines detected threats")
            if vt_data.get('positives', 0) > 0:
                print(f"   📋 Detected by: {vt_data['positives']}/{vt_data['total']} engines")
        
        # AI Analysis summary
        ai_data = result.get('ai_analysis', {})
        if ai_data.get('final_verdict'):
            print(f"\n🤖 AI Analysis: {ai_data['final_verdict']}")
            if ai_data.get('ai_analysis', {}).get('threat_level'):
                print(f"   🎯 AI Threat Level: {ai_data['ai_analysis']['threat_level']}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if verdict == 'MALICIOUS':
            print("   🚨 IMMEDIATE ACTION: Quarantine file")
            print("   🔒 Block execution and network access")
            print("   🕵️ Investigate source and potential spread")
        elif verdict == 'SUSPICIOUS':
            print("   ⚠️ Monitor file activity closely")
            print("   🔍 Consider manual analysis")
            print("   🚫 Restrict execution permissions")
        elif verdict == 'QUESTIONABLE':
            print("   👀 Keep under observation")
            print("   📊 Consider additional scanning")
        else:
            print("   ✅ File appears safe based on current analysis")
        
        print("="*60)

def setup_virustotal_api():
    """Setup VirusTotal API key configuration"""
    print("🔧 VIRUSTOTAL API SETUP")
    print("="*40)
    
    # Check if API key exists
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if api_key:
        print(f"✅ API Key found: {api_key[:8]}...{api_key[-4:]}")
        return api_key
    
    print("ℹ️ No VirusTotal API key found")
    print("\n📋 To get a FREE VirusTotal API key:")
    print("1. Visit: https://www.virustotal.com/gui/join-us")
    print("2. Create free account")
    print("3. Go to: https://www.virustotal.com/gui/my-apikey")
    print("4. Copy your API key")
    
    print("\n⚙️ Setup options:")
    print("A) Set environment variable:")
    print("   export VIRUSTOTAL_API_KEY='your_key_here'")
    print("\nB) Create .env file:")
    print("   echo 'VIRUSTOTAL_API_KEY=your_key_here' > .env")
    
    # Interactive setup
    response = input("\nDo you have an API key to enter now? [y/N]: ").strip().lower()
    if response in ['y', 'yes']:
        api_key = input("Enter your VirusTotal API key: ").strip()
        if api_key:
            # Save to .env file
            with open('.env', 'w') as f:
                f.write(f'VIRUSTOTAL_API_KEY={api_key}\n')
            print("✅ API key saved to .env file")
            return api_key
    
    print("⚠️ Continuing without VirusTotal integration")
    return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Malware Detector with VirusTotal Integration')
    parser.add_argument('file_path', help='File to analyze')
    parser.add_argument('--ai-model', default='llama3.2', help='AI model to use')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama server URL')
    parser.add_argument('--vt-api-key', help='VirusTotal API key')
    parser.add_argument('--setup-vt', action='store_true', help='Setup VirusTotal API key')
    parser.add_argument('--cache-stats', action='store_true', help='Show cache statistics')
    
    args = parser.parse_args()
    
    # Setup VirusTotal API if requested
    if args.setup_vt:
        setup_virustotal_api()
        return
    
    # Get API key
    vt_api_key = args.vt_api_key or setup_virustotal_api()
    
    # Show cache stats if requested
    if args.cache_stats:
        vt_client = VirusTotalClient(vt_api_key)
        stats = vt_client.get_cache_stats()
        print("📊 VirusTotal Cache Statistics:")
        for key, value in stats.items():
            print(f"   {key}: {value}")
        return
    
    # Check file exists
    if not os.path.exists(args.file_path):
        print(f"❌ File not found: {args.file_path}")
        sys.exit(1)
    
    try:
        # Initialize enhanced detector
        detector = EnhancedMalwareDetector(
            ai_model=args.ai_model,
            ollama_url=args.ollama_url,
            vt_api_key=vt_api_key
        )
        
        # Perform comprehensive analysis
        result = detector.comprehensive_analysis(args.file_path)
        
        # Save detailed results
        output_file = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        
        print(f"\n💾 Detailed report saved: {output_file}")
        
    except KeyboardInterrupt:
        print("\n🛑 Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
