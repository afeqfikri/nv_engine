#!/usr/bin/env python3
"""
Batch Malware Analysis Processor
================================
Processes large numbers of files for malware analysis using AI detection
Generates comprehensive reports with statistics and threat intelligence
"""

import os
import sys
import json
import csv
import time
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
import argparse

# Import our AI detector
try:
    from ai_powered_detector import RealTimeMalwareDetector, OllamaClient, EnhancedYARADetector
    DETECTOR_AVAILABLE = True
except ImportError:
    DETECTOR_AVAILABLE = False
    print("⚠️ Warning: ai_powered_detector.py not found. Some features may be limited.")

class BatchAnalysisProcessor:
    """Processes large batches of files for malware analysis"""
    
    def __init__(self, ollama_model="llama3.2", ollama_url="http://localhost:11434", max_workers=4):
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url
        self.max_workers = max_workers
        
        # Initialize components
        if DETECTOR_AVAILABLE:
            self.detector = RealTimeMalwareDetector(ollama_model, ollama_url)
        else:
            self.detector = None
            
        # Statistics tracking
        self.stats = {
            'total_files': 0,
            'processed_files': 0,
            'error_files': 0,
            'verdicts': defaultdict(int),
            'file_types': defaultdict(int),
            'threat_indicators': defaultdict(int),
            'processing_times': [],
            'ai_confidence_scores': []
        }
        
        # Thread safety
        self.stats_lock = threading.Lock()
        self.progress_lock = threading.Lock()
        
        # File extensions to process
        self.scannable_extensions = {
            '.py', '.js', '.php', '.pl', '.rb', '.sh', '.bat', '.cmd',
            '.ps1', '.vbs', '.jar', '.exe', '.dll', '.scr', '.com',
            '.html', '.htm', '.asp', '.aspx', '.jsp', '.c', '.cpp',
            '.java', '.cs', '.go', '.rs', '.swift', '.kt'
        }
    
    def discover_files(self, paths, recursive=True):
        """Discover all files to be processed"""
        files_to_process = []
        
        for path_str in paths:
            path = Path(path_str)
            
            if path.is_file():
                if self.is_scannable_file(path):
                    files_to_process.append(path)
            elif path.is_dir():
                if recursive:
                    for file_path in path.rglob('*'):
                        if file_path.is_file() and self.is_scannable_file(file_path):
                            files_to_process.append(file_path)
                else:
                    for file_path in path.iterdir():
                        if file_path.is_file() and self.is_scannable_file(file_path):
                            files_to_process.append(file_path)
        
        return files_to_process
    
    def is_scannable_file(self, file_path):
        """Check if file should be scanned"""
        # Check extension
        if file_path.suffix.lower() not in self.scannable_extensions:
            return False
        
        # Check file size (skip very large files)
        try:
            if file_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                return False
        except:
            return False
        
        # Skip hidden files and directories
        if file_path.name.startswith('.'):
            return False
        
        return True
    
    def process_single_file(self, file_path):
        """Process a single file and return results"""
        start_time = time.time()
        
        try:
            if self.detector:
                # Use full AI-powered detection
                result = self.detector.scan_file_comprehensive(file_path, "batch")
            else:
                # Fallback to basic analysis
                result = self.basic_file_analysis(file_path)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            # Update statistics
            with self.stats_lock:
                self.stats['processed_files'] += 1
                self.stats['processing_times'].append(processing_time)
                self.stats['verdicts'][result.get('final_verdict', 'UNKNOWN')] += 1
                self.stats['file_types'][file_path.suffix.lower()] += 1
                
                # Track AI confidence if available
                if 'ai_analysis' in result and 'confidence' in result.get('ai_analysis', {}):
                    confidence = result['ai_analysis']['confidence']
                    self.stats['ai_confidence_scores'].append(confidence)
                
                # Track threat indicators
                if result.get('yara_matches'):
                    for match in result['yara_matches']:
                        if 'rule' in match:
                            self.stats['threat_indicators'][match['rule']] += 1
            
            return result
            
        except Exception as e:
            with self.stats_lock:
                self.stats['error_files'] += 1
            
            return {
                'file_path': str(file_path),
                'error': str(e),
                'final_verdict': 'ERROR',
                'processing_time': time.time() - start_time
            }
    
    def basic_file_analysis(self, file_path):
        """Basic file analysis when full detector is not available"""
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Basic suspicious pattern detection
            suspicious_patterns = [
                b'cmd.exe', b'powershell', b'subprocess.call', b'system(',
                b'base64.decode', b'eval(', b'exec(', b'urllib.request'
            ]
            
            found_patterns = []
            for pattern in suspicious_patterns:
                if pattern in content:
                    found_patterns.append(pattern.decode('utf-8', errors='ignore'))
            
            # Determine verdict
            if len(found_patterns) >= 3:
                verdict = 'SUSPICIOUS'
            elif len(found_patterns) >= 1:
                verdict = 'QUESTIONABLE'
            else:
                verdict = 'CLEAN'
            
            return {
                'file_path': str(file_path),
                'final_verdict': verdict,
                'confidence': len(found_patterns) * 0.2,
                'found_patterns': found_patterns,
                'file_size': len(content),
                'analysis_method': 'basic'
            }
            
        except Exception as e:
            return {
                'file_path': str(file_path),
                'error': str(e),
                'final_verdict': 'ERROR'
            }
    
    def process_files_batch(self, file_paths, progress_callback=None):
        """Process files in parallel batches"""
        results = []
        
        print(f"🚀 Starting batch processing of {len(file_paths)} files")
        print(f"⚙️ Using {self.max_workers} worker threads")
        print(f"🤖 AI Model: {self.ollama_model}")
        print("="*60)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all files for processing
            future_to_file = {
                executor.submit(self.process_single_file, file_path): file_path 
                for file_path in file_paths
            }
            
            # Process completed futures
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Progress update
                    if progress_callback:
                        progress_callback(len(results), len(file_paths), result)
                    
                    # Print progress
                    with self.progress_lock:
                        progress = len(results) / len(file_paths) * 100
                        verdict = result.get('final_verdict', 'UNKNOWN')
                        verdict_color = {
                            'CLEAN': '🟢',
                            'QUESTIONABLE': '🟠', 
                            'SUSPICIOUS': '🟡',
                            'MALICIOUS': '🔴',
                            'ERROR': '🟣'
                        }.get(verdict, '⚪')
                        
                        print(f"[{progress:5.1f}%] {verdict_color} {verdict:12} | {file_path.name}")
                        
                except Exception as e:
                    print(f"❌ Error processing {file_path}: {e}")
        
        return results
    
    def generate_comprehensive_report(self, results, output_dir):
        """Generate comprehensive analysis report"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Generate summary report
        self._generate_summary_report(results, output_dir / f"summary_{timestamp}.txt")
        
        # 2. Generate detailed CSV report
        self._generate_csv_report(results, output_dir / f"detailed_{timestamp}.csv")
        
        # 3. Generate JSON report for further analysis
        self._generate_json_report(results, output_dir / f"results_{timestamp}.json")
        
        # 4. Generate threat intelligence report
        self._generate_threat_report(results, output_dir / f"threats_{timestamp}.txt")
        
        # 5. Generate statistics report
        self._generate_statistics_report(output_dir / f"statistics_{timestamp}.txt")
        
        print(f"\n📊 Reports generated in: {output_dir}")
        return output_dir
    
    def _generate_summary_report(self, results, output_file):
        """Generate executive summary report"""
        with open(output_file, 'w') as f:
            f.write("AI-POWERED MALWARE ANALYSIS SUMMARY REPORT\n")
            f.write("="*60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"AI Model: {self.ollama_model}\n\n")
            
            # Overall statistics
            f.write("OVERALL STATISTICS\n")
            f.write("-"*30 + "\n")
            f.write(f"Total files processed: {self.stats['processed_files']}\n")
            f.write(f"Processing errors: {self.stats['error_files']}\n")
            f.write(f"Average processing time: {sum(self.stats['processing_times'])/max(len(self.stats['processing_times']), 1):.2f}s\n\n")
            
            # Threat breakdown
            f.write("THREAT ASSESSMENT BREAKDOWN\n")
            f.write("-"*30 + "\n")
            for verdict, count in sorted(self.stats['verdicts'].items()):
                percentage = count / max(self.stats['processed_files'], 1) * 100
                f.write(f"{verdict}: {count} files ({percentage:.1f}%)\n")
            
            # High-priority findings
            f.write("\nHIGH-PRIORITY FINDINGS\n")
            f.write("-"*30 + "\n")
            malicious_files = [r for r in results if r.get('final_verdict') == 'MALICIOUS']
            suspicious_files = [r for r in results if r.get('final_verdict') == 'SUSPICIOUS']
            
            f.write(f"🔴 MALICIOUS files: {len(malicious_files)}\n")
            for result in malicious_files[:10]:  # Top 10
                f.write(f"   - {result['file_path']}\n")
            
            f.write(f"\n🟡 SUSPICIOUS files: {len(suspicious_files)}\n")
            for result in suspicious_files[:10]:  # Top 10
                f.write(f"   - {result['file_path']}\n")
            
            # Recommendations
            f.write("\nRECOMMENDATIONS\n")
            f.write("-"*30 + "\n")
            if malicious_files:
                f.write("• IMMEDIATE ACTION REQUIRED: Quarantine malicious files\n")
                f.write("• Investigate source and propagation of malicious files\n")
            if suspicious_files:
                f.write("• Review suspicious files manually\n")
                f.write("• Monitor suspicious file activity\n")
            f.write("• Implement real-time monitoring for new threats\n")
            f.write("• Update signature databases regularly\n")
    
    def _generate_csv_report(self, results, output_file):
        """Generate detailed CSV report"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'File Path', 'Verdict', 'Confidence', 'File Size', 'Processing Time',
                'YARA Matches', 'AI Generated', 'Threat Level', 'Malicious Indicators'
            ])
            
            # Data rows
            for result in results:
                yara_matches = ', '.join([m.get('rule', '') for m in result.get('yara_matches', []) if 'rule' in m])
                ai_analysis = result.get('ai_analysis', {})
                
                writer.writerow([
                    result.get('file_path', ''),
                    result.get('final_verdict', ''),
                    result.get('confidence', 0),
                    result.get('file_size', 0),
                    result.get('processing_time', 0),
                    yara_matches,
                    ai_analysis.get('ai_generated', ''),
                    ai_analysis.get('threat_level', ''),
                    ', '.join(ai_analysis.get('malicious_indicators', []))
                ])
    
    def _generate_json_report(self, results, output_file):
        """Generate JSON report for programmatic analysis"""
        report_data = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'ai_model': self.ollama_model,
                'total_files': self.stats['processed_files'],
                'processing_stats': dict(self.stats)
            },
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def _generate_threat_report(self, results, output_file):
        """Generate threat intelligence report"""
        with open(output_file, 'w') as f:
            f.write("THREAT INTELLIGENCE REPORT\n")
            f.write("="*50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Threat indicators
            f.write("TOP THREAT INDICATORS\n")
            f.write("-"*30 + "\n")
            for indicator, count in Counter(self.stats['threat_indicators']).most_common(10):
                f.write(f"{indicator}: {count} occurrences\n")
            
            # File type analysis
            f.write("\nFILE TYPE ANALYSIS\n")
            f.write("-"*30 + "\n")
            for file_type, count in Counter(self.stats['file_types']).most_common():
                f.write(f"{file_type}: {count} files\n")
            
            # AI confidence distribution
            if self.stats['ai_confidence_scores']:
                f.write("\nAI CONFIDENCE DISTRIBUTION\n")
                f.write("-"*30 + "\n")
                avg_confidence = sum(self.stats['ai_confidence_scores']) / len(self.stats['ai_confidence_scores'])
                f.write(f"Average AI confidence: {avg_confidence:.2f}\n")
                f.write(f"High confidence detections (>0.8): {sum(1 for c in self.stats['ai_confidence_scores'] if c > 0.8)}\n")
    
    def _generate_statistics_report(self, output_file):
        """Generate detailed statistics report"""
        with open(output_file, 'w') as f:
            f.write("DETAILED STATISTICS REPORT\n")
            f.write("="*50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("PROCESSING STATISTICS\n")
            f.write("-"*30 + "\n")
            if self.stats['processing_times']:
                f.write(f"Total processing time: {sum(self.stats['processing_times']):.2f}s\n")
                f.write(f"Average time per file: {sum(self.stats['processing_times'])/len(self.stats['processing_times']):.2f}s\n")
                f.write(f"Fastest analysis: {min(self.stats['processing_times']):.2f}s\n")
                f.write(f"Slowest analysis: {max(self.stats['processing_times']):.2f}s\n")
            
            f.write(f"\nFiles processed successfully: {self.stats['processed_files']}\n")
            f.write(f"Files with errors: {self.stats['error_files']}\n")
            f.write(f"Success rate: {self.stats['processed_files']/(self.stats['processed_files']+self.stats['error_files'])*100:.1f}%\n")

def main():
    parser = argparse.ArgumentParser(description='Batch Malware Analysis Processor')
    parser.add_argument('paths', nargs='+', help='Paths to analyze (files or directories)')
    parser.add_argument('--model', default='llama3.2', help='Ollama model to use')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama server URL')
    parser.add_argument('--workers', type=int, default=4, help='Number of worker threads')
    parser.add_argument('--output', default='./batch_analysis_reports', help='Output directory for reports')
    parser.add_argument('--no-recursive', action='store_true', help='Don\'t scan directories recursively')
    parser.add_argument('--extensions', help='Comma-separated list of file extensions to scan')
    
    args = parser.parse_args()
    
    # Initialize processor
    processor = BatchAnalysisProcessor(
        ollama_model=args.model,
        ollama_url=args.ollama_url,
        max_workers=args.workers
    )
    
    # Override extensions if specified
    if args.extensions:
        extensions = [ext.strip() for ext in args.extensions.split(',')]
        processor.scannable_extensions = set(extensions)
    
    try:
        start_time = time.time()
        
        # Discover files
        print("🔍 Discovering files to analyze...")
        files_to_process = processor.discover_files(args.paths, not args.no_recursive)
        processor.stats['total_files'] = len(files_to_process)
        
        if not files_to_process:
            print("❌ No files found to process")
            sys.exit(1)
        
        print(f"📁 Found {len(files_to_process)} files to analyze")
        
        # Process files
        results = processor.process_files_batch(files_to_process)
        
        # Generate reports
        print("\n📊 Generating comprehensive reports...")
        report_dir = processor.generate_comprehensive_report(results, args.output)
        
        # Print final summary
        end_time = time.time()
        total_time = end_time - start_time
        
        print("\n" + "="*60)
        print("🎉 BATCH ANALYSIS COMPLETE")
        print("="*60)
        print(f"⏱️ Total time: {total_time:.1f} seconds")
        print(f"📁 Files processed: {processor.stats['processed_files']}")
        print(f"❌ Errors: {processor.stats['error_files']}")
        print(f"📊 Reports saved to: {report_dir}")
        
        # Show threat summary
        print(f"\n🎯 THREAT SUMMARY:")
        for verdict, count in sorted(processor.stats['verdicts'].items()):
            percentage = count / max(processor.stats['processed_files'], 1) * 100
            emoji = {'CLEAN': '🟢', 'SUSPICIOUS': '🟡', 'MALICIOUS': '🔴', 'ERROR': '🟣'}.get(verdict, '⚪')
            print(f"   {emoji} {verdict}: {count} ({percentage:.1f}%)")
            
    except KeyboardInterrupt:
        print("\n🛑 Batch processing interrupted by user")
    except Exception as e:
        print(f"\n❌ Batch processing error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
