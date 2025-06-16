#!/usr/bin/env python3
"""
Detection Testing Script for AI-Generated Malware Sample
========================================================
This script tests various detection methods on the AI-generated malware sample.
It demonstrates how different detection techniques identify AI-generated patterns.
"""

import os
import sys
import re
import json
import math
import subprocess
from collections import Counter
from pathlib import Path

class AIDetectionTester:
    """
    Class to test AI-generated malware detection methods
    """
    
    def __init__(self, sample_file):
        self.sample_file = sample_file
        self.sample_code = ""
        self.results = {}
        
        # Load the sample file
        self.load_sample()
    
    def load_sample(self):
        """Load the malware sample for analysis"""
        try:
            with open(self.sample_file, 'r', encoding='utf-8') as f:
                self.sample_code = f.read()
            print(f"✅ Loaded sample: {self.sample_file}")
            print(f"   Size: {len(self.sample_code)} characters")
        except Exception as e:
            print(f"❌ Failed to load sample: {e}")
            sys.exit(1)
    
    def test_comment_density(self):
        """Test comment density analysis"""
        lines = self.sample_code.split('\n')
        comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
        total_lines = len([line for line in lines if line.strip()])
        
        if total_lines > 0:
            comment_ratio = comment_lines / total_lines
            is_suspicious = comment_ratio > 0.25
            
            self.results['comment_density'] = {
                'ratio': round(comment_ratio, 3),
                'comment_lines': comment_lines,
                'total_lines': total_lines,
                'suspicious': is_suspicious,
                'threshold': 0.25
            }
            
            status = "🔍 SUSPICIOUS" if is_suspicious else "✅ NORMAL"
            print(f"\n📝 Comment Density Analysis:")
            print(f"   {status} - Ratio: {comment_ratio:.3f} (threshold: 0.25)")
            print(f"   Comment lines: {comment_lines}/{total_lines}")
        
        return self.results.get('comment_density', {})
    
    def test_function_patterns(self):
        """Test AI function naming patterns"""
        patterns = {
            'verb_noun_noun': r'def \w+_\w+_\w+\(',
            'collect_pattern': r'def collect_\w+\(',
            'generate_pattern': r'def generate_\w+\(',
            'simulate_pattern': r'def simulate_\w+\(',
            'handle_pattern': r'def handle_\w+\(',
        }
        
        matches = {}
        total_matches = 0
        
        for pattern_name, pattern in patterns.items():
            found = re.findall(pattern, self.sample_code)
            matches[pattern_name] = len(found)
            total_matches += len(found)
        
        is_suspicious = total_matches > 3
        
        self.results['function_patterns'] = {
            'matches': matches,
            'total_matches': total_matches,
            'suspicious': is_suspicious,
            'threshold': 3
        }
        
        status = "🔍 SUSPICIOUS" if is_suspicious else "✅ NORMAL"
        print(f"\n🔧 Function Pattern Analysis:")
        print(f"   {status} - Total matches: {total_matches} (threshold: 3)")
        for pattern_name, count in matches.items():
            if count > 0:
                print(f"   - {pattern_name}: {count}")
        
        return self.results['function_patterns']
    
    def test_import_analysis(self):
        """Test import statement analysis"""
        import_lines = [line.strip() for line in self.sample_code.split('\n') 
                       if line.strip().startswith('import ') or line.strip().startswith('from ')]
        
        common_ai_imports = [
            'os', 'sys', 'time', 'json', 'base64', 
            'hashlib', 'random', 'string', 'urllib', 'datetime'
        ]
        
        found_imports = []
        for imp in common_ai_imports:
            if any(imp in line for line in import_lines):
                found_imports.append(imp)
        
        is_suspicious = len(found_imports) > 5
        
        self.results['import_analysis'] = {
            'total_imports': len(import_lines),
            'ai_imports_found': found_imports,
            'ai_import_count': len(found_imports),
            'suspicious': is_suspicious,
            'threshold': 5
        }
        
        status = "🔍 SUSPICIOUS" if is_suspicious else "✅ NORMAL"
        print(f"\n📦 Import Analysis:")
        print(f"   {status} - AI imports: {len(found_imports)}/10 (threshold: 5)")
        print(f"   Total imports: {len(import_lines)}")
        print(f"   AI imports found: {', '.join(found_imports)}")
        
        return self.results['import_analysis']
    
    def test_entropy_analysis(self):
        """Test entropy analysis"""
        data = self.sample_code.encode()
        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = 0
        
        for count in byte_counts.values():
            p = count / total_bytes
            if p > 0:
                entropy -= p * math.log2(p)
        
        # AI-generated code typically has entropy between 4.0-5.5
        is_suspicious = 4.0 <= entropy <= 5.5
        
        self.results['entropy_analysis'] = {
            'entropy': round(entropy, 3),
            'suspicious': is_suspicious,
            'ai_range': [4.0, 5.5]
        }
        
        status = "🔍 SUSPICIOUS" if is_suspicious else "✅ NORMAL"
        print(f"\n🌪️ Entropy Analysis:")
        print(f"   {status} - Entropy: {entropy:.3f} (AI range: 4.0-5.5)")
        
        return self.results['entropy_analysis']
    
    def test_class_patterns(self):
        """Test AI class naming patterns"""
        class_patterns = [
            r'class \w+Manager',
            r'class \w+Handler',
            r'class \w+Gatherer',
            r'class \w+Communicator'
        ]
        
        found_classes = []
        for pattern in class_patterns:
            matches = re.findall(pattern, self.sample_code)
            found_classes.extend(matches)
        
        is_suspicious = len(found_classes) > 1
        
        self.results['class_patterns'] = {
            'found_classes': found_classes,
            'count': len(found_classes),
            'suspicious': is_suspicious,
            'threshold': 1
        }
        
        status = "🔍 SUSPICIOUS" if is_suspicious else "✅ NORMAL"
        print(f"\n🏗️ Class Pattern Analysis:")
        print(f"   {status} - AI class patterns: {len(found_classes)} (threshold: 1)")
        if found_classes:
            for cls in found_classes:
                print(f"   - {cls}")
        
        return self.results['class_patterns']
    
    def test_string_patterns(self):
        """Test suspicious string patterns"""
        ai_strings = [
            "This is a comment explaining",
            "Function to process",
            "Method to gather",
            "This demonstrates",
            "[INFO]",
            "[ERROR]",
            "[STAGE"
        ]
        
        found_strings = []
        for string in ai_strings:
            if string in self.sample_code:
                count = self.sample_code.count(string)
                found_strings.append({'string': string, 'count': count})
        
        total_matches = sum(item['count'] for item in found_strings)
        is_suspicious = total_matches > 5
        
        self.results['string_patterns'] = {
            'found_strings': found_strings,
            'total_matches': total_matches,
            'suspicious': is_suspicious,
            'threshold': 5
        }
        
        status = "🔍 SUSPICIOUS" if is_suspicious else "✅ NORMAL"
        print(f"\n🔤 String Pattern Analysis:")
        print(f"   {status} - AI strings: {total_matches} (threshold: 5)")
        for item in found_strings[:3]:  # Show top 3
            print(f"   - '{item['string']}': {item['count']} times")
        
        return self.results['string_patterns']
    
    def calculate_overall_score(self):
        """Calculate overall AI detection score"""
        score = 0
        max_score = 0
        
        # Weight different detection methods
        weights = {
            'comment_density': 0.2,
            'function_patterns': 0.2,
            'import_analysis': 0.15,
            'entropy_analysis': 0.15,
            'class_patterns': 0.15,
            'string_patterns': 0.15
        }
        
        for method, weight in weights.items():
            if method in self.results:
                if self.results[method].get('suspicious', False):
                    score += weight
                max_score += weight
        
        final_score = score / max_score if max_score > 0 else 0
        
        self.results['overall_score'] = {
            'score': round(final_score, 3),
            'percentage': round(final_score * 100, 1),
            'classification': self.classify_sample(final_score)
        }
        
        return final_score
    
    def classify_sample(self, score):
        """Classify sample based on score"""
        if score >= 0.7:
            return "🔴 HIGHLY SUSPICIOUS (AI-Generated)"
        elif score >= 0.5:
            return "🟡 SUSPICIOUS (Possibly AI-Generated)"
        elif score >= 0.3:
            return "🟠 MODERATE (Some AI Patterns)"
        else:
            return "🟢 CLEAN (Low AI Patterns)"
    
    def run_all_tests(self):
        """Run all detection tests"""
        print("="*60)
        print("🤖 AI-GENERATED MALWARE DETECTION TESTING")
        print("="*60)
        
        # Run individual tests
        self.test_comment_density()
        self.test_function_patterns()
        self.test_import_analysis()
        self.test_entropy_analysis()
        self.test_class_patterns()
        self.test_string_patterns()
        
        # Calculate overall score
        overall_score = self.calculate_overall_score()
        
        # Print summary
        print("\n" + "="*60)
        print("📊 DETECTION SUMMARY")
        print("="*60)
        
        classification = self.results['overall_score']['classification']
        percentage = self.results['overall_score']['percentage']
        
        print(f"🎯 Overall Score: {percentage}%")
        print(f"🏷️ Classification: {classification}")
        
        print(f"\n📋 Individual Test Results:")
        for method in ['comment_density', 'function_patterns', 'import_analysis', 
                      'entropy_analysis', 'class_patterns', 'string_patterns']:
            if method in self.results:
                result = self.results[method]
                status = "🔍 SUSPICIOUS" if result.get('suspicious', False) else "✅ NORMAL"
                print(f"   {method.replace('_', ' ').title()}: {status}")
        
        return self.results
    
    def test_with_external_detector(self):
        """Test with external malware detector if available"""
        detector_script = Path("malware_detector.py")
        
        if detector_script.exists():
            print(f"\n🔍 Testing with external detector...")
            try:
                result = subprocess.run([
                    sys.executable, str(detector_script), self.sample_file
                ], capture_output=True, text=True, timeout=30)
                
                print("External Detector Output:")
                print("-" * 40)
                print(result.stdout)
                
                if result.stderr:
                    print("Errors:")
                    print(result.stderr)
                    
            except subprocess.TimeoutExpired:
                print("❌ External detector timed out")
            except Exception as e:
                print(f"❌ Error running external detector: {e}")
        else:
            print(f"\n⚠️ External detector not found: {detector_script}")
            print("   Place malware_detector.py in the same directory to test")
    
    def save_results(self, output_file="detection_results.json"):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n💾 Results saved to: {output_file}")
        except Exception as e:
            print(f"❌ Failed to save results: {e}")

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python test_detection.py <malware_sample.py>")
        sys.exit(1)
    
    sample_file = sys.argv[1]
    
    if not os.path.exists(sample_file):
        print(f"❌ Sample file not found: {sample_file}")
        sys.exit(1)
    
    # Run detection tests
    tester = AIDetectionTester(sample_file)
    results = tester.run_all_tests()
    
    # Test with external detector
    tester.test_with_external_detector()
    
    # Save results
    tester.save_results()
    
    print("\n" + "="*60)
    print("✅ TESTING COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
