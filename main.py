#!/usr/bin/env python3
"""
Enhanced Main entry point for AI-Enhanced VAPT Tool
"""

import time
import sys
import traceback
from datetime import datetime
from modules.information_gathering import InformationGatherer
from modules.scanner import VulnerabilityScanner
from modules.ai_analyzer import AIAnalyzer
from modules.pentest import PenetrationTester
from modules.reporter import ReportGenerator
from config.settings import VAPTConfig
from utils.helpers import display_banner, format_duration
from utils.api_client import DeepSeekClient

class VAPTOrchestrator:
    def __init__(self):
        self.config = VAPTConfig()
        self.assessment_data = {
            'client_info': {},
            'scan_results': {},
            'vulnerability_data': [],
            'penetration_plan': [],
            'report_data': {},
            'start_time': None,
            'end_time': None
        }
        
    def _validate_api_key(self, api_key):
        """Validate that the API key is working"""
        print("🔑 Validating API key...")
        try:
            test_client = DeepSeekClient(self.config)
            test_client.set_api_key(api_key)
            
            # Test with a simple prompt
            test_response = test_client._call_api(
                "Respond with only: {\"status\": \"ok\"}",
                "You are a test assistant. Return only JSON."
            )
            
            if test_response and test_response.get('status') == 'ok':
                print("✅ API key validation successful")
                return True
            else:
                print("❌ API key validation failed - invalid response")
                return False
                
        except Exception as e:
            print(f"❌ API key validation failed: {e}")
            return False

    def run_assessment(self):
        """Orchestrate the complete VAPT assessment with enhanced error handling"""
        self.assessment_data['start_time'] = datetime.now()
        
        display_banner("🚀 AI-Enhanced VAPT Assessment Started", 60)
        print(f"Start Time: {self.assessment_data['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        try:
            # Initialize modules
            info_gatherer = InformationGatherer(self.config)
            scanner = VulnerabilityScanner(self.config)
            ai_analyzer = AIAnalyzer(self.config)
            pentester = PenetrationTester(self.config)
            reporter = ReportGenerator(self.config)
            
            phases = [
                ("Information Gathering", info_gatherer.execute),
                ("Vulnerability Assessment", scanner.execute),
                ("AI Analysis", ai_analyzer.execute),
                ("Penetration Test Planning", pentester.execute),
                ("Report Generation", reporter.execute)
            ]
            
            for phase_name, phase_method in phases:
                phase_start = time.time()
                print(f"\n🔄 Starting {phase_name}...")
                
                try:
                    success = phase_method(self.assessment_data)
                    phase_duration = time.time() - phase_start
                    
                    if success:
                        print(f"✅ {phase_name} completed successfully ({format_duration(phase_duration)})")
                    else:
                        print(f"❌ {phase_name} failed after {format_duration(phase_duration)}")
                        if not self._handle_phase_failure(phase_name):
                            break
                        
                except KeyboardInterrupt:
                    print(f"\n⏹️  {phase_name} interrupted by user")
                    if not self._handle_user_interrupt():
                        break
                except Exception as e:
                    print(f"❌ Unexpected error in {phase_name}: {e}")
                    traceback.print_exc()
                    if not self._handle_phase_failure(phase_name):
                        break
                    
                time.sleep(1)  # Brief pause between phases
                
            else:
                # All phases completed successfully
                self.assessment_data['end_time'] = datetime.now()
                self._display_completion_summary()
                return True
                
        except Exception as e:
            print(f"\n💥 Critical error in assessment orchestration: {e}")
            traceback.print_exc()
            return False
            
        return False
        
    def _handle_phase_failure(self, phase_name):
        """Handle phase failure with user interaction"""
        print(f"\n⚠️  {phase_name} phase failed.")
        
        for attempt in range(3):
            response = input("Do you want to [c]ontinue, [r]etry, or [q]uit? ").strip().lower()
            
            if response in ['c', 'continue']:
                print("Continuing to next phase...")
                return True
            elif response in ['r', 'retry']:
                print("Retry functionality not yet implemented. Continuing to next phase...")
                return True
            elif response in ['q', 'quit']:
                print("Assessment terminated by user.")
                return False
            else:
                print("Please enter 'c' to continue, 'r' to retry, or 'q' to quit")
                
        print("Invalid response after 3 attempts. Continuing...")
        return True
        
    def _handle_user_interrupt(self):
        """Handle user interrupt (Ctrl+C)"""
        print("\n\n⚠️  Assessment interrupted by user")
        response = input("Do you want to [c]ontinue or [q]uit? ").strip().lower()
        return response in ['c', 'continue']
        
    def _display_completion_summary(self):
        """Display assessment completion summary"""
        duration = (self.assessment_data['end_time'] - self.assessment_data['start_time']).total_seconds()
        
        display_banner("🎯 Assessment Complete!", 60)
        print(f"Client: {self.assessment_data['client_info'].get('client_name', 'Unknown')}")
        print(f"Target: {self.assessment_data['client_info'].get('target_ip', 'Unknown')}")
        print(f"Start Time: {self.assessment_data['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"End Time: {self.assessment_data['end_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Duration: {format_duration(duration)}")
        print(f"Vulnerabilities Found: {len(self.assessment_data.get('vulnerability_data', []))}")
        
        if 'report_file' in self.assessment_data['client_info']:
            print(f"📄 Report Generated: {self.assessment_data['client_info']['report_file']}")
            
        print("=" * 60)

def main():
    """Enhanced main execution function"""
    try:
        orchestrator = VAPTOrchestrator()
        success = orchestrator.run_assessment()
        
        if success:
            print("\n✨ Assessment completed successfully!")
            sys.exit(0)
        else:
            print("\n💥 Assessment failed or was terminated.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Assessment cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()