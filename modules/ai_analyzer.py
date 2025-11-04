"""
Enhanced AI Analysis Module with proper false positive tracking
"""

import json
import time
from utils.api_client import DeepSeekClient, APIError, AuthenticationError
from utils.helpers import display_banner, safe_get

class AIAnalyzer:
    def __init__(self, config):
        self.config = config
        self.ai_client = DeepSeekClient(config)
        
    def execute(self, assessment_data):
        """Execute AI analysis phase with enhanced error handling"""
        display_banner("PHASE 3: AI ANALYSIS")
        
        if not assessment_data['vulnerability_data']:
            print("ℹ️  No vulnerabilities found for AI analysis")
            return True
            
        # Set API key
        api_key = assessment_data['client_info'].get('deepseek_api_key')
        if not api_key:
            print("❌ No API key found in assessment data")
            return False
            
        self.ai_client.set_api_key(api_key)
        
        print("🤖 Sending vulnerability data to DeepSeek AI for analysis...")
        
        try:
            # Process vulnerabilities in smaller batches for better accuracy
            processed_vulnerabilities = []
            false_positive_count = 0
            validated_count = 0
            
            for i, vulnerability in enumerate(assessment_data['vulnerability_data']):
                print(f"  Analyzing vulnerability {i+1}/{len(assessment_data['vulnerability_data'])}...")
                
                # Skip obvious scanner errors before AI analysis
                if self._is_obvious_scanner_error(vulnerability):
                    vulnerability['is_false_positive'] = True
                    vulnerability['false_positive_reason'] = "Scanner execution error"
                    vulnerability['validated_risk_level'] = 'Informational'
                    false_positive_count += 1
                    processed_vulnerabilities.append(vulnerability)
                    continue
                
                # Create specific prompt for each vulnerability
                prompt = self._create_specific_analysis_prompt(assessment_data, vulnerability)
                
                # Get AI analysis for this specific vulnerability
                ai_response = self.ai_client.analyze_single_vulnerability(prompt)
                
                if ai_response and isinstance(ai_response, dict):
                    # Merge the AI analysis with the original vulnerability
                    enhanced_vuln = {**vulnerability, **ai_response}
                    
                    # Track false positives
                    if enhanced_vuln.get('is_false_positive', False):
                        false_positive_count += 1
                    else:
                        validated_count += 1
                    
                    processed_vulnerabilities.append(enhanced_vuln)
                else:
                    # Keep original if AI analysis fails
                    processed_vulnerabilities.append(vulnerability)
                    validated_count += 1
            
            # Update the assessment data with processed vulnerabilities
            assessment_data['vulnerability_data'] = processed_vulnerabilities
            
            # Store analysis summary
            assessment_data['ai_analysis'] = {
                'analysis_summary': {
                    'total_findings': len(processed_vulnerabilities),
                    'validated_findings': validated_count,
                    'false_positives': false_positive_count,
                    'overall_risk': self._calculate_overall_risk(processed_vulnerabilities),
                    'analysis_confidence': 'High'
                }
            }
            
            print(f"✅ AI analysis completed for {len(processed_vulnerabilities)} vulnerabilities")
            print(f"📊 Summary: {validated_count} validated, {false_positive_count} false positives")
            return True
                
        except AuthenticationError as e:
            print(f"❌ Authentication error: {e}")
            return False
        except APIError as e:
            print(f"❌ API error during AI analysis: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error during AI analysis: {e}")
            return False
    
    def _is_obvious_scanner_error(self, vulnerability):
        """Identify obvious scanner errors before AI analysis"""
        description = vulnerability.get('description', '').lower()
        vuln_name = vulnerability.get('vulnerability_name', '').lower()
        
        # Check for scanner execution errors
        scanner_error_indicators = [
            'error: script execution failed',
            'script execution failed',
            'error: nmap script failed',
            'could not run script',
            'script timed out',
            'connection refused',
            'no response',
            'host seems down'
        ]
        
        for indicator in scanner_error_indicators:
            if indicator in description:
                return True
        
        # Check for specific false positive patterns
        if 'cve2014' in vuln_name and 'error' in description:
            return True
            
        return False
            
    def _calculate_overall_risk(self, vulnerabilities):
        """Calculate overall risk based on validated vulnerabilities"""
        if not vulnerabilities:
            return 'Low'
            
        risk_scores = {'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}
        max_score = 0
        
        for vuln in vulnerabilities:
            if not vuln.get('is_false_positive', False):
                risk_level = vuln.get('validated_risk_level', vuln.get('risk_level', 'Informational'))
                score = risk_scores.get(risk_level, 0)
                max_score = max(max_score, score)
        
        if max_score >= 3:
            return 'High'
        elif max_score >= 2:
            return 'Medium'
        else:
            return 'Low'
            
    def _create_specific_analysis_prompt(self, assessment_data, vulnerability):
        """Create specific AI prompt for individual vulnerability analysis"""
        client_info = assessment_data['client_info']
        
        prompt_template = """
        IMPORTANT: You MUST return ONLY valid JSON format. Do not include any other text.
        CRITICAL: Your analysis MUST be specific to the vulnerability described below.

        As a senior cybersecurity analyst, analyze this specific vulnerability finding:

        CLIENT: {client_name}
        TARGET: {target_ip}
        
        SPECIFIC VULNERABILITY TO ANALYZE:
        - Service: {service_type}
        - Port: {port}
        - Protocol: {protocol}
        - Vulnerability Name: {vuln_name}
        - Description: {vuln_description}
        - Current Risk Level: {current_risk}

        SERVICE CONTEXT:
        {service_context}

        Analyze this vulnerability and determine if it's a valid finding or a false positive.
        Pay special attention to scanner errors, incomplete scans, or misconfigurations.

        Return ONLY JSON with this exact structure:
        {{
            "validated_risk_level": "High/Medium/Low/Informational",
            "is_false_positive": boolean,
            "technical_analysis": "DETAILED analysis specific to {service_type} service and the described vulnerability. If this is a scanner error, explain why.",
            "cve_references": ["CVE-XXXX-XXXX", ...],
            "confidence_level": "High/Medium/Low",
            "attack_vector": "Network/Adjacent/Local/Physical",
            "impact_analysis": "Specific impact analysis for this {service_type} vulnerability",
            "false_positive_reason": "string (only if is_false_positive is true - explain why this is a false positive)"
        }}

        IMPORTANT: 
        - Mark as false positive if the description indicates scanner errors, timeouts, or incomplete execution
        - Be conservative - only mark as validated if you're confident it's a real vulnerability
        - For scanner errors, set risk level to 'Informational' and is_false_positive to true
        """
        
        # Get service-specific context
        service_context = self._get_service_context(vulnerability.get('service', ''))
        
        return prompt_template.format(
            client_name=client_info['client_name'],
            target_ip=client_info['target_ip'],
            service_type=vulnerability.get('service', 'Unknown'),
            port=vulnerability.get('port', 'Unknown'),
            protocol=vulnerability.get('protocol', 'Unknown'),
            vuln_name=vulnerability.get('vulnerability_name', 'Unknown'),
            vuln_description=vulnerability.get('description', 'No description'),
            current_risk=vulnerability.get('risk_level', 'Unknown'),
            service_context=service_context
        )
    
    def _get_service_context(self, service_type):
        """Provide service-specific context to guide the AI analysis"""
        context_templates = {
            'ssh': """
            SSH (Secure Shell) Service Context:
            - Used for secure remote access and file transfers
            - Common security concerns: weak authentication, outdated versions, configuration issues
            - Key aspects: encryption strength, authentication methods, user access controls
            - Focus on: key exchange algorithms, authentication methods, protocol version, user enumeration
            """,
            'web': """
            Web Service Context:
            - HTTP/HTTPS services serving web applications
            - Common security concerns: injection flaws, XSS, broken authentication, security headers
            - Key aspects: HTTP methods, security headers, SSL/TLS configuration, application logic
            - Focus on: HSTS, CSP, X-Frame-Options, authentication mechanisms, input validation
            - Scanner errors often occur with custom applications or misconfigured services
            """,
            'ftp': """
            FTP Service Context:
            - File Transfer Protocol for file exchanges
            - Common security concerns: clear-text credentials, anonymous access, directory traversal
            - Key aspects: authentication, encryption, directory permissions, anonymous access
            - Focus on: anonymous login, encryption support, directory listing, permission issues
            """
        }
        
        return context_templates.get(service_type.lower(), 
            "General network service. Focus on authentication, encryption, and configuration security.")