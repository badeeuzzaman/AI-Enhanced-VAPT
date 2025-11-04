"""
Enhanced Report Generation Module with cleaned vulnerability data and better analysis
"""

import html
import json
from datetime import datetime
from utils.api_client import DeepSeekClient
from utils.helpers import sanitize_html, display_banner

class ReportGenerator:
    def __init__(self, config):
        self.config = config
        self.ai_client = DeepSeekClient(config)
        
    def execute(self, assessment_data):
        """Execute report generation phase with enhanced error handling"""
        display_banner("PHASE 5: REPORT GENERATION")
        
        print("📊 Generating comprehensive HTML report...")
        
        try:
            # Clean vulnerability data before processing
            cleaned_vulnerabilities = self._clean_vulnerability_data(assessment_data['vulnerability_data'])
            assessment_data['vulnerability_data'] = cleaned_vulnerabilities
            
            # Set API key
            api_key = assessment_data['client_info'].get('deepseek_api_key')
            ai_enhancement = {}
            
            if api_key:
                self.ai_client.set_api_key(api_key)
                # Get AI-enhanced recommendations
                ai_enhancement = self._get_ai_enhancements(assessment_data)
            else:
                print("  ⚠️  No API key found for AI enhancements")
            
            # Generate report (with or without AI enhancements)
            report_file = self._generate_html_report(assessment_data, ai_enhancement)
            
            assessment_data['client_info']['report_file'] = report_file
            assessment_data['report_data'] = {
                'generated_time': datetime.now().isoformat(),
                'ai_enhanced': bool(ai_enhancement)
            }
            
            print("✅ Comprehensive report generated successfully")
            return True
            
        except Exception as e:
            print(f"❌ Error during report generation: {e}")
            # Try to generate basic report as fallback
            try:
                report_file = self._generate_html_report(assessment_data, {})
                assessment_data['client_info']['report_file'] = report_file
                print("✅ Basic report generated (AI enhancement failed)")
                return True
            except Exception as fallback_error:
                print(f"❌ Failed to generate any report: {fallback_error}")
                return False
            
    def _clean_vulnerability_data(self, vulnerabilities):
        """Clean and correct mismatched vulnerability data with enhanced false positive detection"""
        cleaned_vulnerabilities = []
        
        for vuln in vulnerabilities:
            cleaned_vuln = vuln.copy()
            
            # Enhanced false positive detection for scanner errors
            if self._is_scanner_error_vulnerability(cleaned_vuln):
                cleaned_vuln['is_false_positive'] = True
                if not cleaned_vuln.get('false_positive_reason'):
                    cleaned_vuln['false_positive_reason'] = "Scanner execution error or incomplete assessment"
                cleaned_vuln['validated_risk_level'] = 'Informational'
            
            # Fix SSH authentication methods analysis
            if 'ssh' in vuln.get('service', '').lower() and 'auth' in vuln.get('vulnerability_name', '').lower():
                if 'HSTS' in vuln.get('technical_analysis', '') or 'HTTPS' in vuln.get('technical_analysis', ''):
                    # Replace incorrect analysis with SSH-focused analysis
                    cleaned_vuln['technical_analysis'] = self._generate_ssh_auth_analysis(vuln)
                elif not vuln.get('technical_analysis') or 'generic' in vuln.get('technical_analysis', '').lower():
                    cleaned_vuln['technical_analysis'] = self._generate_ssh_auth_analysis(vuln)
            
            # Fix web security headers analysis
            elif 'web' in vuln.get('service', '').lower() and 'security' in vuln.get('vulnerability_name', '').lower():
                if 'ssh' in vuln.get('technical_analysis', '').lower() or not vuln.get('technical_analysis'):
                    cleaned_vuln['technical_analysis'] = self._generate_web_security_analysis(vuln)
            
            # Fix CVE-specific false positives (like Drupal CVE on non-Drupal systems)
            cleaned_vuln = self._detect_cve_false_positives(cleaned_vuln)
            
            # Ensure risk level is appropriate for the service
            cleaned_vuln = self._adjust_risk_levels(cleaned_vuln)
            
            cleaned_vulnerabilities.append(cleaned_vuln)
        
        return cleaned_vulnerabilities
    
    def _is_scanner_error_vulnerability(self, vulnerability):
        """Detect if this vulnerability is actually a scanner error"""
        description = vulnerability.get('description', '').lower()
        vuln_name = vulnerability.get('vulnerability_name', '').lower()
        
        # Scanner error indicators
        error_indicators = [
            'error: script execution failed',
            'script execution failed',
            'error: nmap script failed',
            'could not run script',
            'script timed out',
            'connection refused',
            'no response',
            'host seems down',
            'use -d to debug',
            'execution failure'
        ]
        
        # Specific false positive patterns
        false_positive_patterns = [
            'cve2014' in vuln_name and 'error' in description,
            'cve-2014' in vuln_name and 'error' in description,
            'vulnerability detection script failed' in description
        ]
        
        # Check for any error indicators
        for indicator in error_indicators:
            if indicator in description:
                return True
        
        # Check for specific false positive patterns
        if any(false_positive_patterns):
            return True
            
        return False
    
    def _detect_cve_false_positives(self, vulnerability):
        """Detect CVE-specific false positives"""
        description = vulnerability.get('description', '').lower()
        vuln_name = vulnerability.get('vulnerability_name', '').lower()
        cve_references = vulnerability.get('cve_references', [])
        
        # Drupal CVE on non-Drupal systems
        if any('cve-2014-3704' in cve.lower() for cve in cve_references):
            if 'error' in description or 'drupal' not in description.lower():
                vulnerability['is_false_positive'] = True
                vulnerability['false_positive_reason'] = "CVE-2014-3704 (Drupalgeddon) scanner error - likely not a Drupal system"
                vulnerability['validated_risk_level'] = 'Informational'
        
        # Other CVE false positive patterns can be added here
        elif any('cve-2017-5638' in cve.lower() for cve in cve_references):  # Struts2
            if 'error' in description or 'apache struts' not in description.lower():
                vulnerability['is_false_positive'] = True
                vulnerability['false_positive_reason'] = "CVE-2017-5638 (Struts2) scanner error - likely not a Struts2 application"
                vulnerability['validated_risk_level'] = 'Informational'
        
        return vulnerability
    
    def _generate_ssh_auth_analysis(self, vulnerability):
        """Generate proper SSH authentication analysis"""
        description = vulnerability.get('description', '')
        script_name = vulnerability.get('script_name', '')
        
        if 'auth-methods' in script_name.lower():
            if 'publickey' in description and 'password' in description:
                return "SSH service allows both public key and password authentication. While this provides flexibility, it increases the attack surface. Password authentication is vulnerable to brute-force attacks. Consider disabling password authentication if public key authentication is sufficient for your use case."
            elif 'publickey' in description:
                return "SSH service configured for public key authentication only. This is generally considered more secure than password authentication as it's resistant to brute-force attacks. Ensure proper key management and consider implementing key rotation policies."
            elif 'password' in description:
                return "SSH service allows password authentication. This is vulnerable to brute-force attacks. Consider implementing fail2ban, strong password policies, or switching to public key authentication. Monitor for authentication attempts."
            else:
                return "SSH authentication methods have been enumerated. Review the allowed authentication methods and ensure they align with security best practices for your environment."
        
        elif 'enum-algos' in script_name.lower():
            return "SSH supported algorithms have been enumerated. This information can be used to identify weak encryption algorithms or outdated protocol support. Review and disable weak algorithms like CBC mode ciphers, MD5, or SHA1 hashes."
        
        return "SSH service security analysis: Review authentication methods, encryption algorithms, and protocol version to ensure compliance with security standards."
    
    def _generate_web_security_analysis(self, vulnerability):
        """Generate proper web security analysis"""
        script_name = vulnerability.get('script_name', '')
        description = vulnerability.get('description', '')
        
        if 'http-security' in script_name.lower():
            if 'hsts' in description.lower():
                return "Web server lacks HSTS (HTTP Strict Transport Security) header. This leaves the application vulnerable to SSL stripping attacks and protocol downgrade attacks. Implement HSTS to ensure browsers only connect via HTTPS and prevent certificate warnings from being bypassed."
            elif 'x-frame-options' in description.lower():
                return "Missing X-Frame-Options header. This could allow clickjacking attacks where the site is embedded in a malicious frame. Implement X-Frame-Options with 'DENY' or 'SAMEORIGIN' to prevent framing."
            elif 'content-security-policy' in description.lower():
                return "Missing Content-Security-Policy header. CSP helps prevent XSS attacks by restricting sources of executable scripts. Implement a strong CSP policy to mitigate XSS risks."
            else:
                return "Web security headers analysis: Review missing security headers that enhance application security. Consider implementing HSTS, X-Frame-Options, Content-Security-Policy, and X-Content-Type-Options headers."
        
        elif 'http-vuln' in script_name.lower():
            return f"Web application vulnerability detected: {vulnerability.get('vulnerability_name', 'Unknown')}. This may indicate potential security issues in the web application that could be exploited by attackers."
        
        return "Web service security analysis: Review application security configurations, input validation, authentication mechanisms, and security headers."
    
    def _generate_ftp_analysis(self, vulnerability):
        """Generate proper FTP service analysis"""
        script_name = vulnerability.get('script_name', '')
        description = vulnerability.get('description', '')
        
        if 'anon' in script_name.lower():
            return "FTP anonymous access is enabled. This allows anyone to access FTP resources without authentication, potentially exposing sensitive files. Disable anonymous access unless specifically required, and ensure proper directory permissions if enabled."
        
        elif 'bounce' in script_name.lower():
            return "FTP bounce attack vulnerability detected. This could allow attackers to use the FTP server as a proxy for port scanning or other network attacks. Consider updating the FTP server or implementing restrictions to prevent bounce attacks."
        
        return "FTP service analysis: Review authentication requirements, encryption support, user permissions, and ensure the service is properly configured for security."
    
    def _generate_smb_analysis(self, vulnerability):
        """Generate proper SMB service analysis"""
        script_name = vulnerability.get('script_name', '')
        
        if 'vuln' in script_name.lower():
            return f"SMB vulnerability detected: {vulnerability.get('vulnerability_name', 'Unknown')}. This could allow unauthorized access, information disclosure, or remote code execution. Update SMB implementation, disable vulnerable versions, or implement access controls."
        
        elif 'enum-shares' in script_name.lower():
            return "SMB shares enumeration successful. This reveals available network shares which could contain sensitive information. Review share permissions, implement access controls, and consider disabling unnecessary shares."
        
        return "SMB service analysis: Review SMB version, signing requirements, share permissions, and user access controls to ensure proper security configuration."
    
    def _adjust_risk_levels(self, vulnerability):
        """Adjust risk levels based on service and context"""
        service = vulnerability.get('service', '').lower()
        vuln_name = vulnerability.get('vulnerability_name', '').lower()
        current_risk = vulnerability.get('risk_level', 'Informational')
        
        # Downgrade informational findings
        if 'auth-methods' in vuln_name and current_risk == 'High':
            vulnerability['risk_level'] = 'Informational'
        elif 'enum-algos' in vuln_name and current_risk == 'High':
            vulnerability['risk_level'] = 'Informational'
        elif 'http-headers' in vuln_name and current_risk == 'High':
            vulnerability['risk_level'] = 'Low'
        
        # Upgrade critical service vulnerabilities
        if 'vuln' in vuln_name and 'critical' in vulnerability.get('description', '').lower():
            vulnerability['risk_level'] = 'High'
        elif 'anonymous' in vuln_name and 'ftp' in service:
            vulnerability['risk_level'] = 'Medium'
        elif 'bounce' in vuln_name and 'ftp' in service:
            vulnerability['risk_level'] = 'Medium'
        
        return vulnerability
            
    def _get_ai_enhancements(self, assessment_data):
        """Get AI-enhanced recommendations for the report with better error handling"""
        print("  Getting AI-enhanced recommendations...")
        
        try:
            prompt = self._create_recommendation_prompt(assessment_data)
            ai_response = self.ai_client.get_recommendations(prompt)
            
            if ai_response and isinstance(ai_response, dict):
                print("  ✅ AI recommendations received successfully")
                return ai_response
            else:
                print("  ⚠️  Invalid AI response format for recommendations")
                return {}
                
        except Exception as e:
            print(f"  ⚠️  AI enhancement failed: {e}")
            return {}
            
    def _create_recommendation_prompt(self, assessment_data):
        """Create AI prompt for specific recommendations"""
        client_info = assessment_data['client_info']
        vulnerabilities = assessment_data['vulnerability_data']
        penetration_plan = assessment_data.get('penetration_plan', [])
        
        prompt_template = """
        IMPORTANT: You MUST return ONLY valid JSON format. Do not include any other text.

        As a cybersecurity consultant, provide specific, actionable recommendations:

        CLIENT: {client_name}
        TARGET: {target_ip}
        
        FINDINGS:
        {vulnerabilities}
        
        PENETRATION TEST RESULTS:
        {penetration_plan}
        
        Provide tailored recommendations that are:
        - Specific to the findings
        - Actionable and technical
        - Include detailed remediation steps
        - Include immediate mitigations
        - Prioritized by risk
        
        Return ONLY JSON with this exact structure:
        {{
            "executive_summary": "string",
            "technical_summary": "string",
            "overall_risk_rating": "High/Medium/Low",
            "vulnerability_recommendations": [
                {{
                    "vulnerability_name": "string",
                    "specific_recommendation": "detailed technical recommendation",
                    "remediation_steps": ["step1", "step2", ...],
                    "immediate_mitigations": ["mitigation1", "mitigation2", ...],
                    "priority": "High/Medium/Low",
                    "estimated_effort": "Low/Medium/High",
                    "business_impact": "string"
                }}
            ],
            "strategic_recommendations": ["rec1", "rec2", ...]
        }}
        """
        
        return prompt_template.format(
            client_name=client_info['client_name'],
            target_ip=client_info['target_ip'],
            vulnerabilities=json.dumps(vulnerabilities, indent=2),
            penetration_plan=json.dumps(penetration_plan, indent=2)
        )
        
    def _generate_html_report(self, assessment_data, ai_enhancement):
        """Generate comprehensive HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        client_name = assessment_data['client_info']['client_name']
        filename = f"vapt_report_{client_name}_{timestamp}.html"
        
        html_content = self._create_report_template(assessment_data, ai_enhancement)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"  📄 Report saved as: {filename}")
        return filename
        
    def _create_report_template(self, assessment_data, ai_enhancement):
        """Create complete HTML report template with accurate statistics"""
        client_info = assessment_data['client_info']
        scan_results = assessment_data.get('scan_results', {})
        vulnerabilities = assessment_data.get('vulnerability_data', [])
        penetration_plan = assessment_data.get('penetration_plan', [])
        ai_analysis = assessment_data.get('ai_analysis', {})
        
        # Calculate accurate statistics from the cleaned vulnerability data
        total_findings = len(vulnerabilities)
        false_positives = sum(1 for vuln in vulnerabilities if vuln.get('is_false_positive', False))
        validated_findings = total_findings - false_positives
        
        # Get scanner errors count
        scanner_errors = sum(1 for vuln in vulnerabilities if vuln.get('is_scanner_error', False))
        
        # Get AI-enhanced content or use defaults
        executive_summary = ai_enhancement.get('executive_summary', 
            'Comprehensive security assessment completed using AI-enhanced analysis.')
        technical_summary = ai_enhancement.get('technical_summary', 
            'Detailed technical analysis performed with automated vulnerability assessment.')
        
        # Calculate overall risk based on validated vulnerabilities only
        overall_risk = self._calculate_overall_risk(vulnerabilities)
        
        # Use AI overall risk if available, otherwise calculate it
        overall_risk = ai_enhancement.get('overall_risk_rating', overall_risk)

        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPT Report - {sanitize_html(client_info.get('client_name', 'Unknown'))}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            line-height: 1.6; 
            color: #333;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{ 
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white; 
            padding: 30px; 
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header h2 {{
            margin: 10px 0 0 0;
            font-weight: 300;
            opacity: 0.9;
        }}
        .section {{ 
            margin: 30px 0; 
            padding: 25px;
            border-left: 5px solid #3498db; 
            background: #f8f9fa; 
            border-radius: 5px;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .vulnerability {{ 
            background: white; 
            margin: 20px 0; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
        }}
        .high-risk {{ border-left-color: #e74c3c; }}
        .medium-risk {{ border-left-color: #f39c12; }}
        .low-risk {{ border-left-color: #f1c40f; }}
        .info-risk {{ border-left-color: #3498db; }}
        .false-positive-risk {{ border-left-color: #95a5a6; background: #f8f9fa; opacity: 0.7; }}
        table {{
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #ecf0f1;
        }}
        th {{
            background-color: #34495e; 
            color: white; 
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .risk-high {{ color: #e74c3c; font-weight: bold; }}
        .risk-medium {{ color: #f39c12; font-weight: bold; }}
        .risk-low {{ color: #f1c40f; font-weight: bold; }}
        .risk-info {{ color: #3498db; font-weight: bold; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            margin: 2px;
        }}
        .badge-high {{ background: #e74c3c; color: white; }}
        .badge-medium {{ background: #f39c12; color: white; }}
        .badge-low {{ background: #f1c40f; color: white; }}
        .badge-info {{ background: #3498db; color: white; }}
        .badge-fp {{ background: #95a5a6; color: white; }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .code {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-align: right;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-high {{ color: #e74c3c; }}
        .stat-medium {{ color: #f39c12; }}
        .stat-low {{ color: #f1c40f; }}
        .stat-fp {{ color: #95a5a6; }}
        .false-positive {{
            background: #95a5a6;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-left: 10px;
        }}
        .scanner-error {{
            background: #e67e22;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-left: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Vulnerability Assessment & Penetration Test Report</h1>
            <h2>Client: {sanitize_html(client_info.get('client_name', 'Unknown'))}</h2>
            <div class="timestamp">
                Generated on: {sanitize_html(client_info.get('scan_date', 'Unknown'))}
            </div>
        </div>

        <div class="section">
            <h2>📋 Executive Summary</h2>
            <div class="summary-card">
                <p><strong>Overall Risk Rating:</strong> <span class="risk-{overall_risk.lower()}">{overall_risk}</span></p>
                <p>{executive_summary}</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div>Total Findings</div>
                    <div class="stat-number">{total_findings}</div>
                    <div>Vulnerabilities Identified</div>
                </div>
                <div class="stat-card">
                    <div>Validated Findings</div>
                    <div class="stat-number">{validated_findings}</div>
                    <div>Confirmed Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div>False Positives</div>
                    <div class="stat-number stat-fp">{false_positives}</div>
                    <div>Automatically Filtered</div>
                </div>
                <div class="stat-card">
                    <div>Scanner Errors</div>
                    <div class="stat-number">{scanner_errors}</div>
                    <div>Execution Issues</div>
                </div>
            </div>
        </div>

        <!-- Rest of the HTML template remains the same -->
        <div class="section">
            <h2>🎯 Assessment Overview</h2>
            <table>
                <tr><th>Client Name</th><td>{sanitize_html(client_info.get('client_name', 'Unknown'))}</td></tr>
                <tr><th>Target IP</th><td>{sanitize_html(client_info.get('target_ip', 'Unknown'))}</td></tr>
                <tr><th>Scan Date</th><td>{sanitize_html(client_info.get('scan_date', 'Unknown'))}</td></tr>
                <tr><th>Scan ID</th><td>{sanitize_html(client_info.get('scan_id', 'Unknown'))}</td></tr>
                <tr><th>Target Description</th><td>{sanitize_html(client_info.get('target_description', 'Not specified'))}</td></tr>
                <tr><th>Contact Email</th><td>{sanitize_html(client_info.get('contact_email', 'Not provided'))}</td></tr>
                <tr><th>AI Enhanced</th><td>{'Yes' if assessment_data.get('ai_analysis', {}) else 'No'}</td></tr>
                <tr><th>False Positives Filtered</th><td>{false_positives} out of {total_findings} findings</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>🔍 Open Ports Found</h2>
            {self._generate_ports_table(scan_results.get('open_ports', []))}
        </div>

        <div class="section">
            <h2>⚠️ Vulnerability Findings</h2>
            {self._generate_vulnerabilities_section(vulnerabilities) if vulnerabilities else '<p>No vulnerabilities found.</p>'}
        </div>

        <div class="section">
            <h2>🎯 Penetration Test Plan</h2>
            {self._generate_penetration_section(penetration_plan) if penetration_plan else '<p>No penetration test plan generated.</p>'}
        </div>

        <div class="section">
            <h2>💡 Recommendations</h2>
            {self._generate_recommendations_section(ai_enhancement)}
        </div>

        <div class="section">
            <h2>📝 Methodology</h2>
            <div class="summary-card">
                <p>This assessment was conducted using black-box testing methodology with AI-enhanced analysis through DeepSeek AI.</p>
                <p><strong>Testing Approach:</strong></p>
                <ul>
                    <li>Information Gathering</li>
                    <li>Port Scanning with Nmap</li>
                    <li>Vulnerability Assessment</li>
                    <li>AI-Powered Analysis & False Positive Filtering</li>
                    <li>Penetration Test Planning</li>
                    <li>Comprehensive Reporting</li>
                </ul>
                <p><strong>False Positive Detection:</strong> {false_positives} out of {total_findings} findings were automatically identified as scanner errors or false positives using AI analysis.</p>
            </div>
        </div>

        <div class="timestamp">
            Report generated by AI-Enhanced VAPT Tool on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>
        """
    
    def _calculate_overall_risk(self, vulnerabilities):
        """Calculate overall risk based on validated vulnerabilities only"""
        if not vulnerabilities:
            return 'Low'
            
        risk_scores = {'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}
        max_score = 0
        
        for vuln in vulnerabilities:
            # Only consider validated vulnerabilities (not false positives)
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
        
    def _generate_ports_table(self, open_ports):
        """Generate HTML table for open ports"""
        if not open_ports:
            return "<p>No open ports found.</p>"
            
        rows = "".join(
            f"<tr>"
            f"<td>{port_info.get('port', '')}</td>"
            f"<td>{port_info.get('protocol', '')}</td>"
            f"<td>{port_info.get('service', '')}</td>"
            f"<td>{port_info.get('state', '')}</td>"
            f"<td>{sanitize_html(port_info.get('product', ''))} {sanitize_html(port_info.get('version', ''))}</td>"
            f"</tr>"
            for port_info in open_ports
        )
        
        return f"""
        <table>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>State</th>
                <th>Version</th>
            </tr>
            {rows}
        </table>
        """
        
    def _generate_vulnerabilities_section(self, vulnerabilities):
        """Generate vulnerabilities section HTML"""
        return "".join(self._format_vulnerability_html(vuln) for vuln in vulnerabilities)
        
    def _format_vulnerability_html(self, vulnerability):
        """Format individual vulnerability for HTML"""
        risk_level = vulnerability.get('risk_level', 'Informational').lower()
        risk_class = f"risk-{risk_level}"
        badge_class = f"badge-{risk_level}"
        
        cve_refs = vulnerability.get('cve_references', [])
        cve_html = ", ".join(f'<span class="badge badge-info">{cve}</span>' for cve in cve_refs) if cve_refs else "None identified"
        
        # Check if this was marked as false positive
        is_false_positive = vulnerability.get('is_false_positive', False)
        false_positive_html = ""
        if is_false_positive:
            false_positive_html = f'<span class="false-positive">FALSE POSITIVE: {vulnerability.get("false_positive_reason", "Identified by AI analysis")}</span>'
        
        return f"""
        <div class="vulnerability {risk_level}-risk">
            <h3>🔍 {sanitize_html(vulnerability.get('vulnerability_name', 'Unknown Vulnerability'))} {false_positive_html}</h3>
            <p><strong>Risk Level:</strong> <span class="{risk_class}">{vulnerability.get('risk_level', 'Unknown')}</span></p>
            <p><strong>Service:</strong> {vulnerability.get('service', 'Unknown')} on port {vulnerability.get('port', 'Unknown')}</p>
            <p><strong>CVE References:</strong> {cve_html}</p>
            <p><strong>Description:</strong> {sanitize_html(str(vulnerability.get('description', 'No description available')))}</p>
            <p><strong>Technical Analysis:</strong> {sanitize_html(vulnerability.get('technical_analysis', 'No technical analysis available'))}</p>
            <p><strong>Confidence Level:</strong> {vulnerability.get('confidence_level', 'Unknown')}</p>
        </div>
        """
        
    def _generate_penetration_section(self, penetration_plan):
        """Generate penetration test plan section"""
        return "".join(self._format_penetration_html(plan) for plan in penetration_plan)
        
    def _format_penetration_html(self, plan):
        """Format individual penetration test plan"""
        risk_level = plan.get('risk_level', 'Medium').lower()
        risk_class = f"risk-{risk_level}"
        
        return f"""
        <div class="vulnerability">
            <h3>🎯 {sanitize_html(plan.get('vulnerability', 'Unknown Vulnerability'))}</h3>
            <p><strong>Risk Level:</strong> <span class="{risk_class}">{plan.get('risk_level', 'Medium')}</span></p>
            <p><strong>Exploitation Technique:</strong> {sanitize_html(plan.get('exploitation_technique', 'Not specified'))}</p>
            <p><strong>Tools Required:</strong> {', '.join(plan.get('tools_required', ['Not specified']))}</p>
            <p><strong>Test Commands:</strong></p>
            <div class="code">
                {"<br>".join(sanitize_html(cmd) for cmd in plan.get('test_commands', [])) or 'No specific commands provided'}
            </div>
            <p><strong>Proof of Concept Steps:</strong></p>
            <ol>
                {"".join(f"<li>{sanitize_html(step)}</li>" for step in plan.get('poc_steps', [])) or '<li>No specific steps provided</li>'}
            </ol>
            <p><strong>Expected Result:</strong> {sanitize_html(plan.get('expected_result', 'Not specified'))}</p>
        </div>
        """
        
    def _generate_recommendations_section(self, ai_enhancement):
        """Generate recommendations section"""
        recommendations = ai_enhancement.get('vulnerability_recommendations', [])
        
        if not recommendations:
            return """
            <div class="summary-card">
                <h3>General Security Recommendations</h3>
                <p>Based on the assessment findings, consider these general security improvements:</p>
                <ul>
                    <li>Implement regular security patching and updates for all services</li>
                    <li>Configure firewalls to restrict unnecessary services and ports</li>
                    <li>Enable security logging and monitoring for critical services</li>
                    <li>Conduct regular security assessments and penetration tests</li>
                    <li>Implement network segmentation to limit lateral movement</li>
                    <li>Use strong authentication mechanisms and disable weak protocols</li>
                    <li>Regularly review and update security configurations</li>
                </ul>
                <p><em>Note: For specific, tailored recommendations, ensure API key is properly configured for AI enhancements.</em></p>
            </div>
            """
            
        return "".join(self._format_recommendation_html(rec) for rec in recommendations)
        
    def _format_recommendation_html(self, recommendation):
        """Format individual recommendation"""
        priority = recommendation.get('priority', 'Medium')
        priority_class = f"risk-{priority.lower()}"
        effort = recommendation.get('estimated_effort', 'Medium')
        
        return f"""
        <div class="vulnerability">
            <h3>💡 {sanitize_html(recommendation.get('vulnerability_name', 'General Recommendation'))}</h3>
            <p><strong>Priority:</strong> <span class="{priority_class}">{priority}</span></p>
            <p><strong>Estimated Effort:</strong> {effort}</p>
            <p><strong>Business Impact:</strong> {sanitize_html(recommendation.get('business_impact', 'Not specified'))}</p>
            <p><strong>Recommendation:</strong> {sanitize_html(recommendation.get('specific_recommendation', 'No specific recommendation'))}</p>
            <p><strong>Remediation Steps:</strong></p>
            <ol>
                {"".join(f"<li>{sanitize_html(step)}</li>" for step in recommendation.get('remediation_steps', ['No specific steps provided']))}
            </ol>
            <p><strong>Immediate Mitigations:</strong></p>
            <ul>
                {"".join(f"<li>{sanitize_html(mitigation)}</li>" for mitigation in recommendation.get('immediate_mitigations', ['No immediate mitigations provided']))}
            </ul>
        </div>
        """