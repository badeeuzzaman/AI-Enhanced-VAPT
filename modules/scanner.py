"""
Enhanced Vulnerability Scanning Module with better categorization and specific naming
"""

import nmap
import socket
from utils.helpers import risk_assessor

class VulnerabilityScanner:
    def __init__(self, config):
        self.config = config
        self.nm = nmap.PortScanner()
        
    def execute(self, assessment_data):
        """Execute vulnerability assessment phase"""
        print("\n" + "="*50)
        print("PHASE 2: VULNERABILITY ASSESSMENT")
        print("="*50)
        
        target_ip = assessment_data['client_info']['target_ip']
        
        # Perform port scanning
        port_scan_results = self._perform_port_scan(target_ip)
        if not port_scan_results:
            return False
            
        assessment_data['scan_results'] = port_scan_results
        
        # Perform vulnerability scanning
        if port_scan_results['open_ports']:
            vulnerabilities = self._perform_vulnerability_scan(
                port_scan_results['open_ports'], 
                target_ip
            )
            assessment_data['vulnerability_data'] = vulnerabilities
            print(f"✓ Vulnerability scanning completed. Found {len(vulnerabilities)} potential vulnerabilities")
        else:
            print("No open ports found for vulnerability scanning")
            
        return True
        
    def _perform_port_scan(self, target_ip):
        """Perform comprehensive port scanning"""
        print("Starting port scanning...")
        
        try:
            scan_result = self.nm.scan(
                hosts=target_ip, 
                arguments=self.config.nmap_arguments
            )
            
            open_ports = self._parse_open_ports(scan_result, target_ip)
            return {
                'port_scan': scan_result['scan'],
                'open_ports': open_ports
            }
            
        except Exception as e:
            print(f"✗ Error during port scanning: {e}")
            return None
            
    def _parse_open_ports(self, scan_result, target_ip):
        """Parse and extract open ports from scan results"""
        open_ports = []
        
        if target_ip in scan_result['scan']:
            for proto in scan_result['scan'][target_ip].all_protocols():
                ports = scan_result['scan'][target_ip][proto].keys()
                for port in ports:
                    port_info = scan_result['scan'][target_ip][proto][port]
                    if port_info['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'protocol': proto,
                            'service': port_info.get('name', 'unknown'),
                            'state': port_info['state'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        })
                        
        print(f"✓ Found {len(open_ports)} open ports")
        return open_ports
        
    def _perform_vulnerability_scan(self, open_ports, target_ip):
        """Perform vulnerability scanning based on open ports"""
        print("Starting vulnerability scanning...")
        vulnerabilities = []
        
        # Group by service type for efficient scanning
        service_map = self._categorize_services(open_ports)
        
        for service_type, ports in service_map.items():
            print(f"  Scanning {service_type} services...")
            for port_info in ports:
                service_vulns = self._scan_service_vulnerabilities(
                    service_type, port_info, target_ip
                )
                vulnerabilities.extend(service_vulns)
                
        return vulnerabilities
        
    def _categorize_services(self, open_ports):
        """Categorize open ports by service type"""
        service_map = {}
        
        for port_info in open_ports:
            service = port_info['service']
            
            if service in ['http', 'https', 'www', 'http-proxy', 'http-alt']:
                category = 'web'
            elif service in ['ssh']:
                category = 'ssh'
            elif service in ['ftp', 'ftps']:
                category = 'ftp'
            elif service in ['smb', 'netbios-ssn', 'microsoft-ds']:
                category = 'smb'
            elif service in ['mysql', 'postgresql', 'oracle', 'mongodb', 'redis']:
                category = 'database'
            elif service in ['telnet', 'rlogin', 'rsh']:
                category = 'remote-access'
            elif service in ['dns', 'domain']:
                category = 'dns'
            elif service in ['snmp']:
                category = 'snmp'
            else:
                category = 'general'
                
            if category not in service_map:
                service_map[category] = []
            service_map[category].append(port_info)
            
        return service_map
        
    def _scan_service_vulnerabilities(self, service_type, port_info, target_ip):
        """Scan specific service for vulnerabilities"""
        vulnerabilities = []
        
        try:
            if service_type in self.config.service_scan_scripts:
                script_args = self.config.service_scan_scripts[service_type]
                scan_result = self.nm.scan(
                    hosts=target_ip,
                    ports=str(port_info['port']),
                    arguments=script_args
                )
                
                vulns = self._parse_vulnerability_results(
                    scan_result, service_type, port_info
                )
                vulnerabilities.extend(vulns)
                
        except Exception as e:
            print(f"  Error scanning {service_type} on port {port_info['port']}: {e}")
            
        return vulnerabilities
        
    def _parse_vulnerability_results(self, scan_result, service_type, port_info):
        """Parse vulnerability scan results with better categorization and error detection"""
        vulnerabilities = []
        target_ip = list(scan_result['scan'].keys())[0] if scan_result['scan'] else None
        
        if target_ip and target_ip in scan_result['scan']:
            port_data = scan_result['scan'][target_ip]['tcp'].get(port_info['port'], {})
            
            if 'script' in port_data:
                for script_name, script_output in port_data['script'].items():
                    # Check if this is a scanner error before creating vulnerability
                    if self._is_scanner_error(script_output):
                        # Create an informational finding for scanner errors
                        vuln_name = f"Scanner Error: {script_name}"
                        risk_level = 'Informational'
                    else:
                        # Create more specific vulnerability names based on service and script
                        vuln_name = self._generate_specific_vulnerability_name(service_type, script_name, script_output)
                        risk_level = risk_assessor(script_name, script_output)
                    
                    vulnerability = {
                        'service': service_type,
                        'port': port_info['port'],
                        'protocol': port_info['protocol'],
                        'vulnerability_name': vuln_name,
                        'description': script_output,
                        'risk_level': risk_level,
                        'discovery_method': 'Nmap Script',
                        'service_info': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                        'script_name': script_name,
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'is_scanner_error': self._is_scanner_error(script_output)
                    }
                    vulnerabilities.append(vulnerability)
                    
        return vulnerabilities
    
    def _is_scanner_error(self, script_output):
        """Detect if script output indicates a scanner error rather than a real vulnerability"""
        error_indicators = [
            'ERROR: Script execution failed',
            'Script execution failed',
            'could not run script',
            'script timed out',
            'connection refused',
            'no response',
            'use -d to debug'
        ]
        
        script_output_lower = script_output.lower()
        for indicator in error_indicators:
            if indicator.lower() in script_output_lower:
                return True
        return False
    
    def _generate_specific_vulnerability_name(self, service_type, script_name, script_output):
        """Generate more specific vulnerability names based on context"""
        script_lower = script_name.lower()
        output_lower = script_output.lower()
        
        # SSH-specific naming
        if service_type == 'ssh':
            if 'auth-methods' in script_lower:
                return "SSH Authentication Methods Disclosure"
            elif 'enum-algos' in script_lower:
                return "SSH Algorithm Enumeration"
            elif 'vuln' in script_lower:
                return f"SSH {script_name} Vulnerability"
            elif '2-enum-algos' in script_lower:
                return "SSH2 Algorithm Support Disclosure"
        
        # Web-specific naming
        elif service_type == 'web':
            if 'http-vuln' in script_lower:
                # Extract specific vulnerability from script name
                vuln_type = script_name.replace('http-vuln-', '').replace('-', ' ').title()
                return f"Web Service {vuln_type} Vulnerability"
            elif 'http-enum' in script_lower:
                return "Web Directory/File Enumeration"
            elif 'http-security' in script_lower:
                if 'hsts' in output_lower:
                    return "Missing HSTS Security Header"
                elif 'x-frame-options' in output_lower:
                    return "Missing X-Frame-Options Header"
                elif 'content-security-policy' in output_lower:
                    return "Missing Content-Security-Policy Header"
                else:
                    return "Web Security Headers Misconfiguration"
            elif 'http-headers' in script_lower:
                return "HTTP Headers Information Disclosure"
            elif 'http-methods' in script_lower:
                return "HTTP Methods Enumeration"
        
        # FTP-specific naming
        elif service_type == 'ftp':
            if 'anon' in script_lower:
                return "FTP Anonymous Access Enabled"
            elif 'bounce' in script_lower:
                return "FTP Bounce Attack Vulnerability"
            elif 'vuln' in script_lower:
                return f"FTP {script_name} Vulnerability"
        
        # SMB-specific naming
        elif service_type == 'smb':
            if 'vuln' in script_lower:
                vuln_type = script_name.replace('smb-vuln-', '').replace('-', ' ').title()
                return f"SMB {vuln_type} Vulnerability"
            elif 'enum-shares' in script_lower:
                return "SMB Share Enumeration"
            elif 'enum-users' in script_lower:
                return "SMB User Enumeration"
            elif 'os-discovery' in script_lower:
                return "SMB OS Information Disclosure"
        
        # Database-specific naming
        elif service_type == 'database':
            if 'vuln' in script_lower:
                db_type = 'Database'
                if 'mysql' in script_lower:
                    db_type = 'MySQL'
                elif 'pgsql' in script_lower:
                    db_type = 'PostgreSQL'
                elif 'oracle' in script_lower:
                    db_type = 'Oracle'
                return f"{db_type} {script_name} Vulnerability"
            elif 'empty-password' in script_lower:
                return "Database Empty Password Vulnerability"
            elif 'brute' in script_lower:
                return "Database Weak Authentication"
        
        # DNS-specific naming
        elif service_type == 'dns':
            if 'zone-transfer' in script_lower:
                return "DNS Zone Transfer Vulnerability"
            elif 'enum' in script_lower:
                return "DNS Enumeration"
            elif 'vuln' in script_lower:
                return f"DNS {script_name} Vulnerability"
        
        # SNMP-specific naming
        elif service_type == 'snmp':
            if 'brute' in script_lower:
                return "SNMP Community String Brute Force"
            elif 'enum' in script_lower:
                return "SNMP Enumeration"
            elif 'vuln' in script_lower:
                return f"SNMP {script_name} Vulnerability"
        
        # Remote access services
        elif service_type == 'remote-access':
            if 'telnet' in script_lower:
                return "Telnet Service Information Disclosure"
            elif 'rlogin' in script_lower:
                return "Rlogin Service Vulnerability"
            elif 'rsh' in script_lower:
                return "RSH Service Vulnerability"
        
        # Default naming with service context
        return f"{service_type.upper()} {script_name.replace('-', ' ').title()}"