"""
Enhanced Configuration settings for VAPT Tool
"""

class VAPTConfig:
    def __init__(self):
        # API Configuration
        self.deepseek_api_url = "https://api.deepseek.com/v1/chat/completions"
        self.api_timeout = 300  # Increased to 300 seconds (5 minutes)
        self.max_retries = 3
        self.retry_delay = 5
        
        # Scanning Configuration
        self.nmap_arguments = '-sS -T4 -F'
        self.service_scan_scripts = {
            'web': '--script http-vuln*,http-enum,http-security-headers',
            'ssh': '--script ssh2-enum-algos,ssh-auth-methods',
            'ftp': '--script ftp-anon,ftp-bounce,ftp-vuln*',
            'smb': '--script smb-vuln*,smb-enum-shares',
            'database': '--script mysql-vuln*,pgsql-vuln*'
        }
        
        # Report Configuration
        self.report_template = 'html'
        self.risk_levels = {
            'high': '#e74c3c',
            'medium': '#f39c12', 
            'low': '#f1c40f',
            'informational': '#3498db'
        }
        
        # User Interaction Configuration
        self.max_input_attempts = 3
        self.default_scan_ports = '1-1000'

# Singleton instance
config = VAPTConfig()