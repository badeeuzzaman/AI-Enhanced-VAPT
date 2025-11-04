#!/usr/bin/env python3
"""Create missing project files"""

import os

# File structure with content
files_structure = {
    'config/__init__.py': '',
    'modules/__init__.py': '', 
    'utils/__init__.py': '',
    'config/settings.py': '''"""
Configuration settings for VAPT Tool
"""

class VAPTConfig:
    def __init__(self):
        # API Configuration
        self.deepseek_api_url = "https://api.deepseek.com/v1/chat/completions"
        self.api_timeout = 300
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
        
        # User Interaction Configuration
        self.max_input_attempts = 3

# Singleton instance
config = VAPTConfig()
''',
    'utils/helpers.py': '''"""
Helper functions and utilities
"""

import html
import socket
import getpass
from typing import Callable, Any

def risk_assessor(script_name: str, output: str) -> str:
    """Assess risk level based on script output"""
    output_lower = output.lower()
    
    if any(word in output_lower for word in ['critical', 'vulnerable', 'exploit', 'cve']):
        return 'High'
    elif any(word in output_lower for word in ['warning', 'weak', 'misconfig']):
        return 'Medium'
    elif any(word in output_lower for word in ['info', 'information']):
        return 'Low'
    else:
        return 'Informational'

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def sanitize_html(text: str) -> str:
    """Sanitize text for HTML output"""
    return html.escape(str(text))

def get_user_input(prompt: str, 
                   validation_func: Callable[[str], bool] = None,
                   max_attempts: int = 3,
                   error_message: str = "Invalid input",
                   is_password: bool = False) -> str:
    """Get user input with validation"""
    for attempt in range(max_attempts):
        try:
            if is_password:
                user_input = getpass.getpass(f"{prompt}: ")
            else:
                user_input = input(f"{prompt}: ").strip()
            
            if validation_func is None or validation_func(user_input):
                return user_input
            else:
                print(f"  {error_message}")
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"  Input error: {e}")
    raise ValueError(f"Failed to get valid input after {max_attempts} attempts")

def display_banner(title: str, width: int = 50):
    """Display a formatted banner"""
    print("\\n" + "=" * width)
    print(f" {title}")
    print("=" * width)
'''
}

def create_files():
    """Create all missing files"""
    for file_path, content in files_structure.items():
        # Create directory if needed
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Create file if it doesn't exist
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"✅ Created {file_path}")
        else:
            print(f"✅ {file_path} already exists")

if __name__ == "__main__":
    create_files()
    print("\\n🎉 All required files are ready!")