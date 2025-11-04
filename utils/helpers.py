"""
Enhanced Helper functions and utilities
"""

import html
import socket
import getpass
from typing import Callable, Any

def risk_assessor(script_name: str, output: str) -> str:
    """Assess risk level based on script output with enhanced logic"""
    output_lower = output.lower()
    
    critical_indicators = ['critical', 'vulnerable', 'exploit', 'cve', 'remote code execution', 'rce', 'privilege escalation']
    warning_indicators = ['warning', 'weak', 'misconfig', 'information disclosure', 'xss', 'csrf']
    info_indicators = ['info', 'information', 'disclosure', 'enumerat']
    
    if any(indicator in output_lower for indicator in critical_indicators):
        return 'High'
    elif any(indicator in output_lower for indicator in warning_indicators):
        return 'Medium'
    elif any(indicator in output_lower for indicator in info_indicators):
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
    """
    Get user input with validation and retry logic
    
    Args:
        prompt: The input prompt to display
        validation_func: Function to validate input
        max_attempts: Maximum number of input attempts
        error_message: Error message to display on validation failure
        is_password: Whether to hide input (for passwords/API keys)
    
    Returns:
        Validated user input
    """
    for attempt in range(max_attempts):
        try:
            if is_password:
                user_input = getpass.getpass(f"{prompt}: ")
            else:
                user_input = input(f"{prompt}: ").strip()
            
            # If no validation function, return input as is
            if validation_func is None:
                return user_input
                
            # Validate input
            if validation_func(user_input):
                return user_input
            else:
                print(f"  {error_message}")
                
        except KeyboardInterrupt:
            print("\n\nInput cancelled by user")
            raise
        except Exception as e:
            print(f"  Input error: {e}")
            
    # If max attempts reached
    raise ValueError(f"Failed to get valid input after {max_attempts} attempts")

def display_banner(title: str, width: int = 50):
    """Display a formatted banner"""
    print("\n" + "=" * width)
    print(f" {title}")
    print("=" * width)

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"

def safe_get(dictionary: dict, keys: list, default: Any = None) -> Any:
    """Safely get nested dictionary values"""
    current = dictionary
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current