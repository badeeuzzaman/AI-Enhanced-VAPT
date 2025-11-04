"""
Enhanced Information Gathering Module with API key validation
"""

import socket
import re
from datetime import datetime
from utils.helpers import validate_ip_address, get_user_input, display_banner
from utils.api_client import DeepSeekClient

class InformationGatherer:
    def __init__(self, config):
        self.config = config
        self.max_attempts = config.max_input_attempts
        
    def execute(self, assessment_data):
        """Execute information gathering phase"""
        display_banner("PHASE 1: INFORMATION GATHERING")
        
        try:
            client_info = self._interactive_information_gathering()
            if not client_info:
                return False
                
            assessment_data['client_info'] = client_info
            print("✅ Information gathering completed successfully")
            return True
            
        except KeyboardInterrupt:
            print("\n\n❌ Information gathering interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Unexpected error during information gathering: {e}")
            return False

    def _validate_api_key(self, api_key):
        """Validate that the API key is working"""
        print("🔑 Validating API key...")
        try:
            from utils.api_client import DeepSeekClient
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
        
    def _interactive_information_gathering(self):
        """Interactive information gathering with validation"""
        client_info = {}
        
        print("\n📋 Please provide the following information:")
        print("-" * 40)
        
        # Get client name
        client_info['client_name'] = get_user_input(
            prompt="Enter client name",
            validation_func=self._validate_client_name,
            max_attempts=self.max_attempts,
            error_message="Client name cannot be empty"
        )
        
        # Get target IP
        client_info['target_ip'] = get_user_input(
            prompt="Enter target IP address",
            validation_func=validate_ip_address,
            max_attempts=self.max_attempts,
            error_message="Invalid IP address format"
        )
        
        # Get API key with validation
        api_key_valid = False
        for attempt in range(self.max_attempts):
            client_info['deepseek_api_key'] = get_user_input(
                prompt="Enter DeepSeek API key",
                validation_func=self._validate_api_key_format,
                max_attempts=1,
                error_message="API key cannot be empty and must be at least 20 characters",
                is_password=True
            )
            
            # Validate API key functionality
            if self._validate_api_key(client_info['deepseek_api_key']):
                api_key_valid = True
                break
            else:
                print(f"❌ API key validation failed. Attempt {attempt + 1}/{self.max_attempts}")
                if attempt < self.max_attempts - 1:
                    print("Please check your API key and try again.")
                else:
                    print("Maximum attempts reached. Please check your API key and restart.")
                    return None
        
        if not api_key_valid:
            return None
        
        # Additional optional information
        print("\n📝 Optional Information (press Enter to skip):")
        client_info['target_description'] = input("Target description (optional): ").strip() or "Not specified"
        client_info['contact_email'] = self._get_optional_input("Contact email", self._validate_email)
        
        # Scan configuration
        print("\n⚙️  Scan Configuration (press Enter for defaults):")
        client_info['scan_ports'] = self._get_optional_input(
            "Port range to scan (e.g., 1-1000)", 
            self._validate_port_range,
            default="1-1000"
        ) or "1-1000"
        
        # Timestamp
        client_info['scan_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_info['scan_id'] = f"VAPT_{client_info['client_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Display summary
        self._display_summary(client_info)
        
        # Confirm before proceeding
        if not self._confirm_proceeding():
            return None
            
        return client_info
        
    def _validate_client_name(self, name):
        """Validate client name"""
        return bool(name and name.strip())
        
    def _validate_api_key_format(self, api_key):
        """Validate API key format (basic validation)"""
        return bool(api_key and len(api_key.strip()) >= 20)
        
    def _validate_email(self, email):
        """Validate email format (optional field)"""
        if not email:  # Empty is allowed for optional fields
            return True
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
        
    def _validate_port_range(self, port_range):
        """Validate port range format"""
        if not port_range:
            return True
        pattern = r'^\d+(-\d+)?$'
        return bool(re.match(pattern, port_range))
        
    def _get_optional_input(self, field_name, validation_func, default=""):
        """Get optional input with validation"""
        for attempt in range(self.max_attempts):
            value = input(f"{field_name} (optional): ").strip()
            if not value:
                return default
            if validation_func(value):
                return value
            print(f"  Invalid {field_name.lower()}, please try again or press Enter to use default")
        return default
        
    def _display_summary(self, client_info):
        """Display summary of gathered information"""
        print("\n" + "="*50)
        print("📊 INFORMATION SUMMARY")
        print("="*50)
        print(f"Client Name: {client_info['client_name']}")
        print(f"Target IP: {client_info['target_ip']}")
        print(f"Target Description: {client_info['target_description']}")
        print(f"Port Range: {client_info['scan_ports']}")
        print(f"Contact Email: {client_info['contact_email'] or 'Not provided'}")
        print(f"Scan ID: {client_info['scan_id']}")
        print(f"Scan Date: {client_info['scan_date']}")
        print("="*50)
        
    def _confirm_proceeding(self):
        """Confirm if user wants to proceed"""
        for attempt in range(self.max_attempts):
            response = input("\nProceed with the assessment? (yes/no): ").strip().lower()
            if response in ['yes', 'y', '']:
                return True
            elif response in ['no', 'n']:
                print("Assessment cancelled by user.")
                return False
            else:
                print("Please enter 'yes' or 'no'")
        return False