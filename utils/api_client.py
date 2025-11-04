"""
Enhanced DeepSeek API Client with better JSON parsing, error handling, and service-specific methods
"""

import requests
import json
import time
import re
from requests.exceptions import Timeout, ConnectionError, RequestException

class DeepSeekClient:
    def __init__(self, config):
        self.config = config
        self.api_url = config.deepseek_api_url
        self.timeout = config.api_timeout
        self.max_retries = config.max_retries
        self.retry_delay = config.retry_delay
        self.api_key = None
        
    def set_api_key(self, api_key):
        """Set API key for authentication"""
        self.api_key = api_key.strip()
        
    def _call_api(self, prompt, system_message=None):
        """Make API call to DeepSeek with enhanced error handling and retries"""
        if not self.api_key:
            raise ValueError("API key not set. Call set_api_key() first.")
            
        if not system_message:
            system_message = """You are a cybersecurity expert. You MUST return ONLY valid JSON format. 
            Do not include any markdown, code blocks, or additional text outside the JSON structure."""
            
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        data = {
            'model': 'deepseek-chat',
            'messages': [
                {'role': 'system', 'content': system_message},
                {'role': 'user', 'content': prompt}
            ],
            'temperature': 0.3,
            'max_tokens': 4000
        }
        
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                print(f"  API Request (Attempt {attempt + 1}/{self.max_retries})...")
                
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=data,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    content = response_data['choices'][0]['message']['content']
                    
                    # Enhanced JSON parsing with fallback
                    parsed_response = self._parse_json_response(content)
                    return parsed_response
                        
                elif response.status_code == 401:
                    raise AuthenticationError("Invalid API key - please check your DeepSeek API key")
                elif response.status_code == 429:
                    raise RateLimitError("API rate limit exceeded - please wait before retrying")
                elif response.status_code >= 500:
                    raise ServerError(f"DeepSeek API server error: {response.status_code}")
                else:
                    raise APIError(f"API request failed with status {response.status_code}: {response.text}")
                    
            except Timeout:
                last_exception = Timeout(f"API request timed out after {self.timeout} seconds")
                print(f"  Timeout occurred, retrying in {self.retry_delay} seconds...")
                
            except ConnectionError:
                last_exception = ConnectionError("Network connection error - please check your internet connection")
                print(f"  Connection error, retrying in {self.retry_delay} seconds...")
                
            except RequestException as e:
                last_exception = APIError(f"Request exception: {str(e)}")
                print(f"  Request error, retrying in {self.retry_delay} seconds...")
                
            # Wait before retry
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay)
                
        # If all retries failed
        raise last_exception or APIError("Unknown error occurred during API call")
    
    def _parse_json_response(self, content):
        """Enhanced JSON parsing with multiple fallback strategies"""
        content = content.strip()
        
        # Strategy 1: Direct JSON parsing
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        
        # Strategy 2: Extract JSON from code blocks
        json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Strategy 3: Find JSON object/array pattern
        json_patterns = [
            r'\{.*\}',  # JSON object
            r'\[.*\]',  # JSON array
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue
        
        # Strategy 4: Last resort - try to fix common JSON issues
        try:
            # Remove potential markdown and extra spaces
            cleaned = re.sub(r'^```json\s*|\s*```$', '', content, flags=re.MULTILINE)
            cleaned = cleaned.strip()
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
            
        # Final fallback
        print("  ⚠️  API returned non-JSON response, using raw content")
        return {'raw_response': content}
    
    def analyze_vulnerabilities(self, prompt):
        """Analyze vulnerabilities with AI"""
        system_msg = """You are a senior vulnerability analyst. Provide accurate, technical vulnerability analysis.
        You MUST return ONLY valid JSON format. Do not include any other text, markdown, or code blocks."""
        return self._call_api(prompt, system_msg)
    
    def analyze_single_vulnerability(self, prompt):
        """Analyze a single vulnerability with service-specific context"""
        system_msg = """You are a senior vulnerability analyst specializing in network service security. 
        You MUST return ONLY valid JSON format. 
        Your analysis MUST be specific to the service type and vulnerability described.
        Focus on technical accuracy and relevance to the specific finding."""
        return self._call_api(prompt, system_msg)
        
    def create_penetration_plan(self, prompt):
        """Create penetration test plan with AI"""
        system_msg = """You are an experienced penetration tester. Provide safe, ethical exploitation techniques.
        You MUST return ONLY valid JSON format. Do not include any other text, markdown, or code blocks."""
        return self._call_api(prompt, system_msg)
    
    def create_service_specific_penetration_plan(self, prompt):
        """Create penetration test plan for specific service"""
        system_msg = """You are an experienced penetration tester specializing in network service exploitation.
        You MUST return ONLY valid JSON format.
        Provide specific, actionable exploitation techniques for the service type described."""
        return self._call_api(prompt, system_msg)
        
    def get_recommendations(self, prompt):
        """Get AI-enhanced recommendations"""
        system_msg = """You are a cybersecurity consultant. Provide specific, actionable security recommendations.
        You MUST return ONLY valid JSON format. Do not include any other text, markdown, or code blocks."""
        return self._call_api(prompt, system_msg)

# Custom Exception Classes
class APIError(Exception):
    """Base class for API errors"""
    pass

class AuthenticationError(APIError):
    """Authentication related errors"""
    pass

class RateLimitError(APIError):
    """Rate limiting errors"""
    pass

class ServerError(APIError):
    """Server-side errors"""
    pass