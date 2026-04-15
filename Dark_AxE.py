import re
import os
import requests
from typing import Optional, Dict, Any
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Data class for validation results"""
    is_valid: bool
    message: str
    data: Optional[Dict] = None

class DarkWebScanner:
    """Scanner for dark web exposure using OSINT and breach intelligence."""
    
    def __init__(
        self,
        api_key: Optional[str] = "dfma_193e7cda6c25b54a3fd3252bed3c7993e2b867c62bdb49834591670dfbd8f9ff",
        base_url: str = "https://deepfind.me/api",
        timeout: int = 10
    ):
        """
        Initialize the scanner.
        
        Args:
            api_key: API key for DeepFind.me. Defaults to DARK_AXE_API_KEY env var.
            base_url: Base URL for API calls.
            timeout: Request timeout in seconds.
        """
        self.api_key = api_key or os.getenv("DARK_AXE_API_KEY")
        if not self.api_key:
            raise ValueError("API key required. Set DARK_AXE_API_KEY env var or pass directly.")
        
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "X-DFME-API-KEY": self.api_key,
            "User-Agent": "DarkWebScanner/1.0"
        })
    
    def _make_request(self, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Internal method to handle API requests with error handling."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout,
                **kwargs
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            print(f"Request to {endpoint} timed out after {self.timeout}s")
            return None
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error for {endpoint}: {e}")
            if response.status_code == 401:
                print("Invalid API key")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Request failed for {endpoint}: {e}")
            return None
        except ValueError as e:
            print(f"Invalid JSON response from {endpoint}: {e}")
            return None
    
    def validate_email_format(self, email: str) -> ValidationResult:
        """Validate email format using regex."""
        if not email:
            return ValidationResult(False, "Email cannot be empty")
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        is_valid = re.fullmatch(pattern, email) is not None
        
        return ValidationResult(
            is_valid=is_valid,
            message="Valid email format" if is_valid else "Invalid email format",
            data={"email": email}
        )
    
    def check_email_existence(self, email: str) -> ValidationResult:
        """Check if an email address exists."""
        # First validate format
        format_check = self.validate_email_format(email)
        if not format_check.is_valid:
            return format_check
        
        # Make API call
        endpoint = f"exists/{email}"
        result = self._make_request(endpoint)
        
        if result is None:
            return ValidationResult(
                False,
                "Failed to check email existence",
                {"email": email}
            )
        
        return ValidationResult(
            is_valid=True,
            message="Email existence check completed",
            data=result
        )
    
    def full_email_scan(self, email: str) -> Dict[str, ValidationResult]:
        """Run all available checks on an email."""
        results = {}
        
        # Format validation
        results["format"] = self.validate_email_format(email)
        
        # Only continue if format is valid
        if results["format"].is_valid:
            results["existence"] = self.check_email_existence(email)
            results["disposability"] = self.check_email_disposability(email)
            results["breaches"] = self.check_email_breaches(email)
        
        return results
    
    def check_email_disposability(self, email: str) -> ValidationResult:
        """Check if email is from a disposable provider."""
        endpoint = f"disposable-email/check/{email}"
        result = self._make_request(endpoint)
        
        if result is None:
            return ValidationResult(False, "Failed to check disposability")
        
        return ValidationResult(
            is_valid=True,
            message="Disposability check completed",
            data=result
        )
    
    def check_email_breaches(self, email: str) -> ValidationResult:
        """Check if email appears in known data breaches."""
        # Implementation depends on available API endpoint
        pass


# Usage example
if __name__ == "__main__":
    # Load API key from environment variable
    # export DARK_AXE_API_KEY="your_key_here"
    
    scanner = DarkWebScanner()
    
    # Single check
    result = scanner.check_email_existence("anomalyylamnoa@gmail.com")
    print(f"Exists: {result.data.get('exists') if result.data else 'Unknown'}")
    
    # Full scan
    email = input("Enter email to scan: ")
    results = scanner.full_email_scan(email)
    
    for check_name, result in results.items():
        print(f"{check_name}: {result.message}")

