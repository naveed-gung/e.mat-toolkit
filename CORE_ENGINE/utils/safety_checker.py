"""
ETHICAL Malware Analysis Toolkit (E-MAT)
Safety Checker Module

Validates that all operations are safe, legal, and ethical:
- Ensures dynamic analysis only runs with explicit flags
- Validates Docker isolation settings
- Checks file size limits
- Enforces ethical constraints
"""

import os
from pathlib import Path
from typing import Tuple, Optional
import warnings


class SafetyViolation(Exception):
    """Raised when a safety constraint is violated"""
    pass


class SafetyChecker:
    """Validates operations for safety and ethical compliance"""
    
    def __init__(self, max_file_size_mb: int = 100):
        self.max_file_size_mb = max_file_size_mb
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
    
    def check_file_safety(self, filepath: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a file is safe to analyze
        
        Args:
            filepath: Path to the file
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        path = Path(filepath)
        
        # Check if file exists
        if not path.exists():
            return (False, f"File not found: {filepath}")
        
        # Check if it's actually a file
        if not path.is_file():
            return (False, f"Not a file: {filepath}")
        
        # Check file size
        file_size = path.stat().st_size
        if file_size > self.max_file_size_bytes:
            size_mb = file_size / (1024 * 1024)
            return (False, f"File too large: {size_mb:.2f}MB (max: {self.max_file_size_mb}MB)")
        
        # Check if file is readable
        if not os.access(filepath, os.R_OK):
            return (False, f"File not readable: {filepath}")
        
        return (True, None)
    
    def check_sandbox_safety(self, explicit_flag: bool, docker_available: bool) -> Tuple[bool, Optional[str]]:
        """
        Check if sandbox execution is safe to proceed
        
        Args:
            explicit_flag: Whether user provided explicit --safe-sandbox flag
            docker_available: Whether Docker is available
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        if not explicit_flag:
            return (False, 
                   "Dynamic analysis requires explicit consent. Use --safe-sandbox flag.\n"
                   "This will execute the file in an isolated Docker container.")
        
        if not docker_available:
            return (False,
                   "Docker is not available. Dynamic analysis requires Docker for safe isolation.\n"
                   "Install Docker and ensure it's running.")
        
        return (True, None)
    
    def validate_docker_config(self, network_mode: str = "none") -> Tuple[bool, Optional[str]]:
        """
        Validate Docker container configuration for safety
        
        Args:
            network_mode: Docker network mode
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        # Ensure network isolation
        if network_mode != "none":
            return (False,
                   f"SAFETY VIOLATION: Network mode must be 'none' for isolation, got '{network_mode}'")
        
        return (True, None)
    
    def check_yara_rules_safety(self, rules_path: str) -> Tuple[bool, Optional[str]]:
        """
        Check if YARA rules are from a safe source
        
        Args:
            rules_path: Path to YARA rules
            
        Returns:
            Tuple of (is_safe, warning_message)
        """
        path = Path(rules_path)
        
        if not path.exists():
            return (False, f"YARA rules not found: {rules_path}")
        
        # Check if rules are from the default safe directory
        default_rules = Path(__file__).parent.parent.parent / "DATA" / "yara_rules"
        
        if not str(path.absolute()).startswith(str(default_rules.absolute())):
            warning = (
                "WARNING: Using custom YARA rules from outside the default directory.\n"
                "Ensure these rules are from a trusted source and for educational purposes only."
            )
            return (True, warning)
        
        return (True, None)
    
    def display_ethical_warning(self, operation: str):
        """
        Display ethical warning before potentially risky operations
        
        Args:
            operation: Description of the operation
        """
        warning_msg = f"""
╔═══════════════════════════════════════════════════════════════╗
║                     ETHICAL WARNING                           ║
╚═══════════════════════════════════════════════════════════════╝

You are about to: {operation}

REMINDER:
  • This tool is for EDUCATIONAL and AUTHORIZED research only
  • Ensure you have legal permission to analyze this file
  • Do not use findings for malicious purposes
  • Report discovered threats through proper channels

By proceeding, you confirm this use is ethical and legal.
"""
        print(warning_msg)
    
    def validate_api_key_usage(self, service: str, api_key: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Validate external API key usage
        
        Args:
            service: Name of the external service
            api_key: API key (if provided)
            
        Returns:
            Tuple of (is_safe, warning_message)
        """
        if not api_key:
            return (False, f"No API key provided for {service}")
        
        warning = (
            f"WARNING: You are about to submit data to {service}.\n"
            f"This will share file hashes/information with an external service.\n"
            f"Ensure you have permission to share this data and comply with privacy policies."
        )
        
        return (True, warning)
    
    def check_output_directory(self, output_path: str) -> Tuple[bool, Optional[str]]:
        """
        Check if output directory is safe to write to
        
        Args:
            output_path: Path to output directory
            
        Returns:
            Tuple of (is_safe, error_message)
        """
        path = Path(output_path)
        
        # Check if we can write to the directory
        parent = path.parent if path.is_file() else path
        
        if not parent.exists():
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                return (False, f"Cannot create output directory: {e}")
        
        if not os.access(parent, os.W_OK):
            return (False, f"Output directory not writable: {parent}")
        
        return (True, None)
    
    def enforce_rate_limit(self, operation: str, max_per_hour: int = 100) -> Tuple[bool, Optional[str]]:
        """
        Enforce rate limiting for operations
        
        Args:
            operation: Type of operation
            max_per_hour: Maximum operations per hour
            
        Returns:
            Tuple of (is_allowed, error_message)
        """
        # This is a placeholder - full implementation would track operations
        # For now, just return allowed
        return (True, None)


# Global safety checker instance
_safety_checker = SafetyChecker()


def get_safety_checker() -> SafetyChecker:
    """Get the global safety checker instance"""
    return _safety_checker


if __name__ == "__main__":
    # Test safety checker
    checker = SafetyChecker()
    
    print("Testing Safety Checker...")
    print("="*60)
    
    # Test file safety
    is_safe, msg = checker.check_file_safety(__file__)
    print(f"File safety check: {is_safe}")
    if msg:
        print(f"  Message: {msg}")
    
    # Test sandbox safety
    is_safe, msg = checker.check_sandbox_safety(False, True)
    print(f"\nSandbox safety (no flag): {is_safe}")
    if msg:
        print(f"  Message: {msg}")
    
    is_safe, msg = checker.check_sandbox_safety(True, True)
    print(f"\nSandbox safety (with flag): {is_safe}")
    
    # Test Docker config
    is_safe, msg = checker.validate_docker_config("none")
    print(f"\nDocker config (isolated): {is_safe}")
    
    is_safe, msg = checker.validate_docker_config("bridge")
    print(f"Docker config (networked): {is_safe}")
    if msg:
        print(f"  Message: {msg}")
    
    print("="*60)
