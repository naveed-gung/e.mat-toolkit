"""
ETHICAL Malware Analysis Toolkit (E-MAT)
Configuration and Preferences Manager

Manages user preferences including:
- Preferred component (CLI/Desktop/Server)
- Default analysis mode
- Output format preferences
- API keys for optional external services
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from enum import Enum


class Component(Enum):
    """Available E-MAT components"""
    CLI = "cli"
    DESKTOP = "desktop"
    SERVER = "server"


class AnalysisMode(Enum):
    """Analysis modes"""
    STATIC_ONLY = "static_only"
    SANDBOX_ENABLED = "sandbox_enabled"


class OutputFormat(Enum):
    """Output formats"""
    JSON = "json"
    TABLE = "table"
    HTML = "html"
    PDF = "pdf"


class PreferencesManager:
    """Manages user preferences for E-MAT"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".emat"
        self.config_file = self.config_dir / "config.json"
        self.preferences = self._load_preferences()
    
    def _get_default_preferences(self) -> Dict[str, Any]:
        """Get default preferences"""
        return {
            "version": "1.0.0",
            "first_run": True,
            "preferred_component": None,
            "default_analysis_mode": AnalysisMode.STATIC_ONLY.value,
            "default_output_format": OutputFormat.TABLE.value,
            "docker_available": False,
            "api_keys": {
                "virustotal": None,
                "abuseipdb": None
            },
            "safety": {
                "require_explicit_sandbox_flag": True,
                "auto_cleanup_containers": True,
                "max_file_size_mb": 100,
                "network_isolation": True
            },
            "ui": {
                "show_ethical_disclaimer": True,
                "color_output": True
            }
        }
    
    def _load_preferences(self) -> Dict[str, Any]:
        """Load preferences from config file"""
        if not self.config_file.exists():
            return self._get_default_preferences()
        
        try:
            with open(self.config_file, 'r') as f:
                prefs = json.load(f)
                # Merge with defaults to ensure all keys exist
                defaults = self._get_default_preferences()
                defaults.update(prefs)
                return defaults
        except Exception as e:
            print(f"Warning: Could not load preferences: {e}")
            return self._get_default_preferences()
    
    def save_preferences(self) -> bool:
        """Save preferences to config file"""
        try:
            # Create config directory if it doesn't exist
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.preferences, f, indent=2)
            return True
        except Exception as e:
            print(f"Error: Could not save preferences: {e}")
            return False
    
    def is_first_run(self) -> bool:
        """Check if this is the first run"""
        return self.preferences.get("first_run", True)
    
    def mark_first_run_complete(self):
        """Mark first run as complete"""
        self.preferences["first_run"] = False
        self.save_preferences()
    
    def get_preferred_component(self) -> Optional[Component]:
        """Get the user's preferred component"""
        comp = self.preferences.get("preferred_component")
        if comp:
            try:
                return Component(comp)
            except ValueError:
                return None
        return None
    
    def set_preferred_component(self, component: Component):
        """Set the user's preferred component"""
        self.preferences["preferred_component"] = component.value
        self.save_preferences()
    
    def get_analysis_mode(self) -> AnalysisMode:
        """Get default analysis mode"""
        mode = self.preferences.get("default_analysis_mode", AnalysisMode.STATIC_ONLY.value)
        return AnalysisMode(mode)
    
    def set_analysis_mode(self, mode: AnalysisMode):
        """Set default analysis mode"""
        self.preferences["default_analysis_mode"] = mode.value
        self.save_preferences()
    
    def get_output_format(self) -> OutputFormat:
        """Get default output format"""
        fmt = self.preferences.get("default_output_format", OutputFormat.TABLE.value)
        return OutputFormat(fmt)
    
    def set_output_format(self, format: OutputFormat):
        """Set default output format"""
        self.preferences["default_output_format"] = format.value
        self.save_preferences()
    
    def is_docker_available(self) -> bool:
        """Check if Docker is available"""
        return self.preferences.get("docker_available", False)
    
    def set_docker_available(self, available: bool):
        """Set Docker availability"""
        self.preferences["docker_available"] = available
        self.save_preferences()
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for external service"""
        return self.preferences.get("api_keys", {}).get(service)
    
    def set_api_key(self, service: str, key: str):
        """Set API key for external service"""
        if "api_keys" not in self.preferences:
            self.preferences["api_keys"] = {}
        self.preferences["api_keys"][service] = key
        self.save_preferences()
    
    def get_safety_setting(self, setting: str) -> Any:
        """Get a safety setting"""
        return self.preferences.get("safety", {}).get(setting)
    
    def get_ui_setting(self, setting: str) -> Any:
        """Get a UI setting"""
        return self.preferences.get("ui", {}).get(setting)
    
    def export_config(self, filepath: str):
        """Export configuration to a file"""
        with open(filepath, 'w') as f:
            json.dump(self.preferences, f, indent=2)
    
    def import_config(self, filepath: str):
        """Import configuration from a file"""
        with open(filepath, 'r') as f:
            self.preferences = json.load(f)
        self.save_preferences()
