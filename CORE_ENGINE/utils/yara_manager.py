"""
ETHICAL Malware Analysis Toolkit (E-MAT)
YARA Manager

Manages YARA rule scanning for educational purposes:
- Load default educational rules
- Support custom rule directories
- Output matching rules with educational context
"""

import os
from typing import Dict, List, Optional
from pathlib import Path


class YARAManager:
    """Manages YARA rule scanning"""
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize YARA manager
        
        Args:
            rules_path: Path to YARA rules directory or file
        """
        self.rules_path = rules_path
        self.default_rules_dir = Path(__file__).parent.parent.parent.parent / "DATA" / "yara_rules"
        
    def scan(self, filepath: str) -> Dict:
        """
        Scan a file with YARA rules
        
        Args:
            filepath: Path to file to scan
            
        Returns:
            Dictionary with scan results
        """
        try:
            import yara
            
            # Compile rules
            rules = self._compile_rules()
            
            if not rules:
                return {
                    'scanned': False,
                    'error': 'No YARA rules found or failed to compile'
                }
            
            # Scan file
            matches = rules.match(filepath)
            
            # Process matches
            results = []
            for match in matches:
                result = {
                    'rule': match.rule,
                    'namespace': match.namespace if hasattr(match, 'namespace') else 'default',
                    'tags': list(match.tags) if match.tags else [],
                    'meta': dict(match.meta) if match.meta else {},
                    'strings': self._format_strings(match.strings[:10]),  # Limit to first 10
                    'educational_note': self._get_educational_note(match)
                }
                results.append(result)
            
            return {
                'scanned': True,
                'rules_file': str(self.rules_path) if self.rules_path else 'default',
                'matches_count': len(results),
                'matches': results,
                'educational_summary': self._generate_summary(results)
            }
            
        except ImportError:
            return {
                'scanned': False,
                'error': 'yara-python library not installed. Install with: pip install yara-python'
            }
        except Exception as e:
            return {
                'scanned': False,
                'error': f'YARA scan failed: {str(e)}'
            }
    
    def _compile_rules(self):
        """Compile YARA rules from file or directory"""
        import yara
        
        rules_path = self.rules_path if self.rules_path else self.default_rules_dir
        
        if not rules_path or not Path(rules_path).exists():
            # Create default rule if no rules exist
            return self._create_default_rules()
        
        path = Path(rules_path)
        
        if path.is_file():
            # Single rule file
            return yara.compile(filepath=str(path))
        elif path.is_dir():
            # Directory of rules
            rule_files = {}
            for rule_file in path.glob('*.yar'):
                rule_files[rule_file.stem] = str(rule_file)
            
            for rule_file in path.glob('*.yara'):
                rule_files[rule_file.stem] = str(rule_file)
            
            if rule_files:
                return yara.compile(filepaths=rule_files)
        
        return None
    
    def _create_default_rules(self):
        """Create default educational YARA rules"""
        import yara
        
        # Default educational rules
        default_rules = """
        rule Suspicious_Strings
        {
            meta:
                description = "Detects common suspicious strings (educational)"
                author = "E-MAT"
                severity = "low"
            
            strings:
                $s1 = "cmd.exe" nocase
                $s2 = "powershell" nocase
                $s3 = "CreateRemoteThread" nocase
                $s4 = "VirtualAllocEx" nocase
                $s5 = "WriteProcessMemory" nocase
            
            condition:
                any of ($s*)
        }
        
        rule High_Entropy_Section
        {
            meta:
                description = "Detects high entropy (possible packing/encryption)"
                author = "E-MAT"
                severity = "medium"
            
            strings:
                $upx1 = "UPX0"
                $upx2 = "UPX1"
            
            condition:
                any of ($upx*)
        }
        
        rule Network_Indicators
        {
            meta:
                description = "Detects network-related strings (educational)"
                author = "E-MAT"
                severity = "low"
            
            strings:
                $url1 = "http://" nocase
                $url2 = "https://" nocase
                $net1 = "ws2_32.dll" nocase
                $net2 = "wininet.dll" nocase
            
            condition:
                any of them
        }
        """
        
        try:
            return yara.compile(source=default_rules)
        except:
            return None
    
    def _format_strings(self, strings: List) -> List[Dict]:
        """Format matched strings for output"""
        formatted = []
        for s in strings:
            formatted.append({
                'offset': hex(s[0]),
                'identifier': s[1],
                'data': s[2].decode('utf-8', errors='ignore')[:100]  # Truncate long strings
            })
        return formatted
    
    def _get_educational_note(self, match) -> str:
        """Get educational note for a match"""
        meta = dict(match.meta) if match.meta else {}
        
        description = meta.get('description', 'No description available')
        severity = meta.get('severity', 'unknown')
        
        note = f"{description} (Severity: {severity})"
        
        # Add context based on rule name
        if 'suspicious' in match.rule.lower():
            note += " - This indicates potentially suspicious behavior patterns"
        elif 'packer' in match.rule.lower() or 'entropy' in match.rule.lower():
            note += " - File may be packed or obfuscated"
        elif 'network' in match.rule.lower():
            note += " - File contains network-related functionality"
        
        return note
    
    def _generate_summary(self, results: List[Dict]) -> str:
        """Generate educational summary of YARA scan"""
        if not results:
            return "No YARA rules matched. File appears clean based on current ruleset."
        
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'unknown': 0}
        
        for result in results:
            severity = result['meta'].get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary = f"Matched {len(results)} YARA rule(s). "
        
        if severity_counts['high'] > 0:
            summary += f"HIGH severity: {severity_counts['high']}. "
        if severity_counts['medium'] > 0:
            summary += f"MEDIUM severity: {severity_counts['medium']}. "
        if severity_counts['low'] > 0:
            summary += f"LOW severity: {severity_counts['low']}. "
        
        summary += "Review matches for educational analysis."
        
        return summary


def create_default_yara_rules():
    """Create default YARA rules file"""
    rules_dir = Path(__file__).parent.parent.parent.parent / "DATA" / "yara_rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    
    default_rules_file = rules_dir / "default_educational.yar"
    
    if not default_rules_file.exists():
        rules_content = """/*
    E-MAT Default Educational YARA Rules
    
    These rules are designed for EDUCATIONAL purposes only.
    They detect common patterns found in both legitimate and malicious software.
    
    Author: Naveed Gung
    Purpose: Educational malware analysis
*/

rule Suspicious_API_Calls
{
    meta:
        description = "Detects potentially suspicious Windows API calls"
        author = "E-MAT / Naveed Gung"
        severity = "medium"
        educational_note = "These APIs can be used for legitimate purposes but are also common in malware"
    
    strings:
        $api1 = "CreateRemoteThread" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "VirtualAllocEx" nocase
        $api4 = "SetWindowsHookEx" nocase
        $api5 = "GetAsyncKeyState" nocase
    
    condition:
        2 of ($api*)
}

rule UPX_Packer
{
    meta:
        description = "Detects UPX packer signatures"
        author = "E-MAT / Naveed Gung"
        severity = "low"
        educational_note = "UPX is a legitimate packer but also used to obfuscate malware"
    
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    
    condition:
        any of them
}

rule Network_Activity
{
    meta:
        description = "Detects network-related strings and APIs"
        author = "E-MAT / Naveed Gung"
        severity = "low"
        educational_note = "Network activity is normal but worth investigating"
    
    strings:
        $url1 = "http://" nocase
        $url2 = "https://" nocase
        $dll1 = "ws2_32.dll" nocase
        $dll2 = "wininet.dll" nocase
        $api1 = "InternetOpen" nocase
        $api2 = "URLDownloadToFile" nocase
    
    condition:
        2 of them
}

rule Registry_Modification
{
    meta:
        description = "Detects registry-related strings"
        author = "E-MAT / Naveed Gung"
        severity = "medium"
        educational_note = "Registry modifications can indicate persistence mechanisms"
    
    strings:
        $reg1 = "HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $reg2 = "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $api1 = "RegSetValueEx" nocase
        $api2 = "RegCreateKeyEx" nocase
    
    condition:
        any of them
}

rule Command_Execution
{
    meta:
        description = "Detects command execution strings"
        author = "E-MAT / Naveed Gung"
        severity = "medium"
        educational_note = "Command execution can be legitimate or malicious depending on context"
    
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase
        $cmd3 = "wscript.exe" nocase
        $cmd4 = "cscript.exe" nocase
        $api1 = "WinExec" nocase
        $api2 = "ShellExecute" nocase
        $api3 = "CreateProcess" nocase
    
    condition:
        2 of them
}
"""
        
        with open(default_rules_file, 'w') as f:
            f.write(rules_content)
        
        print(f"Created default YARA rules: {default_rules_file}")


if __name__ == "__main__":
    # Create default rules
    create_default_yara_rules()
    
    # Test scanning
    import sys
    if len(sys.argv) > 1:
        manager = YARAManager()
        result = manager.scan(sys.argv[1])
        
        import json
        print(json.dumps(result, indent=2))
