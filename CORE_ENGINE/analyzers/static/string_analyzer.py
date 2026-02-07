"""
ETHICAL Malware Analysis Toolkit (E-MAT)
String Analyzer

Extracts and categorizes strings from files:
- ASCII and Unicode strings
- URLs, IPs, file paths, registry keys
- Base64/hex encoded data detection
- Educational categorization
"""

import re
import string
from typing import Dict, List, Set
from pathlib import Path


class StringAnalyzer:
    """Extracts and analyzes strings from files"""
    
    def __init__(self, filepath: str, min_length: int = 4):
        self.filepath = filepath
        self.min_length = min_length
        
    def analyze(self) -> Dict:
        """
        Extract and categorize strings
        
        Returns:
            Dictionary with categorized strings
        """
        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()
            
            # Extract ASCII and Unicode strings
            ascii_strings = self._extract_ascii_strings(data)
            unicode_strings = self._extract_unicode_strings(data)
            
            # Combine and deduplicate
            all_strings = list(set(ascii_strings + unicode_strings))
            
            # Categorize strings
            categorized = self._categorize_strings(all_strings)
            
            result = {
                'total_count': len(all_strings),
                'ascii_count': len(ascii_strings),
                'unicode_count': len(unicode_strings),
                'categories': categorized,
                'statistics': self._generate_statistics(categorized),
                'educational_notes': self._generate_educational_notes(categorized)
            }
            
            return result
            
        except Exception as e:
            return {
                'error': f'String analysis failed: {str(e)}'
            }
    
    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        """Extract ASCII strings"""
        ascii_chars = bytes(string.printable, 'ascii')
        pattern = b'[' + re.escape(ascii_chars) + b']{' + str(self.min_length).encode() + b',}'
        
        strings = []
        for match in re.finditer(pattern, data):
            try:
                s = match.group().decode('ascii', errors='ignore')
                if len(s) >= self.min_length:
                    strings.append(s)
            except:
                pass
        
        return strings
    
    def _extract_unicode_strings(self, data: bytes) -> List[str]:
        """Extract Unicode (UTF-16LE) strings"""
        strings = []
        
        # Look for UTF-16LE encoded strings (common in Windows)
        i = 0
        while i < len(data) - 1:
            if data[i] != 0 and data[i+1] == 0:
                # Potential UTF-16LE string
                string_bytes = bytearray()
                j = i
                while j < len(data) - 1:
                    if data[j] == 0 and data[j+1] == 0:
                        break
                    if data[j+1] == 0:
                        string_bytes.append(data[j])
                        j += 2
                    else:
                        break
                
                if len(string_bytes) >= self.min_length:
                    try:
                        s = string_bytes.decode('ascii', errors='ignore')
                        if len(s) >= self.min_length and s.isprintable():
                            strings.append(s)
                    except:
                        pass
                
                i = j
            else:
                i += 1
        
        return strings
    
    def _categorize_strings(self, strings: List[str]) -> Dict:
        """Categorize strings by type"""
        categories = {
            'urls': [],
            'ips': [],
            'file_paths': [],
            'registry_keys': [],
            'email_addresses': [],
            'base64_candidates': [],
            'hex_candidates': [],
            'suspicious_keywords': [],
            'interesting': []
        }
        
        # Patterns
        url_pattern = re.compile(r'https?://[^\s]+', re.IGNORECASE)
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        file_path_pattern = re.compile(r'[A-Za-z]:\\[^<>:"|?*\n]+|/[a-zA-Z0-9/_.-]+')
        registry_pattern = re.compile(r'HKEY_[A-Z_]+\\[^\n]+', re.IGNORECASE)
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
        hex_pattern = re.compile(r'^[0-9A-Fa-f]{32,}$')
        
        # Suspicious keywords for educational purposes
        suspicious_keywords = [
            'password', 'passwd', 'pwd', 'admin', 'root', 'login',
            'cmd.exe', 'powershell', 'shell', 'execute', 'eval',
            'download', 'upload', 'http', 'ftp', 'smtp',
            'keylog', 'inject', 'exploit', 'payload', 'backdoor'
        ]
        
        for s in strings:
            # URLs
            if url_pattern.search(s):
                if len(categories['urls']) < 50:
                    categories['urls'].append(s)
            
            # IPs (educational note: using test ranges only)
            elif ip_pattern.search(s):
                if len(categories['ips']) < 50:
                    categories['ips'].append(s)
            
            # Email addresses
            elif email_pattern.search(s):
                if len(categories['email_addresses']) < 30:
                    categories['email_addresses'].append(s)
            
            # File paths
            elif file_path_pattern.search(s):
                if len(categories['file_paths']) < 50:
                    categories['file_paths'].append(s)
            
            # Registry keys
            elif registry_pattern.search(s):
                if len(categories['registry_keys']) < 30:
                    categories['registry_keys'].append(s)
            
            # Base64 candidates
            elif base64_pattern.match(s):
                if len(categories['base64_candidates']) < 20:
                    categories['base64_candidates'].append(s[:100])  # Truncate long strings
            
            # Hex candidates
            elif hex_pattern.match(s):
                if len(categories['hex_candidates']) < 20:
                    categories['hex_candidates'].append(s[:100])
            
            # Suspicious keywords
            elif any(keyword in s.lower() for keyword in suspicious_keywords):
                if len(categories['suspicious_keywords']) < 30:
                    categories['suspicious_keywords'].append(s)
            
            # Interesting strings (long, printable, not too common)
            elif len(s) > 20 and len(categories['interesting']) < 30:
                categories['interesting'].append(s[:100])
        
        return categories
    
    def _generate_statistics(self, categories: Dict) -> Dict:
        """Generate statistics about categorized strings"""
        return {
            'urls_found': len(categories['urls']),
            'ips_found': len(categories['ips']),
            'file_paths_found': len(categories['file_paths']),
            'registry_keys_found': len(categories['registry_keys']),
            'email_addresses_found': len(categories['email_addresses']),
            'base64_candidates': len(categories['base64_candidates']),
            'hex_candidates': len(categories['hex_candidates']),
            'suspicious_keywords_found': len(categories['suspicious_keywords'])
        }
    
    def _generate_educational_notes(self, categories: Dict) -> List[str]:
        """Generate educational notes about findings"""
        notes = []
        
        if categories['urls']:
            notes.append(f"Found {len(categories['urls'])} URLs - May indicate network communication")
        
        if categories['ips']:
            notes.append(f"Found {len(categories['ips'])} IP addresses - Potential C2 servers or remote hosts")
        
        if categories['registry_keys']:
            notes.append(f"Found {len(categories['registry_keys'])} registry keys - May indicate persistence mechanisms")
        
        if categories['base64_candidates']:
            notes.append(f"Found {len(categories['base64_candidates'])} potential Base64 strings - May hide encoded data")
        
        if categories['suspicious_keywords']:
            notes.append(f"Found {len(categories['suspicious_keywords'])} suspicious keywords - Warrants further investigation")
        
        if not any([categories['urls'], categories['ips'], categories['suspicious_keywords']]):
            notes.append("No obviously suspicious strings found - File may be benign or heavily obfuscated")
        
        return notes


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyzer = StringAnalyzer(sys.argv[1])
        result = analyzer.analyze()
        
        import json
        print(json.dumps(result, indent=2))
