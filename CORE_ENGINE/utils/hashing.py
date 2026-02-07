"""
ETHICAL Malware Analysis Toolkit (E-MAT)
File Hashing and Identification Utilities

Provides functions for:
- Calculating multiple hash types (MD5, SHA1, SHA256, SHA512, SSDEEP)
- Determining file type via magic bytes
- Calculating file entropy for packer detection
"""

import hashlib
import math
from pathlib import Path
from typing import Dict, Tuple
from collections import Counter


def calculate_hashes(filepath: str) -> Dict[str, str]:
    """
    Calculate multiple hashes for a file
    
    Args:
        filepath: Path to the file
        
    Returns:
        Dictionary with hash types as keys and hash values
    """
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }
    
    # Read file in chunks to handle large files
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            for hash_obj in hashes.values():
                hash_obj.update(chunk)
    
    result = {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
    
    # Try to calculate SSDEEP if available
    try:
        import ssdeep
        result['ssdeep'] = ssdeep.hash_from_file(filepath)
    except ImportError:
        result['ssdeep'] = 'Not available (install python-ssdeep)'
    except Exception as e:
        result['ssdeep'] = f'Error: {str(e)}'
    
    return result


def calculate_entropy(filepath: str) -> float:
    """
    Calculate Shannon entropy of a file
    High entropy (>7.0) may indicate compression or encryption
    
    Args:
        filepath: Path to the file
        
    Returns:
        Entropy value (0.0 to 8.0)
    """
    with open(filepath, 'rb') as f:
        data = f.read()
    
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = Counter(data)
    file_size = len(data)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / file_size
        entropy -= probability * math.log2(probability)
    
    return entropy


def get_file_type(filepath: str) -> Tuple[str, str]:
    """
    Determine file type using magic bytes
    
    Args:
        filepath: Path to the file
        
    Returns:
        Tuple of (mime_type, description)
    """
    try:
        import magic
        
        # Try to use python-magic
        try:
            mime = magic.Magic(mime=True)
            desc = magic.Magic()
            mime_type = mime.from_file(filepath)
            description = desc.from_file(filepath)
            return (mime_type, description)
        except AttributeError:
            # Fallback for different python-magic implementations
            mime_type = magic.from_file(filepath, mime=True)
            description = magic.from_file(filepath)
            return (mime_type, description)
    
    except ImportError:
        # Fallback: basic magic byte detection
        return _basic_file_type_detection(filepath)


def detect_file_type(filepath: str) -> Tuple[str, str]:
    """Alias for get_file_type for backward compatibility"""
    return get_file_type(filepath)


def _basic_file_type_detection(filepath: str) -> Tuple[str, str]:
    """
    Basic file type detection using magic bytes
    Fallback when python-magic is not available
    """
    magic_signatures = {
        b'MZ': ('application/x-dosexec', 'PE32 executable (Windows)'),
        b'\x7fELF': ('application/x-executable', 'ELF executable (Linux)'),
        b'%PDF': ('application/pdf', 'PDF document'),
        b'PK\x03\x04': ('application/zip', 'ZIP archive (or Office document)'),
        b'\xd0\xcf\x11\xe0': ('application/vnd.ms-office', 'Microsoft Office document'),
        b'#!/': ('text/x-script', 'Script file'),
    }
    
    with open(filepath, 'rb') as f:
        header = f.read(16)
    
    for signature, (mime, desc) in magic_signatures.items():
        if header.startswith(signature):
            return (mime, desc)
    
    # Check if it's text
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            f.read(512)
        return ('text/plain', 'Text file')
    except UnicodeDecodeError:
        return ('application/octet-stream', 'Binary data')


def get_file_info(filepath: str) -> Dict:
    """
    Get comprehensive file information
    
    Args:
        filepath: Path to the file
        
    Returns:
        Dictionary with file information
    """
    try:
        path = Path(filepath)
        
        if not path.exists():
            return {
                'filename': path.name,
                'filepath': str(filepath),
                'size': 0,
                'mime_type': 'error',
                'description': 'File not found',
                'hashes': {},
                'entropy': 0.0,
                'entropy_analysis': 'File not accessible'
            }
        
        mime_type, description = get_file_type(filepath)
        hashes = calculate_hashes(filepath)
        entropy = calculate_entropy(filepath)
        
        return {
            'filename': path.name,
            'filepath': str(path.absolute()),
            'size': path.stat().st_size,
            'mime_type': mime_type,
            'description': description,
            'hashes': hashes,
            'entropy': round(entropy, 4),
            'entropy_analysis': _analyze_entropy(entropy)
        }
    except Exception as e:
        return {
            'filename': Path(filepath).name if filepath else 'unknown',
            'filepath': str(filepath) if filepath else 'unknown',
            'size': 0,
            'mime_type': 'error',
            'description': f'Error: {str(e)}',
            'hashes': {},
            'entropy': 0.0,
            'entropy_analysis': 'Error'
        }


def _analyze_entropy(entropy: float) -> str:
    """Provide educational analysis of entropy value"""
    if entropy < 1.0:
        return "Very low (likely empty or highly repetitive data)"
    elif entropy < 4.0:
        return "Low (text or structured data)"
    elif entropy < 6.0:
        return "Medium (mixed content)"
    elif entropy < 7.0:
        return "High (compressed or varied data)"
    else:
        return "Very high (likely packed, encrypted, or compressed)"


if __name__ == "__main__":
    # Test with this file
    import sys
    if len(sys.argv) > 1:
        info = get_file_info(sys.argv[1])
        print("\nFile Information:")
        print("="*60)
        for key, value in info.items():
            if key == 'hashes':
                print(f"\n{key.upper()}:")
                for hash_type, hash_value in value.items():
                    print(f"  {hash_type.upper()}: {hash_value}")
            else:
                print(f"{key}: {value}")
        print("="*60)
