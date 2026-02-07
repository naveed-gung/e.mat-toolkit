"""
ETHICAL Malware Analysis Toolkit (E.MAT)
CLI Compare Command

Compare analysis results of two files.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from CLI_TOOL.commands.analyze import perform_static_analysis


def compare_files(file1: str, file2: str) -> bool:
    """
    Compare two files
    
    Args:
        file1: First file path
        file2: Second file path
        
    Returns:
        True if successful
    """
    print("\n" + "="*70)
    print("FILE COMPARISON")
    print("="*70 + "\n")
    
    try:
        # Analyze both files
        print(f"Analyzing {file1}...")
        result1 = perform_static_analysis(file1)
        
        print(f"Analyzing {file2}...")
        result2 = perform_static_analysis(file2)
        
        # Compare hashes
        print("\n" + "-"*70)
        print("HASH COMPARISON")
        print("-"*70)
        
        hashes1 = result1['file_info']['hashes']
        hashes2 = result2['file_info']['hashes']
        
        for hash_type in ['md5', 'sha1', 'sha256']:
            h1 = hashes1.get(hash_type, 'N/A')
            h2 = hashes2.get(hash_type, 'N/A')
            match = "✓ MATCH" if h1 == h2 else "✗ DIFFERENT"
            print(f"\n{hash_type.upper()}:")
            print(f"  File 1: {h1}")
            print(f"  File 2: {h2}")
            print(f"  {match}")
        
        # Compare sizes
        print("\n" + "-"*70)
        print("SIZE COMPARISON")
        print("-"*70)
        size1 = result1['file_info']['size']
        size2 = result2['file_info']['size']
        print(f"File 1: {size1:,} bytes")
        print(f"File 2: {size2:,} bytes")
        print(f"Difference: {abs(size1 - size2):,} bytes")
        
        # Compare entropy
        print("\n" + "-"*70)
        print("ENTROPY COMPARISON")
        print("-"*70)
        ent1 = result1['file_info']['entropy']
        ent2 = result2['file_info']['entropy']
        print(f"File 1: {ent1} - {result1['file_info']['entropy_analysis']}")
        print(f"File 2: {ent2} - {result2['file_info']['entropy_analysis']}")
        print(f"Difference: {abs(ent1 - ent2):.4f}")
        
        print("\n" + "="*70 + "\n")
        
        return True
    
    except Exception as e:
        print(f"ERROR: Comparison failed: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    if len(sys.argv) > 2:
        compare_files(sys.argv[1], sys.argv[2])
