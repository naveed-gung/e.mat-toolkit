"""
ETHICAL Malware Analysis Toolkit (E.MAT)
CLI YARA Scan Command

Scan files with YARA rules.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def yara_scan(filepath: str, rules_path: str) -> bool:
    """
    Scan file with YARA rules
    
    Args:
        filepath: File to scan
        rules_path: Path to YARA rules
        
    Returns:
        True if successful
    """
    print("\n" + "="*70)
    print("YARA SCAN")
    print("="*70 + "\n")
    
    print(f"File: {filepath}")
    print(f"Rules: {rules_path}")
    
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from CORE_ENGINE.utils.yara_manager import YARAManager
        from CORE_ENGINE.utils.safety_checker import get_safety_checker
        
        # Safety check
        safety = get_safety_checker()
        is_safe, error_msg = safety.check_yara_rules_safety(rules_path)
        
        if not is_safe:
            print(f"ERROR: {error_msg}", file=sys.stderr)
            return False
        
        if error_msg:  # Warning
            print(f"⚠️  {error_msg}\n")
        
        # Perform scan
        manager = YARAManager(rules_path)
        result = manager.scan(filepath)
        
        if not result.get('scanned'):
            print(f"ERROR: {result.get('error', 'Unknown error')}", file=sys.stderr)
            return False
        
        # Display results
        print(f"\nRules File: {result['rules_file']}")
        print(f"Matches: {result['matches_count']}")
        
        if result['matches']:
            print("\n" + "-"*70)
            print("MATCHED RULES")
            print("-"*70)
            
            for match in result['matches']:
                print(f"\nRule: {match['rule']}")
                print(f"Severity: {match['meta'].get('severity', 'unknown').upper()}")
                print(f"Description: {match['meta'].get('description', 'No description')}")
                print(f"Note: {match.get('educational_note', 'No note')}")
                
                if match.get('strings'):
                    print(f"Matched Strings: {len(match['strings'])}")
                    for s in match['strings'][:3]:  # Show first 3
                        print(f"  • {s['identifier']}: {s['data'][:50]}")
        
        print(f"\n{result.get('educational_summary', '')}")
        
        print("\n" + "="*70 + "\n")
        return True
        
    except Exception as e:
        print(f"ERROR: YARA scan failed: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    if len(sys.argv) > 2:
        yara_scan(sys.argv[1], sys.argv[2])
