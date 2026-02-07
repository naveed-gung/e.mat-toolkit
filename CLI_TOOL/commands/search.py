"""
ETHICAL Malware Analysis Toolkit (E.MAT)
CLI Search Command

Search past analysis reports by hash, filename, IP, domain, etc.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

REPORT_HISTORY_FILE = Path(__file__).parent.parent.parent / 'DATA' / 'report_history.json'


def search_reports(query):
    """
    Search past analysis reports

    Args:
        query: Search term (hash, filename, IP, domain, etc.)

    Returns:
        True if successful
    """
    if not query:
        print("ERROR: No search query provided.", file=sys.stderr)
        print("Usage: python emat.py search --query <term>")
        return False

    query = query.strip().lower()

    # Load report history
    history = []
    if REPORT_HISTORY_FILE.exists():
        try:
            with open(REPORT_HISTORY_FILE, 'r') as f:
                history = json.load(f)
        except Exception:
            pass

    if not history:
        print("\nNo analysis history found.")
        print("Analyze some files first to build the report history.")
        print("  python emat.py analyze <file>\n")
        return True

    # Search
    matches = []
    for entry in history:
        hashes = entry.get('hashes', {})
        hash_match = any(query in str(v).lower() for v in hashes.values() if v)
        name_match = query in entry.get('filename', '').lower()
        summary_match = query in entry.get('summary', '').lower()
        mime_match = query in entry.get('mime_type', '').lower()

        if hash_match or name_match or summary_match or mime_match:
            matches.append(entry)

    # Display results
    print("\n" + "=" * 70)
    print("REPORT SEARCH RESULTS")
    print("=" * 70)
    print(f"\nQuery: {query}")
    print(f"Results: {len(matches)}\n")

    if matches:
        for i, m in enumerate(matches[:50], 1):
            print(f"--- Result {i} ---")
            print(f"  File:    {m.get('filename', 'unknown')}")
            print(f"  Time:    {m.get('timestamp', 'unknown')}")
            print(f"  Type:    {m.get('mime_type', 'unknown')}")
            print(f"  Size:    {m.get('size', 0):,} bytes")
            print(f"  SHA256:  {m.get('hashes', {}).get('sha256', 'N/A')}")
            print(f"  YARA:    {m.get('yara_matches', 0)} match(es)")
            summary = m.get('summary', '')[:200]
            if summary:
                print(f"  Summary: {summary}")
            print()
    else:
        print("No matching reports found.\n")

    print("=" * 70 + "\n")
    return True


if __name__ == "__main__":
    if len(sys.argv) > 1:
        search_reports(' '.join(sys.argv[1:]))
