"""
ETHICAL Malware Analysis Toolkit (E-MAT)
CLI String Search Command

Search for HEX/ASCII string patterns in files at the byte level.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def string_search(filepath, pattern):
    """
    Search for string/hex patterns in a file

    Args:
        filepath: File to search in
        pattern: Pattern to search for (ASCII or HEX)

    Returns:
        True if successful
    """
    from CORE_ENGINE.utils.safety_checker import get_safety_checker

    safety = get_safety_checker()
    is_safe, error_msg = safety.check_file_safety(filepath)
    if not is_safe:
        print(f"ERROR: {error_msg}", file=sys.stderr)
        return False

    print("\n" + "=" * 70)
    print("STRING / HEX PATTERN SEARCH")
    print("=" * 70)
    print(f"\nFile:    {filepath}")
    print(f"Pattern: {pattern}\n")

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # ASCII search
        pattern_bytes = pattern.encode('utf-8', errors='ignore')
        ascii_matches = []
        offset = 0
        while True:
            idx = data.find(pattern_bytes, offset)
            if idx == -1:
                break
            ctx_s = max(0, idx - 16)
            ctx_e = min(len(data), idx + len(pattern_bytes) + 16)
            ascii_matches.append({
                'offset': idx,
                'context': data[ctx_s:ctx_e]
            })
            offset = idx + 1
            if len(ascii_matches) >= 200:
                break

        # HEX search
        hex_matches = []
        try:
            hex_pattern = bytes.fromhex(pattern.replace(' ', ''))
            offset = 0
            while True:
                idx = data.find(hex_pattern, offset)
                if idx == -1:
                    break
                ctx_s = max(0, idx - 16)
                ctx_e = min(len(data), idx + len(hex_pattern) + 16)
                hex_matches.append({
                    'offset': idx,
                    'context': data[ctx_s:ctx_e]
                })
                offset = idx + 1
                if len(hex_matches) >= 200:
                    break
        except ValueError:
            pass  # Not valid hex

        # Display results
        print(f"ASCII matches: {len(ascii_matches)}")
        print(f"HEX matches:   {len(hex_matches)}")

        if ascii_matches:
            print("\n" + "-" * 70)
            print("ASCII MATCHES")
            print("-" * 70)
            for m in ascii_matches[:50]:
                hex_ctx = m['context'].hex()
                print(f"  Offset: 0x{m['offset']:08x}  Context: {hex_ctx}")

        if hex_matches:
            print("\n" + "-" * 70)
            print("HEX MATCHES")
            print("-" * 70)
            for m in hex_matches[:50]:
                hex_ctx = m['context'].hex()
                print(f"  Offset: 0x{m['offset']:08x}  Context: {hex_ctx}")

        if not ascii_matches and not hex_matches:
            print("\nNo matches found.")

        print("\n" + "=" * 70 + "\n")
        return True

    except Exception as e:
        print(f"ERROR: String search failed: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    if len(sys.argv) > 2:
        string_search(sys.argv[1], sys.argv[2])
