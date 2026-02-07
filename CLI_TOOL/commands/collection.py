"""
ETHICAL Malware Analysis Toolkit (E.MAT)
CLI Collection Command

Batch file analysis - analyze multiple files at once.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def collection_analyze(filepaths, json_output=False):
    """
    Analyze multiple files in batch

    Args:
        filepaths: List of file paths to analyze
        json_output: Output in JSON format

    Returns:
        True if successful
    """
    from CLI_TOOL.commands.analyze import perform_static_analysis
    from CORE_ENGINE.utils.safety_checker import get_safety_checker

    safety = get_safety_checker()

    if not json_output:
        print("\n" + "=" * 70)
        print("E.MAT BATCH ANALYSIS")
        print("=" * 70)
        print(f"\nFiles to analyze: {len(filepaths)}\n")

    results = []

    for i, filepath in enumerate(filepaths, 1):
        if not json_output:
            print(f"[{i}/{len(filepaths)}] Analyzing: {filepath}")

        try:
            is_safe, error_msg = safety.check_file_safety(filepath)
            if not is_safe:
                if not json_output:
                    print(f"  ERROR: {error_msg}")
                results.append({'filename': filepath, 'error': error_msg})
                continue

            result = perform_static_analysis(filepath)
            results.append(result)

            if not json_output:
                fi = result['file_info']
                print(f"  Type: {fi['description']}")
                print(f"  SHA256: {fi['hashes'].get('sha256', 'N/A')}")
                print(f"  Entropy: {fi['entropy']} - {fi['entropy_analysis']}")
                yara_count = len(result['static_analysis'].get('yara_matches', []))
                if yara_count > 0:
                    print(f"  YARA Matches: {yara_count}")
                print()

        except Exception as e:
            if not json_output:
                print(f"  ERROR: {str(e)}")
            results.append({'filename': filepath, 'error': str(e)})

    if json_output:
        print(json.dumps({'total_files': len(results), 'results': results}, indent=2))
    else:
        print("=" * 70)
        print(f"BATCH ANALYSIS COMPLETE: {len(results)} file(s) processed")
        print("=" * 70 + "\n")

    return True


if __name__ == "__main__":
    if len(sys.argv) > 1:
        collection_analyze(sys.argv[1:])
