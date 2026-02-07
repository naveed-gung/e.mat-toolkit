"""
ETHICAL Malware Analysis Toolkit (E-MAT)
CLI Analyze Command

Performs static analysis on files with optional sandboxed dynamic analysis.
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from CORE_ENGINE.utils.hashing import get_file_info
from CORE_ENGINE.utils.safety_checker import get_safety_checker
from CORE_ENGINE.config.preferences import PreferencesManager
from CORE_ENGINE.utils.cli_theme import (
    print_header, print_section, print_key_value, print_success,
    print_error, print_warning, print_info, print_branding, Colors
)


def analyze_file(filepath: str, safe_sandbox: bool = False, 
                json_output: bool = False, report_format: Optional[str] = None) -> bool:
    """
    Analyze a file
    
    Args:
        filepath: Path to file to analyze
        safe_sandbox: Enable sandboxed dynamic analysis
        json_output: Output in JSON format
        report_format: Generate report (html/pdf)
        
    Returns:
        True if successful
    """
    # Get safety checker and preferences
    safety = get_safety_checker()
    prefs = PreferencesManager()
    
    # Display ethical warning for analysis
    if not json_output:
        safety.display_ethical_warning(f"Analyze file: {filepath}")
    
    # Check file safety
    is_safe, error_msg = safety.check_file_safety(filepath)
    if not is_safe:
        print(f"ERROR: {error_msg}", file=sys.stderr)
        return False
    
    # Check if sandbox is requested
    if safe_sandbox:
        docker_available = prefs.is_docker_available()
        is_safe, error_msg = safety.check_sandbox_safety(True, docker_available)
        if not is_safe:
            print(f"ERROR: {error_msg}", file=sys.stderr)
            return False
        
        if not json_output:
            print("\n[!] SANDBOXED ANALYSIS ENABLED")
            print("File will be executed in an isolated Docker container with no network access.\n")
    
    # Perform analysis
    try:
        result = perform_static_analysis(filepath)
        
        if safe_sandbox:
            # TODO: Implement dynamic analysis in Phase 3
            result['dynamic_analysis'] = {
                'executed': False,
                'note': 'Dynamic analysis not yet implemented (Phase 3 feature)'
            }
        
        # Output results
        if json_output:
            print(json.dumps(result, indent=2))
        else:
            display_analysis_results(result)
        
        # Generate report if requested
        if report_format:
            generate_report(result, report_format, filepath)
        
        return True
    
    except Exception as e:
        print(f"ERROR: Analysis failed: {e}", file=sys.stderr)
        return False


def perform_static_analysis(filepath: str) -> dict:
    """
    Perform static analysis on a file
    
    Args:
        filepath: Path to file
        
    Returns:
        Analysis results dictionary
    """
    # Get file information
    file_info = get_file_info(filepath)
    
    # Initialize result structure
    result = {
        'metadata': {
            'tool_name': 'ETHICAL Malware Analysis Toolkit (E-MAT)',
            'version': '1.0.0',
            'analysis_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'purpose': 'EDUCATIONAL ANALYSIS ONLY - For defensive cybersecurity research.',
            'disclaimer': 'This report is generated for educational purposes. Misuse of this tool or its findings for unauthorized activities is strictly prohibited.',
            'timestamp': datetime.now().isoformat()
        },
        'file_info': {
            'filename': file_info['filename'],
            'filepath': file_info['filepath'],
            'size': file_info['size'],
            'mime_type': file_info['mime_type'],
            'description': file_info['description'],
            'hashes': file_info['hashes'],
            'entropy': file_info['entropy'],
            'entropy_analysis': file_info['entropy_analysis']
        },
        'static_analysis': {
            'pe_analysis': None,
            'elf_analysis': None,
            'document_analysis': None,
            'strings': None,
            'yara_matches': []
        },
        'educational_summary': {
            'overall_assessment': '',
            'suggested_learning_topics': []
        }
    }
    
    # Perform format-specific analysis
    mime_type = file_info.get('mime_type', '').lower() if file_info else ''
    
    # PE Analysis
    if 'executable' in mime_type or 'dosexec' in mime_type or filepath.endswith('.exe') or filepath.endswith('.dll'):
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from CORE_ENGINE.analyzers.static.pe_analyzer import PEAnalyzer
            
            pe_analyzer = PEAnalyzer(filepath)
            result['static_analysis']['pe_analysis'] = pe_analyzer.analyze()
        except Exception as e:
            result['static_analysis']['pe_analysis'] = {'error': str(e)}
    
    # ELF Analysis
    elif 'elf' in mime_type or (filepath.startswith('/') and not '.' in Path(filepath).name):
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from CORE_ENGINE.analyzers.static.elf_analyzer import ELFAnalyzer
            
            elf_analyzer = ELFAnalyzer(filepath)
            result['static_analysis']['elf_analysis'] = elf_analyzer.analyze()
        except Exception as e:
            result['static_analysis']['elf_analysis'] = {'error': str(e)}
    
    # Document Analysis (PDF, Office)
    doc_extensions = ['.pdf', '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm',
                      '.ppt', '.pptx', '.pptm', '.dot', '.dotx', '.xlt', '.xltx']
    is_doc = any(filepath.lower().endswith(ext) for ext in doc_extensions)
    is_doc = is_doc or 'pdf' in mime_type or 'office' in mime_type or 'msword' in mime_type
    
    if is_doc:
        try:
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from CORE_ENGINE.analyzers.static.document_analyzer import analyze_document
            
            result['static_analysis']['document_analysis'] = analyze_document(filepath)
        except Exception as e:
            result['static_analysis']['document_analysis'] = {'error': str(e)}
    
    # String Analysis (for all files)
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from CORE_ENGINE.analyzers.static.string_analyzer import StringAnalyzer
        
        string_analyzer = StringAnalyzer(filepath)
        result['static_analysis']['strings'] = string_analyzer.analyze()
    except Exception as e:
        result['static_analysis']['strings'] = {'error': str(e)}
    
    # YARA Scanning
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from CORE_ENGINE.utils.yara_manager import YARAManager
        
        yara_manager = YARAManager()
        yara_result = yara_manager.scan(filepath)
        
        if yara_result.get('scanned'):
            result['static_analysis']['yara_matches'] = yara_result.get('matches', [])
            result['static_analysis']['yara_summary'] = yara_result.get('educational_summary', '')
    except Exception as e:
        result['static_analysis']['yara_matches'] = []
        result['static_analysis']['yara_error'] = str(e)
    
    # Generate educational summary
    result['educational_summary'] = _generate_comprehensive_assessment(result)
    
    return result


def display_analysis_results(result: dict):
    """Display analysis results in human-readable format"""
    print_header("ANALYSIS REPORT")
    
    # Metadata
    print(f"{Colors.TEXT_SECONDARY}{result['metadata']['disclaimer']}{Colors.RESET}\n")
    print_key_value("Analysis ID", result['metadata']['analysis_id'], Colors.PRIMARY)
    print_key_value("Timestamp", result['metadata']['timestamp'], Colors.TEXT_SECONDARY)
    
    # File Info
    print_section("FILE INFORMATION")
    file_info = result['file_info']
    print_key_value("Filename", file_info['filename'], Colors.PRIMARY)
    print_key_value("Path", file_info['filepath'], Colors.TEXT_SECONDARY)
    print_key_value("Size", f"{file_info['size']:,} bytes", Colors.TEXT_PRIMARY)
    print_key_value("Type", file_info['description'], Colors.TEXT_PRIMARY)
    print_key_value("MIME", file_info['mime_type'], Colors.TEXT_SECONDARY)
    print_key_value("Entropy", f"{file_info['entropy']} - {file_info['entropy_analysis']}", 
                    Colors.WARNING if file_info['entropy'] > 7.0 else Colors.SUCCESS)
    
    # Hashes
    print_section("FILE HASHES")
    for hash_type, hash_value in file_info['hashes'].items():
        print_key_value(hash_type.upper(), hash_value, Colors.TEXT_SECONDARY)
    
    # PE Analysis
    if result['static_analysis'].get('pe_analysis') and result['static_analysis']['pe_analysis'].get('is_pe'):
        pe = result['static_analysis']['pe_analysis']
        print("\n" + "-"*70)
        print("PE ANALYSIS (Windows Executable)")
        print("-"*70)
        print(f"Architecture: {pe.get('architecture', 'Unknown')}")
        print(f"Subsystem: {pe.get('subsystem', 'Unknown')}")
        print(f"Compile Time: {pe.get('compile_timestamp', 'Unknown')}")
        print(f"Entry Point: {pe.get('entry_point', 'Unknown')}")
        
        if pe.get('sections'):
            print(f"\nSections: {len(pe['sections'])}")
            for section in pe['sections'][:5]:  # Show first 5
                print(f"  {section['name']:10s} - Size: {section['virtual_size']:8d}, Entropy: {section['entropy']:.2f}")
        
        if pe.get('imports'):
            print(f"\nImported DLLs: {len(pe['imports'])}")
            high_risk_count = sum(1 for imp in pe['imports'] if imp.get('dll_risk') != 'LOW')
            if high_risk_count > 0:
                print(f"  [!] {high_risk_count} network-related DLLs detected")
        
        if pe.get('packer_detection', {}).get('likely_packed'):
            print(f"\n[!] PACKER DETECTED:")
            for indicator in pe['packer_detection'].get('indicators', []):
                print(f"  • {indicator}")
    
    # ELF Analysis
    if result['static_analysis'].get('elf_analysis') and result['static_analysis']['elf_analysis'].get('is_elf'):
        elf = result['static_analysis']['elf_analysis']
        print("\n" + "-"*70)
        print("ELF ANALYSIS (Linux Executable)")
        print("-"*70)
        print(f"Architecture: {elf.get('architecture', 'Unknown')}")
        print(f"Class: {elf.get('class', 'Unknown')}")
        print(f"Type: {elf.get('type', 'Unknown')}")
        print(f"Entry Point: {elf.get('entry_point', 'Unknown')}")
        
        if elf.get('dynamic_dependencies'):
            print(f"\nDynamic Dependencies: {len(elf['dynamic_dependencies'])}")
            for dep in elf['dynamic_dependencies'][:5]:
                print(f"  • {dep}")
        
        if elf.get('symbols'):
            print(f"\nSymbols: {elf['symbols'].get('count', 0)} total")
            if elf['symbols'].get('imported'):
                print(f"  Imported: {len(elf['symbols']['imported'])}")
            if elf['symbols'].get('exported'):
                print(f"  Exported: {len(elf['symbols']['exported'])}")
    
    # String Analysis
    if result['static_analysis'].get('strings'):
        strings = result['static_analysis']['strings']
        if not strings.get('error'):
            print("\n" + "-"*70)
            print("STRING ANALYSIS")
            print("-"*70)
            print(f"Total Strings: {strings.get('total_count', 0)}")
            
            stats = strings.get('statistics', {})
            if stats.get('urls_found', 0) > 0:
                print(f"  URLs: {stats['urls_found']}")
            if stats.get('ips_found', 0) > 0:
                print(f"  IP Addresses: {stats['ips_found']}")
            if stats.get('file_paths_found', 0) > 0:
                print(f"  File Paths: {stats['file_paths_found']}")
            if stats.get('suspicious_keywords_found', 0) > 0:
                print(f"  [!] Suspicious Keywords: {stats['suspicious_keywords_found']}")
            
            # Show some interesting strings
            categories = strings.get('categories', {})
            if categories.get('urls'):
                print(f"\nSample URLs:")
                for url in categories['urls'][:3]:
                    print(f"  • {url}")
            
            if categories.get('suspicious_keywords'):
                print(f"\nSuspicious Keywords Found:")
                for keyword in categories['suspicious_keywords'][:5]:
                    print(f"  • {keyword}")
    
    # YARA Matches
    yara_matches = result['static_analysis'].get('yara_matches', [])
    if yara_matches:
        print("\n" + "-"*70)
        print("YARA MATCHES")
        print("-"*70)
        print(f"Matched Rules: {len(yara_matches)}")
        
        for match in yara_matches:
            severity = match.get('meta', {}).get('severity', 'unknown')
            print(f"\n  Rule: {match['rule']}")
            print(f"  Severity: {severity.upper()}")
            print(f"  Note: {match.get('educational_note', 'No note')}")
    
    # Educational Summary
    print("\n" + "-"*70)
    print("EDUCATIONAL SUMMARY")
    print("-"*70)
    edu = result['educational_summary']
    print(f"\nAssessment: {edu['overall_assessment']}")
    print(f"\nSuggested Learning Topics:")
    for topic in edu['suggested_learning_topics']:
        print(f"  • {topic}")
    
    print("\n" + "="*70)
    print("END OF REPORT")
    print("="*70 + "\n")



def _generate_comprehensive_assessment(result: dict) -> dict:
    """Generate comprehensive educational assessment based on all analysis"""
    file_info = result['file_info']
    static_analysis = result['static_analysis']
    
    assessment_parts = []
    topics = ["File Hashing and Identification", "Entropy Analysis"]
    
    # File type assessment
    assessment_parts.append(f"This file is identified as {file_info['description']}.")
    
    # Entropy assessment
    entropy = file_info['entropy']
    if entropy > 7.0:
        assessment_parts.append("The high entropy suggests the file may be packed, compressed, or encrypted.")
        topics.append("Packer Detection")
    elif entropy < 4.0:
        assessment_parts.append("The low entropy suggests this is likely plain text or structured data.")
    
    # PE-specific assessment
    pe_analysis = static_analysis.get('pe_analysis')
    if pe_analysis and pe_analysis.get('is_pe'):
        pe = pe_analysis
        assessment_parts.append("As a Windows executable, it warrants careful analysis of its structure and behavior.")
        topics.extend(["PE File Structure", "Import Analysis"])
        
        if pe.get('packer_detection', {}).get('likely_packed'):
            assessment_parts.append("[!] Packer detection indicates possible obfuscation.")
            topics.append("Unpacking Techniques")
        
        if pe.get('imports'):
            high_risk_imports = sum(1 for imp in pe['imports'] 
                                   if any(f.get('risk_level') == 'HIGH' 
                                         for f in imp.get('functions', [])))
            if high_risk_imports > 0:
                assessment_parts.append(f"Contains {high_risk_imports} high-risk API imports that warrant investigation.")
                topics.append("Windows API Analysis")
    
    # ELF-specific assessment
    elf_analysis = static_analysis.get('elf_analysis')
    if elf_analysis and elf_analysis.get('is_elf'):
        elf = elf_analysis
        assessment_parts.append("As a Linux executable, analysis of its dependencies and symbols is important.")
        topics.extend(["ELF File Format", "Dynamic Linking"])
        
        if elf.get('dynamic_dependencies'):
            assessment_parts.append(f"Depends on {len(elf['dynamic_dependencies'])} shared libraries.")
    
    # String analysis assessment
    strings = static_analysis.get('strings')
    if strings and not strings.get('error'):
        stats = strings.get('statistics', {})
        
        if stats.get('urls_found', 0) > 0 or stats.get('ips_found', 0) > 0:
            assessment_parts.append(f"Contains network indicators ({stats.get('urls_found', 0)} URLs, {stats.get('ips_found', 0)} IPs).")
            topics.append("Network Indicators of Compromise")
        
        if stats.get('suspicious_keywords_found', 0) > 0:
            assessment_parts.append(f"[!] Found {stats['suspicious_keywords_found']} suspicious keywords.")
            topics.append("Behavioral Analysis")
    
    # YARA assessment
    yara_matches = static_analysis.get('yara_matches', [])
    if yara_matches:
        high_severity = sum(1 for m in yara_matches if m.get('meta', {}).get('severity') == 'high')
        medium_severity = sum(1 for m in yara_matches if m.get('meta', {}).get('severity') == 'medium')
        
        if high_severity > 0:
            assessment_parts.append(f"[!] Matched {high_severity} high-severity YARA rules.")
        elif medium_severity > 0:
            assessment_parts.append(f"Matched {medium_severity} medium-severity YARA rules.")
        
        topics.append("YARA Rule Writing")
    
    # Final recommendation
    assessment_parts.append("Further analysis would reveal more about its purpose and safety.")
    
    return {
        'overall_assessment': ' '.join(assessment_parts),
        'suggested_learning_topics': list(set(topics))  # Remove duplicates
    }


def _generate_assessment(file_info: dict) -> str:
    """Legacy function - kept for compatibility"""
    return f"This file is identified as {file_info['description']}."


def _suggest_topics(file_info: dict) -> list:
    """Legacy function - kept for compatibility"""
    return ["File Analysis Basics"]


def generate_report(result: dict, format: str, original_file: str):
    """Generate HTML or PDF report"""
    # TODO: Implement report generation in Phase 2
    print(f"\n[i] Report generation ({format}) will be implemented in Phase 2")
    print(f"   For now, use --json to save results to a file:")
    print(f"   python __main__.py analyze {original_file} --json > report.json")


if __name__ == "__main__":
    # Test with a file
    import sys
    if len(sys.argv) > 1:
        analyze_file(sys.argv[1])
