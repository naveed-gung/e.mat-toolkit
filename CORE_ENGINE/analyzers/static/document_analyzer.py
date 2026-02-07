"""
ETHICAL Malware Analysis Toolkit (E-MAT)
Document Analyzer

Analyzes PDF and Office documents for suspicious content:
- PDF structure analysis using pdfminer.six
- Office document macro detection using oletools
- Embedded object extraction
- Suspicious pattern detection
"""

import os
from pathlib import Path
from typing import Dict, Optional


def analyze_pdf(filepath: str) -> Dict:
    """
    Analyze a PDF document for suspicious content

    Args:
        filepath: Path to the PDF file

    Returns:
        Dictionary with PDF analysis results
    """
    result = {
        'is_pdf': False,
        'pages': 0,
        'metadata': {},
        'suspicious_elements': [],
        'javascript': False,
        'embedded_files': False,
        'auto_actions': False,
        'urls': [],
        'error': None
    }

    try:
        from pdfminer.high_level import extract_text
        from pdfminer.pdfparser import PDFParser
        from pdfminer.pdfdocument import PDFDocument
        from pdfminer.pdfpage import PDFPage

        result['is_pdf'] = True

        with open(filepath, 'rb') as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)

            # Metadata
            if doc.info:
                for info_dict in doc.info:
                    for key, value in info_dict.items():
                        try:
                            if isinstance(value, bytes):
                                value = value.decode('utf-8', errors='ignore')
                            result['metadata'][key] = str(value)[:200]
                        except Exception:
                            pass

            # Page count
            pages = list(PDFPage.create_pages(doc))
            result['pages'] = len(pages)

        # Extract text and look for suspicious patterns
        try:
            text = extract_text(filepath, maxpages=10)
            if text:
                text_lower = text.lower()

                # Check for JavaScript
                if '/javascript' in text_lower or '/js' in text_lower:
                    result['javascript'] = True
                    result['suspicious_elements'].append('Contains JavaScript')

                # Check for auto-actions
                auto_keywords = ['/openaction', '/aa', '/launch', '/submitform', '/importdata']
                for kw in auto_keywords:
                    if kw in text_lower:
                        result['auto_actions'] = True
                        result['suspicious_elements'].append(f'Auto-action: {kw}')

                # Check for embedded files
                if '/embeddedfile' in text_lower or '/filespec' in text_lower:
                    result['embedded_files'] = True
                    result['suspicious_elements'].append('Contains embedded files')

                # Extract URLs
                import re
                urls = re.findall(r'https?://[^\s<>"\']+', text)
                result['urls'] = list(set(urls))[:20]
                if urls:
                    result['suspicious_elements'].append(f'Contains {len(urls)} URL(s)')

        except Exception:
            pass

        # Raw byte scan for additional indicators
        with open(filepath, 'rb') as f:
            raw = f.read(100000)  # First 100KB
            raw_str = raw.decode('latin-1', errors='ignore').lower()

            suspicious_patterns = [
                ('/javascript', 'JavaScript reference'),
                ('/jbig2decode', 'JBIG2 decoder (potential exploit vector)'),
                ('/richmedia', 'Rich media content'),
                ('/xfa', 'XFA form (potential exploit vector)'),
                ('cmd.exe', 'Command execution reference'),
                ('powershell', 'PowerShell reference'),
            ]

            for pattern, desc in suspicious_patterns:
                if pattern.lower() in raw_str:
                    if desc not in [s for s in result['suspicious_elements']]:
                        result['suspicious_elements'].append(desc)

    except ImportError:
        result['error'] = 'pdfminer.six not installed. Install with: pip install pdfminer.six'
    except Exception as e:
        result['error'] = f'PDF analysis failed: {str(e)}'

    return result


def analyze_office(filepath: str) -> Dict:
    """
    Analyze an Office document (doc, docx, xls, ppt, etc.) for suspicious content

    Args:
        filepath: Path to the Office document

    Returns:
        Dictionary with Office analysis results
    """
    result = {
        'is_office': False,
        'format': 'unknown',
        'macros_found': False,
        'macro_count': 0,
        'macro_names': [],
        'suspicious_keywords': [],
        'auto_exec_macros': [],
        'embedded_objects': [],
        'metadata': {},
        'error': None
    }

    ext = Path(filepath).suffix.lower()

    try:
        # OLE format analysis (doc, xls, ppt)
        if ext in ['.doc', '.xls', '.ppt', '.dot', '.xlt']:
            result['format'] = 'OLE (legacy Office)'
            _analyze_ole(filepath, result)

        # OOXML format analysis (docx, xlsx, pptx)
        elif ext in ['.docx', '.xlsx', '.pptx', '.dotx', '.xltx']:
            result['format'] = 'OOXML (modern Office)'
            _analyze_ooxml(filepath, result)

        # Macro-enabled formats
        elif ext in ['.docm', '.xlsm', '.pptm']:
            result['format'] = 'OOXML macro-enabled'
            _analyze_ooxml(filepath, result)

        else:
            # Try OLE first, then OOXML
            try:
                _analyze_ole(filepath, result)
            except Exception:
                _analyze_ooxml(filepath, result)

        result['is_office'] = True

    except ImportError:
        result['error'] = 'oletools not installed. Install with: pip install oletools'
    except Exception as e:
        result['error'] = f'Office analysis failed: {str(e)}'

    return result


def _analyze_ole(filepath: str, result: Dict):
    """Analyze OLE format documents"""
    from oletools.olevba import VBA_Parser

    vba_parser = VBA_Parser(filepath)

    if vba_parser.detect_vba_macros():
        result['macros_found'] = True

        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            result['macro_count'] += 1
            result['macro_names'].append(vba_filename or stream_path)

            # Check for suspicious keywords
            vba_lower = vba_code.lower() if vba_code else ''

            suspicious = {
                'shell': 'Shell execution',
                'wscript.shell': 'WScript Shell object',
                'powershell': 'PowerShell execution',
                'cmd.exe': 'Command prompt execution',
                'createobject': 'COM object creation',
                'urldownloadtofile': 'File download from URL',
                'environ': 'Environment variable access',
                'kill': 'Process termination',
                'deletefile': 'File deletion',
                'copyfile': 'File copy operation',
                'base64': 'Base64 encoding/decoding',
                'chr(': 'Character obfuscation',
                'callbyname': 'Dynamic function call',
            }

            for keyword, desc in suspicious.items():
                if keyword in vba_lower and desc not in result['suspicious_keywords']:
                    result['suspicious_keywords'].append(desc)

            # Check for auto-exec macros
            auto_exec = ['autoopen', 'autoclose', 'autoexec', 'auto_open',
                        'document_open', 'workbook_open', 'document_close']
            for ae in auto_exec:
                if ae in vba_lower and ae not in result['auto_exec_macros']:
                    result['auto_exec_macros'].append(ae)

    vba_parser.close()


def _analyze_ooxml(filepath: str, result: Dict):
    """Analyze OOXML format documents"""
    import zipfile

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            names = zf.namelist()

            # Check for VBA macros
            vba_files = [n for n in names if 'vbaproject' in n.lower() or n.endswith('.bin')]
            if vba_files:
                result['macros_found'] = True
                result['macro_names'] = vba_files

            # Check for embedded objects
            ole_objects = [n for n in names if 'oleobject' in n.lower() or 'embedding' in n.lower()]
            result['embedded_objects'] = ole_objects

            # Check for external relationships
            for name in names:
                if name.endswith('.rels'):
                    try:
                        content = zf.read(name).decode('utf-8', errors='ignore').lower()
                        if 'http' in content:
                            result['suspicious_keywords'].append('External URL reference in relationships')
                        if 'oleobject' in content:
                            result['suspicious_keywords'].append('OLE object reference')
                    except Exception:
                        pass

            # Try oletools VBA parser on macro-enabled files
            try:
                _analyze_ole(filepath, result)
            except Exception:
                pass

    except zipfile.BadZipFile:
        # Not a valid ZIP/OOXML, try OLE
        _analyze_ole(filepath, result)


def analyze_document(filepath: str) -> Dict:
    """
    Analyze any document type (PDF or Office)

    Args:
        filepath: Path to the document

    Returns:
        Dictionary with analysis results
    """
    ext = Path(filepath).suffix.lower()

    if ext == '.pdf':
        return {'pdf_analysis': analyze_pdf(filepath)}

    office_extensions = ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm',
                        '.ppt', '.pptx', '.pptm', '.dot', '.dotx', '.xlt', '.xltx']

    if ext in office_extensions:
        return {'office_analysis': analyze_office(filepath)}

    # Try to detect by magic bytes
    try:
        with open(filepath, 'rb') as f:
            header = f.read(8)

        if header.startswith(b'%PDF'):
            return {'pdf_analysis': analyze_pdf(filepath)}
        elif header.startswith(b'\xd0\xcf\x11\xe0'):  # OLE
            return {'office_analysis': analyze_office(filepath)}
        elif header.startswith(b'PK\x03\x04'):  # ZIP/OOXML
            return {'office_analysis': analyze_office(filepath)}
    except Exception:
        pass

    return {'document_analysis': {'error': 'Unsupported document format'}}


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) > 1:
        result = analyze_document(sys.argv[1])
        print(json.dumps(result, indent=2))
