"""
ETHICAL Malware Analysis Toolkit (E.MAT)
Web Service / REST API

Flask-based REST API for E.MAT analysis
Runs on localhost only for security
"""

import sys
import os
import json
import glob
from pathlib import Path
from datetime import datetime

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename
import tempfile

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from CLI_TOOL.commands.analyze import perform_static_analysis
from CORE_ENGINE.utils.safety_checker import get_safety_checker
from CORE_ENGINE.utils.yara_manager import YARAManager
from CORE_ENGINE.utils.hashing import calculate_hashes


# Initialize Flask app
app = Flask(__name__)

# CORS configuration - allow both localhost and 127.0.0.1
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:*", "http://127.0.0.1:*"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 250 * 1024 * 1024  # 250MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Report history storage (in-memory + file-backed)
REPORT_HISTORY_FILE = Path(__file__).parent.parent / 'DATA' / 'report_history.json'
REPORT_HISTORY = []

def _load_report_history():
    global REPORT_HISTORY
    if REPORT_HISTORY_FILE.exists():
        try:
            with open(REPORT_HISTORY_FILE, 'r') as f:
                REPORT_HISTORY = json.load(f)
        except:
            REPORT_HISTORY = []

def _save_report_history():
    REPORT_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_HISTORY_FILE, 'w') as f:
        json.dump(REPORT_HISTORY[-500:], f, indent=2)

def _add_to_report_history(result):
    entry = {
        'timestamp': datetime.now().isoformat(),
        'filename': result.get('file_info', {}).get('filename', 'unknown'),
        'hashes': result.get('file_info', {}).get('hashes', {}),
        'mime_type': result.get('file_info', {}).get('mime_type', ''),
        'size': result.get('file_info', {}).get('size', 0),
        'summary': result.get('educational_summary', {}).get('overall_assessment', ''),
        'yara_matches': len(result.get('static_analysis', {}).get('yara_matches', [])),
    }
    REPORT_HISTORY.append(entry)
    _save_report_history()

_load_report_history()

# Any file can be analyzed for educational purposes
# No extension restriction - static analysis is safe on all file types


@app.route('/')
def index():
    """Serve web interface"""
    return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    from flask import send_from_directory
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.svg',
        mimetype='image/svg+xml'
    )



@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'E.MAT REST API',
        'version': '1.0.0',
        'purpose': 'EDUCATIONAL ANALYSIS ONLY'
    })


@app.route('/api/analyze', methods=['POST', 'OPTIONS'])
def analyze_file():
    """Analyze uploaded file"""
    # Handle preflight request
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        # Check if file is present
        if 'file' not in request.files:
            app.logger.error("No file in request")
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            app.logger.error("Empty filename")
            return jsonify({'error': 'No file selected'}), 400
        
        app.logger.info(f"Received file: {file.filename}")
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(filepath)
            app.logger.info(f"File saved to: {filepath}")
            
            # Safety check
            safety = get_safety_checker()
            is_safe, error_msg = safety.check_file_safety(filepath)
            
            if not is_safe:
                app.logger.warning(f"Safety check failed: {error_msg}")
                return jsonify({'error': error_msg}), 400
            
            # Perform analysis
            app.logger.info("Starting analysis...")
            result = perform_static_analysis(filepath)
            app.logger.info("Analysis complete")
            
            # Save to report history
            _add_to_report_history(result)
            
            return jsonify(result)
            
        except Exception as e:
            app.logger.error(f"Analysis error: {str(e)}", exc_info=True)
            return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
            
        finally:
            # Clean up temporary file
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    app.logger.info(f"Cleaned up: {filepath}")
                except Exception as e:
                    app.logger.warning(f"Failed to clean up {filepath}: {e}")
    
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/collection', methods=['POST', 'OPTIONS'])
def analyze_collection():
    """Batch file analysis - File Collection tab"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        files = request.files.getlist('files')
        if not files or all(f.filename == '' for f in files):
            return jsonify({'error': 'No files provided'}), 400
        
        results = []
        safety = get_safety_checker()
        
        for file in files:
            if file.filename == '':
                continue
            
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(filepath)
                
                is_safe, error_msg = safety.check_file_safety(filepath)
                if not is_safe:
                    results.append({'filename': file.filename, 'error': error_msg})
                    continue
                
                result = perform_static_analysis(filepath)
                _add_to_report_history(result)
                results.append(result)
                
            except Exception as e:
                results.append({'filename': file.filename, 'error': str(e)})
            finally:
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except:
                        pass
        
        return jsonify({
            'total_files': len(results),
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': f'Collection analysis failed: {str(e)}'}), 500


@app.route('/api/search/report', methods=['GET'])
def search_reports():
    """Search past analysis reports - Report Search tab"""
    query = request.args.get('q', '').strip().lower()
    
    if not query:
        return jsonify({'error': 'No search query provided'}), 400
    
    matches = []
    for entry in REPORT_HISTORY:
        # Search in hashes
        hashes = entry.get('hashes', {})
        hash_match = any(query in v.lower() for v in hashes.values() if v)
        
        # Search in filename
        name_match = query in entry.get('filename', '').lower()
        
        # Search in summary
        summary_match = query in entry.get('summary', '').lower()
        
        # Search in mime type
        mime_match = query in entry.get('mime_type', '').lower()
        
        if hash_match or name_match or summary_match or mime_match:
            matches.append(entry)
    
    return jsonify({
        'query': query,
        'total_results': len(matches),
        'results': matches[:50]
    })


@app.route('/api/yara/search', methods=['POST', 'OPTIONS'])
def yara_search():
    """YARA rule search - YARA Search tab"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        # Accept either a YARA rule file upload or raw rule text
        rule_text = None
        rule_file_path = None
        
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = secure_filename(file.filename)
            rule_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'yara_' + filename)
            file.save(rule_file_path)
        elif request.is_json:
            rule_text = request.json.get('rule_text', '')
        elif request.form.get('rule_text'):
            rule_text = request.form.get('rule_text')
        
        if not rule_text and not rule_file_path:
            return jsonify({'error': 'No YARA rule provided. Upload a .yar file or provide rule_text.'}), 400
        
        # If rule text provided, write to temp file
        if rule_text and not rule_file_path:
            rule_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_rule.yar')
            with open(rule_file_path, 'w') as f:
                f.write(rule_text)
        
        # Scan target file if provided
        target_path = None
        if 'target' in request.files and request.files['target'].filename:
            target = request.files['target']
            target_name = secure_filename(target.filename)
            target_path = os.path.join(app.config['UPLOAD_FOLDER'], 'target_' + target_name)
            target.save(target_path)
        
        if target_path:
            manager = YARAManager(rule_file_path)
            result = manager.scan(target_path)
        else:
            # Just validate the rule compiles
            try:
                import yara
                yara.compile(filepath=rule_file_path)
                result = {'scanned': True, 'matches_count': 0, 'matches': [], 
                         'message': 'YARA rule compiled successfully. Upload a target file to scan.'}
            except ImportError:
                result = {'scanned': False, 'error': 'yara-python not installed'}
            except Exception as e:
                result = {'scanned': False, 'error': f'YARA compilation error: {str(e)}'}
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'YARA search failed: {str(e)}'}), 500
    finally:
        for p in [rule_file_path, target_path]:
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except:
                    pass


@app.route('/api/string/search', methods=['POST', 'OPTIONS'])
def string_search():
    """String/hex pattern search - String Search tab"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        pattern = None
        if request.is_json:
            pattern = request.json.get('pattern', '')
        else:
            pattern = request.form.get('pattern', '')
        
        if not pattern:
            return jsonify({'error': 'No search pattern provided'}), 400
        
        # Search in uploaded file if provided
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(filepath)
                
                matches = []
                with open(filepath, 'rb') as f:
                    data = f.read()
                
                # ASCII search
                pattern_bytes = pattern.encode('utf-8', errors='ignore')
                offset = 0
                while True:
                    idx = data.find(pattern_bytes, offset)
                    if idx == -1:
                        break
                    context_start = max(0, idx - 16)
                    context_end = min(len(data), idx + len(pattern_bytes) + 16)
                    matches.append({
                        'offset': hex(idx),
                        'type': 'ASCII',
                        'context': data[context_start:context_end].hex()
                    })
                    offset = idx + 1
                    if len(matches) >= 100:
                        break
                
                # Hex search (if pattern looks like hex)
                hex_matches = []
                try:
                    hex_pattern = bytes.fromhex(pattern.replace(' ', ''))
                    offset = 0
                    while True:
                        idx = data.find(hex_pattern, offset)
                        if idx == -1:
                            break
                        context_start = max(0, idx - 16)
                        context_end = min(len(data), idx + len(hex_pattern) + 16)
                        hex_matches.append({
                            'offset': hex(idx),
                            'type': 'HEX',
                            'context': data[context_start:context_end].hex()
                        })
                        offset = idx + 1
                        if len(hex_matches) >= 100:
                            break
                except ValueError:
                    pass
                
                return jsonify({
                    'pattern': pattern,
                    'filename': file.filename,
                    'ascii_matches': len(matches),
                    'hex_matches': len(hex_matches),
                    'matches': matches + hex_matches
                })
                
            finally:
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except:
                        pass
        
        # Search in report history strings
        history_matches = []
        for entry in REPORT_HISTORY:
            if pattern.lower() in entry.get('filename', '').lower():
                history_matches.append(entry)
            elif any(pattern.lower() in v.lower() for v in entry.get('hashes', {}).values() if v):
                history_matches.append(entry)
        
        return jsonify({
            'pattern': pattern,
            'history_matches': len(history_matches),
            'results': history_matches[:50]
        })
    
    except Exception as e:
        return jsonify({'error': f'String search failed: {str(e)}'}), 500



@app.route('/api/yara/scan', methods=['POST'])
def yara_scan():
    """YARA scan endpoint"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    rules_path = request.form.get('rules_path', None)
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(filepath)
        
        # Perform YARA scan
        manager = YARAManager(rules_path)
        result = manager.scan(filepath)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'YARA scan failed: {str(e)}'}), 500
        
    finally:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except:
                pass


@app.route('/api/info', methods=['GET'])
def api_info():
    """API information endpoint"""
    return jsonify({
        'name': 'E.MAT REST API',
        'version': '1.0.0',
        'author': 'Naveed Gung',
        'github': 'https://github.com/naveed-gung',
        'portfolio': 'https://naveed-gung.dev',
        'purpose': 'EDUCATIONAL MALWARE ANALYSIS',
        'disclaimer': 'This API is for educational and authorized research only. Misuse is strictly prohibited.',
        'endpoints': {
            '/': 'Web interface',
            '/api/health': 'Health check',
            '/api/analyze': 'File analysis (POST with file)',
            '/api/yara/scan': 'YARA scan (POST with file and optional rules_path)',
            '/api/info': 'API information'
        }
    })


def start_server(host='127.0.0.1', port=5000, debug=False):
    """
    Start the Flask server
    
    Args:
        host: Host to bind to (default: localhost only for security)
        port: Port to listen on
        debug: Enable debug mode
    """
    print("="*70)
    print("E.MAT REST API Server")
    print("="*70)
    print(f"\n[#] ETHICAL Malware Analysis Toolkit - Web Service")
    print(f"\n[!] FOR EDUCATIONAL AND AUTHORIZED RESEARCH ONLY\n")
    print(f"Server starting on http://{host}:{port}")
    print(f"Web Interface: http://{host}:{port}/")
    print(f"API Docs: http://{host}:{port}/api/info")
    print(f"\nPress CTRL+C to stop the server\n")
    print("="*70 + "\n")
    
    app.run(host=host, port=port, debug=debug)


# Aliases expected by __main__.py
def run_server(port=5000):
    """Alias for start_server used by launcher"""
    start_server(port=port)
    return True

def stop_server():
    """Stop the server (placeholder - Flask doesn't support programmatic stop easily)"""
    print("To stop the server, press CTRL+C in the terminal where it's running.")
    return True


if __name__ == "__main__":
    start_server(debug=True)
