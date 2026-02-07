# E-MAT - Quick Reference Card

## 🚀 Quick Start

```bash
# Activate venv
source venv/Scripts/activate  # Git Bash
venv\Scripts\activate         # CMD

# Install dependencies
pip install -r requirements.txt

# First-time setup
python emat.py setup

# Analyze a file
python emat.py analyze <file>
```

## 📋 Common Commands

### CLI
```bash
# Static analysis
python emat.py analyze sample.exe

# JSON output
python emat.py analyze sample.exe --json > report.json

# Compare files
python emat.py compare file1.exe file2.exe

# YARA scan
python emat.py yara sample.exe --rules DATA/yara_rules/

# View config
python emat.py config --show

# Change component
python emat.py config --set-component cli
```

### Desktop GUI
```bash
python emat.py desktop
```

### Web Server
```bash
python emat.py server --start --port 5000
# Access: http://localhost:5000
```

## 📁 Project Structure

```
e-mat-toolkit/
├── CORE_ENGINE/        # Analysis engine
├── CLI_TOOL/           # CLI commands
├── DESKTOP_APP/        # PyQt6 GUI
├── WEB_SERVICE/        # Flask API
├── DOCKER_CONFIG/      # Sandbox config
├── DATA/               # YARA rules
├── DOCUMENTATION/      # Guides
└── TESTS/              # Tests & samples
```

## 🎯 Key Features

- **3 Interfaces**: CLI, Desktop, Web
- **PE/ELF Analysis**: Full binary analysis
- **String Extraction**: Categorized strings
- **YARA Scanning**: Default + custom rules
- **Safety First**: Static-only by default
- **Educational**: Learning topics & context

## 👤 Author

**Naveed Gung**
- GitHub: [@naveed-gung](https://github.com/naveed-gung)
- Portfolio: [naveed-gung.dev](https://naveed-gung.dev)

## ⚠️ Ethics

**FOR EDUCATIONAL USE ONLY**
- Only analyze authorized files
- Never use for malicious purposes
- Report findings properly

---

**E-MAT v1.0 - ETHICAL Malware Analysis Toolkit**
