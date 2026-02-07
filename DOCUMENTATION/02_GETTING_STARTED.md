# Getting Started with E-MAT

This guide will help you set up and start using the ETHICAL Malware Analysis Toolkit.

## Prerequisites

- **Python 3.8+** - [Download Python](https://www.python.org/downloads/)
- **Git** (optional) - For cloning the repository
- **Docker** (optional) - Required only for dynamic analysis features

## Installation

### Step 1: Clone and Navigate to the Project

```bash
git clone https://github.com/naveed-gung/emat-toolkit.git
cd emat-toolkit
```

### Step 2: Create Virtual Environment

**On Windows (Git Bash/MINGW64):**
```bash
# Run the setup script
./setup_venv.sh

# Or manually:
python -m venv venv
source venv/Scripts/activate
```

**On Windows (CMD/PowerShell):**
```cmd
# Run the setup script
setup_venv.bat

# Or manually:
python -m venv venv
venv\Scripts\activate
```

**On Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note**: Some dependencies (like `python-magic`) may require additional system libraries. See [Troubleshooting](#troubleshooting) below.

### Step 4: First-Time Setup

```bash
python -m emat setup
```

This interactive setup will:
1. Display the ethical pledge (please read carefully!)
2. Ask you to choose your preferred component (CLI/Desktop/Server)
3. Check for Docker installation
4. Save your preferences to `~/.emat/config.json`
5. Show you a personalized quick start guide

## Quick Start

### CLI Tool (Recommended for Beginners)

**Analyze a file:**
```bash
python -m emat analyze <file>
```

**Example - Analyze this Python file:**
```bash
python -m emat analyze __main__.py
```

**Output in JSON format:**
```bash
python -m emat analyze <file> --json
```

**Compare two files:**
```bash
python -m emat compare <file1> <file2>
```

### Desktop GUI

```bash
python -m emat desktop
```

> **Note**: Desktop GUI will be fully implemented in Phase 2. For now, use the CLI tool.

### Web Server

```bash
python -m emat server --start --port 8080
```

> **Note**: Web server will be fully implemented in Phase 3. For now, use the CLI tool.

## Configuration

### View Current Configuration

```bash
python -m emat config --show
```

### Change Preferred Component

```bash
python -m emat config --set-component cli
python -m emat config --set-component desktop
python -m emat config --set-component server
```

### Configuration File

Your preferences are stored in:
- **Windows**: `C:\Users\<username>\.emat\config.json`
- **Linux/Mac**: `~/.emat/config.json`

## Usage Examples

### Example 1: Analyze a Windows Executable

```bash
python -m emat analyze /path/to/program.exe
```

This will:
- Calculate file hashes (MD5, SHA1, SHA256, SHA512)
- Determine file type via magic bytes
- Calculate entropy (detect packing/compression)
- Provide educational assessment

### Example 2: Compare Two Versions of a File

```bash
python -m emat compare original.exe modified.exe
```

This will show:
- Hash comparison
- Size differences
- Entropy differences

### Example 3: Export Analysis to JSON

```bash
python -m emat analyze sample.exe --json > analysis.json
```

## Safety Features

### Static Analysis Only (Default)

By default, E-MAT performs **static-only** analysis:
- No code execution
- Safe for any file
- Fast and efficient

### Dynamic Analysis (Advanced)

> [!CAUTION]
> Dynamic analysis executes files in an isolated Docker container. Only use with explicit consent and proper authorization.

```bash
python -m emat analyze <file> --safe-sandbox
```

Requirements:
- Docker must be installed and running
- Explicit `--safe-sandbox` flag required
- Container runs with `--network=none` (no internet access)

## Troubleshooting

### Python Not Found

Ensure Python 3.8+ is installed and in your PATH:
```bash
python --version
```

### Virtual Environment Activation Issues

**Windows Git Bash:**
```bash
source venv/Scripts/activate
```

**Windows CMD:**
```cmd
venv\Scripts\activate.bat
```

**Windows PowerShell:**
```powershell
venv\Scripts\Activate.ps1
```

If PowerShell gives an error about execution policy:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Missing Dependencies

Some libraries require system packages:

**python-magic on Windows:**
```bash
pip install python-magic-bin
```

**python-magic on Linux:**
```bash
sudo apt-get install libmagic1
pip install python-magic
```

**SSDEEP (optional):**
```bash
# Windows: Download from https://github.com/ssdeep-project/ssdeep/releases
# Linux:
sudo apt-get install libfuzzy-dev
pip install ssdeep
```

### Docker Not Detected

If you want to use dynamic analysis:
1. Install Docker Desktop (Windows/Mac) or Docker Engine (Linux)
2. Ensure Docker is running: `docker ps`
3. Re-run setup: `python -m emat setup`

## Next Steps

1. **Read the Ethical Guidelines**: [ETHICAL_PLEDGE.md](../ETHICAL_PLEDGE.md)
2. **Review Safety Protocols**: [03_SAFETY_PROTOCOLS.md](03_SAFETY_PROTOCOLS.md)
3. **Try the Tutorials**: [04_EDUCATIONAL_TUTORIALS.md](04_EDUCATIONAL_TUTORIALS.md)
4. **Analyze Safe Samples**: Check `TESTS/safe_samples/` directory

## Getting Help

- **Documentation**: See `DOCUMENTATION/` folder
- **Issues**: Report bugs or request features on GitHub
- **Author**: Naveed Gung
  - GitHub: [naveed-gung](https://github.com/naveed-gung)
  - Portfolio: [naveed-gung.dev](https://naveed-gung.dev)

## Ethical Reminder

> [!IMPORTANT]
> E-MAT is for **educational and authorized security research only**. Always ensure you have proper authorization before analyzing files. Misuse may violate laws and result in criminal prosecution.

---

**Happy (ethical) analyzing! 🛡️**
