# E.MAT Usage Examples

This file demonstrates how to use the ETHICAL Malware Analysis Toolkit.

## Prerequisites

E.MAT automatically activates the virtual environment when you run it. Simply ensure you have Python 3.8+ installed:

```bash
cd e.mat-toolkit
# No need to manually activate venv - it happens automatically!
```

## First-Time Setup

Run the setup wizard (only needed once):
```bash
python emat.py setup
```

This will:
1. Display the ethical pledge
2. Ask you to choose your preferred component (CLI/Desktop/Server)
3. Check for Docker
4. Save your preferences

## Basic Usage

### Analyze a File

```bash
python emat.py analyze <file>
```

Example:
```bash
python emat.py analyze README.md
```

Output includes:
- File hashes (MD5, SHA1, SHA256, SHA512)
- File type and MIME type
- Entropy analysis
- Educational assessment
- Suggested learning topics

### Analyze with JSON Output

```bash
python emat.py analyze README.md --json
```

Save to file:
```bash
python emat.py analyze README.md --json > analysis.json
```

### Compare Two Files

```bash
python emat.py compare file1.txt file2.txt
```

Shows:
- Hash comparison
- Size differences
- Entropy differences

### View Configuration

```bash
python emat.py config --show
```

### Change Preferred Component

```bash
python emat.py config --set-component cli
python emat.py config --set-component desktop
python emat.py config --set-component server
```

## Advanced Usage (Future Phases)

### YARA Scanning (Phase 2)

```bash
python emat.py yara <file> --rules DATA/yara_rules/
```

### Sandboxed Analysis (Phase 3)

```bash
python emat.py analyze <file> --safe-sandbox
```

Requires:
- Docker installed and running
- Explicit `--safe-sandbox` flag
- File will execute in isolated container with no network access

### Desktop GUI (Phase 2)

```bash
python emat.py desktop
```

### Web Server (Phase 3)

```bash
python emat.py server --start --port 8080
```

## Testing with Safe Samples

Test the toolkit with harmless files:

```bash
# Analyze a text file
python emat.py analyze README.md

# Analyze a Python script
python emat.py analyze emat.py

# Compare two versions
python emat.py compare README.md ETHICAL_PLEDGE.md
```

## Configuration File

Your preferences are saved in:
- Windows: `C:\Users\<username>\.emat\config.json`
- Linux/Mac: `~/.emat/config.json`

You can manually edit this file or use the `config` command.

## Ethical Reminders

✅ **DO:**
- Use for educational purposes
- Analyze files you have permission to analyze
- Learn defensive security concepts
- Report findings through proper channels

❌ **DON'T:**
- Analyze files without authorization
- Use for malicious purposes
- Share real malware samples
- Violate laws or regulations

## Getting Help

- Read the documentation in `DOCUMENTATION/`
- Check `ETHICAL_PLEDGE.md` for guidelines
- Review `02_GETTING_STARTED.md` for detailed instructions

## Author

**Naveed Gung**
- GitHub: [@naveed-gung](https://github.com/naveed-gung)
- Portfolio: [naveed-gung.dev](https://naveed-gung.dev)

---

**Happy (ethical) analyzing! 🛡️**
