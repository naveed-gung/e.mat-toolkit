# Safe Sample Files for Testing

This directory contains safe files for testing E-MAT functionality:

## EICAR Test File

`eicar.txt` - Standard antivirus test file
- **NOT MALWARE** - This is a universally recognized test file
- Used by antivirus vendors to test detection
- Safe to use for educational testing
- More info: https://www.eicar.org/

## Usage

Test E-MAT with these safe samples:

```bash
# Analyze EICAR file
python emat.py analyze TESTS/safe_samples/eicar.txt

# YARA scan
python emat.py yara TESTS/safe_samples/eicar.txt --rules DATA/yara_rules/

# Compare files
python emat.py compare TESTS/safe_samples/eicar.txt README.md
```

## Adding More Samples

You can add your own safe test files here:
- Benign executables
- Text files with test strings
- PDF documents
- Office documents

**⚠️ NEVER add real malware to this directory**

## Author

Naveed Gung
- GitHub: https://github.com/naveed-gung
- Portfolio: https://naveed-gung.dev
