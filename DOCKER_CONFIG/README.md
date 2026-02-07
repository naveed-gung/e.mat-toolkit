# Docker Sandbox Usage Guide

## Building the Sandbox

```bash
cd DOCKER_CONFIG
docker-compose build
```

## Running Analysis in Sandbox

### Basic Analysis
```bash
# Place sample in DOCKER_CONFIG/samples/
docker-compose run --rm emat-sandbox python -m emat analyze /analysis/samples/yourfile.exe
```

### With Results Output
```bash
docker-compose run --rm emat-sandbox python -m emat analyze /analysis/samples/yourfile.exe --json > results/report.json
```

## Security Features

- **Network Isolation**: `network_mode: none` - No network access
- **Resource Limits**: 2GB RAM, 1 CPU core
- **Read-Only Filesystem**: Prevents file system modifications
- **No New Privileges**: Prevents privilege escalation
- **Temporary Filesystem**: Only /tmp is writable

## Important Notes

⚠️ **EDUCATIONAL USE ONLY**
- This sandbox is for educational malware analysis
- Always use with explicit consent and authorization
- Never analyze files you don't have permission to analyze

## Author

Naveed Gung
- GitHub: https://github.com/naveed-gung
- Portfolio: https://naveed-gung.dev
