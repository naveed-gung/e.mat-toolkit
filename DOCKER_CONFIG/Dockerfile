# E-MAT Docker Configuration
# Isolated sandbox for dynamic analysis

FROM python:3.11-slim

# Set working directory
WORKDIR /emat

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libfuzzy-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install only core dependencies
# The sed command extracts lines between [core] and [desktop] markers
COPY requirements.txt .
RUN pip install --no-cache-dir \
    pefile yara-python pyelftools oletools pdfminer.six capstone \
    python-magic docker scikit-learn requests colorama tabulate click Jinja2

# Copy E-MAT toolkit source
COPY CORE_ENGINE/ /emat/CORE_ENGINE/
COPY CLI_TOOL/ /emat/CLI_TOOL/
COPY DATA/ /emat/DATA/
COPY emat.py __main__.py /emat/

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV EMAT_DOCKER=1

# Create analysis directories
RUN mkdir -p /analysis/samples /analysis/results

# Default command
CMD ["python", "emat.py", "--help"]
