from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="e.mat-toolkit",
    version="1.0.0",
    author="Naveed Gung",
    author_email="contact@naveed-gung.dev",
    description="ETHICAL Malware Analysis Toolkit - Educational cybersecurity analysis framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/naveed-gung/e.mat-toolkit",
    project_urls={
        "Bug Tracker": "https://github.com/naveed-gung/e.mat-toolkit/issues",
        "Documentation": "https://github.com/naveed-gung/e.mat-toolkit/blob/main/DOCUMENTATION/02_GETTING_STARTED.md",
        "Portfolio": "https://naveed-gung.dev",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "emat=emat:main",
        ],
    },
    include_package_data=True,
    keywords="malware analysis security education ethical cybersecurity",
    license="MIT",
)
