"""
Setup script for OTCM Audit Sentinel
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="otcm-audit-sentinel",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="AI-Powered Security Analysis Tool for OpenText Content Manager",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/otcm-audit-sentinel",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "otcm-sentinel=src.interface.streamlit_app:main",
        ],
    },
)
