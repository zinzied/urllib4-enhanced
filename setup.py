#!/usr/bin/env python

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="urllib4-enhanced",
    version="1.1.1",
    description="A modern HTTP client for Python with HTTP/3, WebSocket extensions, and enhanced security features",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Zied Boughdir",
    author_email="ziedboughdir@gmail.com",
    url="https://github.com/zinzied/urllib4",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries",
    ],
    python_requires=">=3.7",
    install_requires=[
        "idna>=2.0.0",
        "certifi",
    ],
    extras_require={
        "http2": ["h2>=4.0.0"],
        "http3": ["aioquic>=0.9.20", "netifaces>=0.11.0"],
        "websocket": ["msgpack>=1.0.4", "cbor2>=5.4.6"],
        "brotli": ["brotli>=1.0.9"],
        "zstd": ["zstandard>=0.18.0"],
        "socks": ["pysocks>=1.7.1"],
        "all": [
            "h2>=4.0.0",
            "aioquic>=0.9.20",
            "netifaces>=0.11.0",
            "msgpack>=1.0.4",
            "cbor2>=5.4.6",
            "brotli>=1.0.9",
            "zstandard>=0.18.0",
            "pysocks>=1.7.1",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
    },
    project_urls={
        "Bug Tracker": "https://github.com/zinzied/urllib4/issues",
        "Documentation": "https://github.com/zinzied/urllib4",
        "Source Code": "https://github.com/zinzied/urllib4",
    },
)
