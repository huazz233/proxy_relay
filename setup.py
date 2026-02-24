#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="proxy-relay",
    version="1.3.0",
    author="huazz233",
    author_email="huazz233@163.com",
    description="多协议代理中转器，支持HTTP/HTTPS/SOCKS5/SOCKS5H协议互转，本地代理无需账密认证",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/huazz233/proxy_relay",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: Proxy Servers",
    ],
    python_requires=">=3.7",
    install_requires=[],
    extras_require={
        "dev": [
            "requests>=2.25.0",
        ],
    },
)

