from setuptools import setup, find_packages

setup(
    name="cybersec-tools",
    version="1.0.0",
    description="Cybersecurity CLI Tools Collection",
    author="CyberSec Tools",
    py_modules=["cybersec"],
    install_requires=[
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "python-whois>=0.9.4",
        "beautifulsoup4>=4.12.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "tqdm>=4.66.0",
        "urllib3>=2.1.0",
    ],
    entry_points={
        "console_scripts": [
            "cybersec=cybersec:main",
        ],
    },
    python_requires=">=3.8",
)
