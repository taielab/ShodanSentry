from setuptools import setup, find_packages

setup(
    name="shodansentry",
    version="1.0.0",
    description="An advanced security tool for scanning and analyzing vulnerabilities using Shodan and NVD APIs",
    author="TaieLab",
    packages=find_packages(),
    install_requires=[
        "shodan>=1.28.0",
        "requests>=2.28.0",
        "pyyaml>=6.0",
        "translate>=3.6.1",
        "googletrans==3.1.0a0",  # 使用alpha版本以避免兼容性问题
        "translators>=5.7.0",
        "diskcache>=5.4.0",
        "ratelimit>=2.2.1"
    ],
    python_requires=">=3.7",
    entry_points={
        'console_scripts': [
            'shodansentry=cve_stats:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
)