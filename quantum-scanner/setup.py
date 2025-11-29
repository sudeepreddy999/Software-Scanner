"""
Setup script for Quantum Vulnerability Scanner
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name='quantum-vulnerability-scanner',
    version='1.0.0',
    description='A security scanner for detecting quantum-vulnerable cryptographic algorithms',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Security Scanner Team',
    author_email='security@example.com',
    url='https://github.com/yourusername/quantum-vulnerability-scanner',
    packages=find_packages(),
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'quantum-scan=src.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Quality Assurance',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'License :: OSI Approved :: MIT License',
    ],
    python_requires='>=3.8',
    include_package_data=True,
    package_data={
        'src': ['../config/*.yaml'],
    },
)
