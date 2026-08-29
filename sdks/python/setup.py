from setuptools import setup, find_packages

setup(
    name="docutrust",
    version="2.1.1",
    description="Python SDK for DocuTrust Sovereign Verifiable Credentials",
    author="DocuTrust Contributors",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "cryptography>=41.0.0"
    ],
    python_requires=">=3.8",
)
