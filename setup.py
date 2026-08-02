from setuptools import setup, find_packages

with open("cybermesh_sdk/README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cybermesh-sdk",
    version="1.0.0",
    author="Kartikey Gupta",
    author_email="kartikey@example.com",
    description="Zero-Trust Identity and DPoP SDK for CyberMesh",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Kartikey-97/CyberMesh",
    packages=["cybermesh_sdk"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
    install_requires=[
        "cryptography>=41.0.0",
        "PyJWT>=2.8.0",
        "httpx>=0.24.0",
        "fastapi>=0.100.0"
    ],
)
