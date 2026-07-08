from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vision-cli",
    version="4.1.0",
    author="VISION",
    description="Advanced Cybercrime Stopper - Scan for leaked secrets, morph images, and more.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vision-cli",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "requests>=2.28.0"
    ],
    entry_points={
        "console_scripts": [
            "vision-cli=vision_cli.cli:main",
        ],
    },
)
