from pathlib import Path
import re

from setuptools import find_packages, setup

ROOT = Path(__file__).parent
version_text = (ROOT / "bla" / "__version__.py").read_text(encoding="utf-8")
version_match = re.search(r'^__version__ = ["\']([^"\']+)["\']', version_text, re.M)
if not version_match:
    raise RuntimeError("Unable to read package version from bla/__version__.py")
VERSION = version_match.group(1)

setup(
    name="blueteam-log-analyzer",
    version=VERSION,
    description="BlueTeam Log Analyzer - 蓝队应急响应日志分析工具",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Hackerchen716",
    url="https://github.com/Hackerchen716/blueteam-log-analyzer",
    python_requires=">=3.9",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "bla.rules": ["*.yaml", "*.yml"],
        "bla.output": ["assets/*.png", "assets/*.geojson"],
    },
    py_modules=["bla_cli"],
    entry_points={
        "console_scripts": [
            "bla=bla_cli:main",
        ],
    },
    install_requires=[],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
    ],
    keywords="blueteam, incident-response, log-analysis, security, SIEM, DFIR, threat-detection, remote-collection, ssh",
)
