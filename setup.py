#!/usr/bin/env python3
from setuptools import setup
from uflash import get_version


with open("README.rst") as f:
    readme = f.read()
with open("CHANGES.rst") as f:
    changes = f.read()


setup(
    name="uflash",
    version=get_version(),
    description="A module and utility to flash Python onto the BBC micro:bit.",
    long_description=readme + "\n\n" + changes,
    author="Nicholas H.Tollervey",
    author_email="ntoll@ntoll.org",
    url="https://github.com/ntoll/uflash",
    packages=["uflash"],
    include_package_data=True,
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Education",
        "Topic :: Software Development :: Embedded Systems",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": ["uflash=uflash.uflash:main", "py2hex=uflash.uflash:py2hex"],
    },
)
