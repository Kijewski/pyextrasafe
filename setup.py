#!/usr/bin/env python3

from sys import version_info

from setuptools import setup
from setuptools_rust import RustExtension, Strip


if __name__ == "__main__":
    setup(
        rust_extensions=[
            RustExtension(
                "pyextrasafe._pyextrasafe",
                debug=False,
                strip=Strip.Debug,
                features=[f"pyo3/abi3-py{version_info[0]}{version_info[1]}"],
                py_limited_api=True,
            )
        ],
    )
