#!/usr/bin/env python3

from sys import version_info

from setuptools import setup
from setuptools_rust import RustExtension, Strip
from wheel.bdist_wheel import bdist_wheel


class bdist_wheel_abi3(bdist_wheel):
    def get_tag(self):
        python, abi, plat = super().get_tag()

        if python.startswith("cp"):
            # on CPython, our wheels are abi3 and compatible back to 3.7
            abi = "abi3"

        return python, abi, plat


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
        cmdclass={"bdist_wheel": bdist_wheel_abi3},
    )
