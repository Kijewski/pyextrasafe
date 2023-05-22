# PyExtraSafe

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/Kijewski/pyextrasafe/ci.yml?branch=main&logo=github&logoColor=efefef&style=flat-square)](https://github.com/Kijewski/pyextrasafe/actions/workflows/ci.yml)
[![Documentation Status](https://img.shields.io/readthedocs/pyextrasafe?logo=readthedocs&logoColor=efefef&style=flat-square)](https://pyextrasafe.readthedocs.io/)
[![PyPI](https://img.shields.io/pypi/v/pyextrasafe?logo=pypi&logoColor=efefef&style=flat-square)](https://pypi.org/project/pyextrasafe/)
[![Python >= 3.7](https://img.shields.io/badge/python-%E2%89%A5%203.7-informational?logo=python&logoColor=efefef&style=flat-square)](https://www.python.org/)
[![OS: Linux](https://img.shields.io/badge/os-linux-informational?logo=linux&logoColor=efefef&style=flat-square)](https://www.kernel.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-informational?logo=apache&logoColor=efefef&style=flat-square)](/LICENSE.md)

PyExtraSafe is a library that makes it easy to improve your program’s security by selectively
allowing the syscalls it can perform via the Linux kernel’s seccomp facilities.

The python library is a shallow wrapper around [extrasafe](https://docs.rs/extrasafe/0.1.2/extrasafe/index.html).
