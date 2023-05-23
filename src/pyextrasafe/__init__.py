# Copyright (c) 2023 René Kijewski <pypi.org@k6i.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

"""
PyExtraSafe
===========

.. |GitHub Workflow Status| image:: https://img.shields.io/github/actions/workflow/status/Kijewski/pyextrasafe/ci.yml?branch=main&logo=github&logoColor=efefef&style=flat-square
   :target: https://github.com/Kijewski/pyextrasafe/actions/workflows/ci.yml
.. |Documentation Status| image:: https://img.shields.io/readthedocs/pyextrasafe?logo=readthedocs&logoColor=efefef&style=flat-square
   :target: https://pyextrasafe.readthedocs.io/
.. |PyPI| image:: https://img.shields.io/pypi/v/pyextrasafe?logo=pypi&logoColor=efefef&style=flat-square
   :target: https://pypi.org/project/pyextrasafe/
.. |Python >= 3.8| image:: https://img.shields.io/badge/python-%E2%89%A5%203.8-informational?logo=python&logoColor=efefef&style=flat-square
   :target: https://www.python.org/
.. |OS: Linux| image:: https://img.shields.io/badge/os-linux-informational?logo=linux&logoColor=efefef&style=flat-square
   :target: https://kernel.org/
.. |License| image:: https://img.shields.io/badge/license-Apache--2.0-informational?logo=apache&logoColor=efefef&style=flat-square
   :target: https://github.com/Kijewski/pyextrasafe/blob/main/LICENSE.md

|GitHub Workflow Status|
|Documentation Status|
|PyPI|
|Python >= 3.8|
|OS: Linux|
|License|

PyExtraSafe is a library that makes it easy to improve your program’s security by selectively
allowing the syscalls it can perform via the Linux kernel’s seccomp facilities.

The Python library is a shallow wrapper around `extrasafe <https://docs.rs/extrasafe/0.1.2/extrasafe/index.html>`_.

Quick Example
-------------

.. code-block:: python

    from threading import Thread
    import pyextrasafe

    try:
        thread = Thread(target=print, args=["Hello, world!"])
        thread.start()
        thread.join()
    except Exception:
        print("Could not run Thread (should have been able!)")

    pyextrasafe.SafetyContext().enable(
        pyextrasafe.BasicCapabilities(),
        pyextrasafe.SystemIO().allow_stdout().allow_stderr(),
    ).apply_to_all_threads()

    try:
        thread = Thread(target=print, args=["Hello, world!"])
        thread.start()
        thread.join()
    except Exception:
        print("Could not run Thread (that's good!)")
    else:
        raise Exception("Should not have been able to run thread")

Classes
-------

.. autoclass:: pyextrasafe.SafetyContext
    :members:

.. autoclass:: pyextrasafe.RuleSet
    :members:

.. autoexception:: pyextrasafe.ExtraSafeError

Built-in profiles
-----------------

All built-in profiles inherit from :class:`~pyextrasafe.RuleSet`.
Adding custom profiles is not implemented, yet.

All methods return :code:`self`\, so method calls can be chained.

.. autoclass:: pyextrasafe.BasicCapabilities
    :members:

.. autoclass:: pyextrasafe.ForkAndExec
    :members:

.. autoclass:: pyextrasafe.Threads
    :members:

.. autoclass:: pyextrasafe.Networking
    :members:

.. autoclass:: pyextrasafe.SystemIO
    :members:

.. autoclass:: pyextrasafe.Time
    :members:
"""

from pyextrasafe._pyextrasafe import (
    __author__,
    __license__,
    __version__,
    BasicCapabilities,
    ExtraSafeError,
    ForkAndExec,
    Networking,
    RuleSet,
    SafetyContext,
    SystemIO,
    Threads,
    Time,
)


__all__ = [
    "BasicCapabilities",
    "ExtraSafeError",
    "ForkAndExec",
    "RuleSet",
    "SafetyContext",
    "Threads",
    "Networking",
    "SystemIO",
    "Time",
]
