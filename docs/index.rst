PyExtraSafe
===========

.. |GitHub Workflow Status| image:: https://img.shields.io/github/actions/workflow/status/Kijewski/pyextrasafe/ci.yml?branch=main&logo=github&logoColor=efefef&style=flat-square
   :target: https://github.com/Kijewski/pyextrasafe/actions/workflows/ci.yml
.. |Documentation Status| image:: https://img.shields.io/readthedocs/pyextrasafe?logo=readthedocs&logoColor=efefef&style=flat-square
   :target: https://pyextrasafe.readthedocs.io/
.. |PyPI| image:: https://img.shields.io/pypi/v/pyextrasafe?logo=pypi&logoColor=efefef&style=flat-square
   :target: https://pypi.org/project/pyextrasafe/
.. |Python >= 3.7| image:: https://img.shields.io/badge/python-%E2%89%A5%203.7-informational?logo=python&logoColor=efefef&style=flat-square
   :target: https://www.python.org/
.. |OS: Linux| image:: https://img.shields.io/badge/os-linux-informational?logo=linux&logoColor=efefef&style=flat-square
   :target: https://kernel.org/
.. |License| image:: https://img.shields.io/badge/license-Apache--2.0-informational?logo=apache&logoColor=efefef&style=flat-square
   :target: /LICENSE.md

|GitHub Workflow Status|
|Documentation Status|
|PyPI|
|Python >= 3.7|
|OS: Linux|
|License|

.. automodule:: pyextrasafe

.. autoclass:: pyextrasafe.SafetyContext
    :members:

.. autoexception:: pyextrasafe.ExtraSafeError

Built-in profiles
-----------------

.. autoclass:: pyextrasafe.RuleSet
    :members:

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
