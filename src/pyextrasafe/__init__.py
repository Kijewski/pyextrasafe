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
PyExtraSafe is a library that makes it easy to improve your program’s security by selectively
allowing the syscalls it can perform via the Linux kernel’s seccomp facilities.
"""

from pyextrasafe._pyextrasafe import (
    __author__,
    __license__,
    __version__,
    ExtraSafeError,
    RuleSet,
    SafetyContext,
    BasicCapabilities,
    ForkAndExec,
    Networking,
    SystemIO,
    Threads,
    Time,
    # Compare,
    # CompareOp,
    # Custom,
    # Rule,
    lock_pid_file,
    restrict_privileges,
)


__all__ = [
    "ExtraSafeError",
    "RuleSet",
    "SafetyContext",
    "BasicCapabilities",
    "ForkAndExec",
    "Networking",
    "SystemIO",
    "Threads",
    "Time",
    # "Compare",
    # "CompareOp",
    # "Custom",
    # "Rule",
    "lock_pid_file",
    "restrict_privileges",
]
