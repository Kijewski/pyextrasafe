from typing import NewType

Rule = NewType("Rule", list[str])
Sysno = NewType("Sysno", int)

__author__: str
__license__: str
__version__: str

class ExtraSafeError(Exception):
    "An exception thrown by PyExtraSafe."

class SafetyContext:
    "A struct representing a set of rules to be loaded into a seccomp filter and applied to the current thread, or all threads in the current process."

    def __init__(self) -> None:
        "Create a new SafetyContext. The seccomp filters will not be loaded until either apply_to_current_thread() or apply_to_all_threads() is called."
    def apply_to_all_threads(self) -> None:
        "Load the SafetyContext’s rules into a seccomp filter and apply the filter to all threads in this process."
    def apply_to_current_thread(self) -> None:
        "Load the SafetyContext’s rules into a seccomp filter and apply the filter to the current thread."
    def enable(self, policy: RuleSet) -> SafetyContext:
        "Enable the simple and conditional rules provided by the RuleSet."

class RuleSet:
    "A RuleSet is a collection of seccomp rules that enable a functionality."

    @property
    def simple_rules(self) -> list[int]:
        "A simple rule is one that just allows the syscall without restriction."
    @property
    def conditional_rules(self) -> list[(Sysno, list[Rule])]:
        "A conditional rule is a rule that uses a condition to restrict the syscall, e.g. only specific flags as parameters."
    @property
    def name(self) -> str:
        "The name of the profile."

# TODO: Doc
class BasicCapabilities(RuleSet):
    # TODO: Doc
    def __init__(self) -> None: ...

# TODO: Doc
class ForkAndExec(RuleSet):
    # TODO: Doc
    def __init__(self) -> None: ...

# TODO: Doc
class Networking(RuleSet):
    # TODO: Doc
    def __init__(self) -> None: ...

    # TODO: Doc
    def allow_running_tcp_clients(self) -> Networking: ...

    # TODO: Doc
    def allow_running_tcp_servers(self) -> Networking: ...

    # TODO: Doc
    def allow_running_udp_sockets(self) -> Networking: ...

    # TODO: Doc
    def allow_running_unix_clients(self) -> Networking: ...

    # TODO: Doc
    def allow_running_unix_servers(self) -> Networking: ...

    # TODO: Doc...
    def allow_start_tcp_clients(self) -> Networking: ...

    # TODO: Doc
    def allow_start_tcp_servers(self) -> Networking: ...

    # TODO: Doc
    def allow_start_udp_servers(self) -> Networking: ...

    # TODO: Doc
    def allow_start_unix_server(self) -> Networking: ...

# TODO: Doc
class SystemIO(RuleSet):
    # TODO: Doc
    def __init__(self) -> None: ...

    # TODO: Doc
    def allow_close(self) -> SystemIO: ...

    # TODO: Doc
    def allow_file_read(self) -> SystemIO: ...

    # TODO: Doc
    def allow_file_write(self) -> SystemIO: ...

    # TODO: Doc
    def allow_ioctl(self) -> SystemIO: ...

    # TODO: Doc
    def allow_metadata(self) -> SystemIO: ...

    # TODO: Doc
    def allow_open(self) -> SystemIO: ...

    # TODO: Doc
    def allow_open_readonly(self) -> SystemIO: ...

    # TODO: Doc
    def allow_read(self) -> SystemIO: ...

    # TODO: Doc
    def allow_stderr(self) -> SystemIO: ...

    # TODO: Doc
    def allow_stdin(self) -> SystemIO: ...

    # TODO: Doc
    def allow_stdout(self) -> SystemIO: ...

    # TODO: Doc
    def allow_write(self) -> SystemIO: ...

# TODO: Doc
class Threads(RuleSet):
    # TODO: Doc
    def __init__(self) -> None: ...

    # TODO: Doc
    def allow_create(self) -> Threads: ...

    # TODO: Doc
    def allow_sleep(self) -> Threads: ...

# TODO: Doc
class Time(RuleSet):
    # TODO: Doc
    def __init__(self) -> None: ...

    # TODO: Doc
    def allow_gettime(self) -> Time: ...
