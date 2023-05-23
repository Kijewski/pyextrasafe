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
    def enable(self, *policy: list[RuleSet]) -> SafetyContext:
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

class BasicCapabilities(RuleSet):
    "Allow basic required syscalls to do things like allocate memory, and also a few that are used by Rust to set up panic handling and segfault handlers."
    def __init__(self) -> None: ...

class ForkAndExec(RuleSet):
    "Start another process, including more privileged ones. That process will still be under seccomp’s restrictions but depending on your filter it could still do bad things."
    def __init__(self) -> None: ...

class Networking(RuleSet):
    "Allows clone and sleep syscalls, which allow creating new threads and processes, and pausing them."
    def __init__(self) -> None:
        "By default, allow no networking syscalls."
    def allow_running_tcp_clients(self) -> Networking:
        "Allow a running TCP client to continue running. Does not allow socket or connect to prevent new sockets from being created."
    def allow_running_tcp_servers(self) -> Networking:
        "Allow a running TCP server to continue running. Does not allow socket or bind to prevent new sockets from being created."
    def allow_running_udp_sockets(self) -> Networking:
        "Allow a running UDP socket to continue running. Does not allow socket or bind to prevent new sockets from being created."
    def allow_running_unix_clients(self) -> Networking:
        "Allow a running Unix socket client to continue running. Does not allow socket or connect to prevent new sockets from being created."
    def allow_running_unix_servers(self) -> Networking:
        "Allow a running Unix server to continue running. Does not allow socket or bind to prevent new sockets from being created."
    def allow_start_tcp_clients(self) -> Networking:
        "Allow starting new TCP clients."
    def allow_start_tcp_servers(self) -> Networking:
        "Allow starting new TCP servers."
    def allow_start_udp_servers(self) -> Networking:
        "Allow starting new UDP sockets."
    def allow_start_unix_server(self) -> Networking:
        "Allow starting new Unix domain servers"

class SystemIO(RuleSet):
    "A RuleSet representing syscalls that perform IO - open/close/read/write/seek/stat."
    def __init__(self) -> None:
        "By default, allow no IO syscalls."
    def allow_close(self) -> SystemIO:
        "Allow close syscalls."
    def allow_file_read(self) -> SystemIO:
        "Allow read syscalls."
    def allow_file_write(self) -> SystemIO:
        "Allow write syscalls."
    def allow_ioctl(self) -> SystemIO:
        "Allow ioctl and fcntl syscalls."
    def allow_metadata(self) -> SystemIO:
        "Allow stat syscalls."
    def allow_open(self) -> SystemIO:
        "Allow open syscalls."
    def allow_open_readonly(self) -> SystemIO:
        "Allow open syscalls but not with write flags."
    def allow_read(self) -> SystemIO:
        "Allow read syscalls."
    def allow_stderr(self) -> SystemIO:
        "Allow writing to stderr"
    def allow_stdin(self) -> SystemIO:
        "Allow reading from stdin"
    def allow_stdout(self) -> SystemIO:
        "Allow writing to stdout"
    def allow_write(self) -> SystemIO:
        "Allow write syscalls."
    def allow_file_read(self, fileno: int) -> SystemIO:
        "Allow reading a given open File. Note that with just this function, you will not be able to close the file under this context."
    def allow_file_write(self, fileno: int) -> SystemIO:
        "Allow writing to a given open File. Note that with just this function, you will not be able to close the file under this context."

class Threads(RuleSet):
    "Allows clone and sleep syscalls, which allow creating new threads and processes, and pausing them."
    def __init__(self) -> None:
        "A new Threads ruleset allows nothing by default."
    def allow_create(self) -> Threads:
        "Allow creating new threads and processes."
    def allow_sleep(self) -> Threads:
        "Allow sleeping on the current thread"

class Time(RuleSet):
    "Enable syscalls related to time."
    def __init__(self) -> None:
        "A new Time RuleSet allows nothing by default."
    def allow_gettime(self) -> Time:
        "On most 64 bit systems glibc and musl both use the vDSO to compute the time directly with rdtsc rather than calling the clock_gettime syscall, so in most cases you don’t need to actually enable this."
