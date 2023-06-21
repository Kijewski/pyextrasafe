:tocdepth: 3
:hide-navigation:
:hide-footer:

.. py:currentmodule:: pyextrasafe

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
   :target: https://github.com/Kijewski/pyextrasafe/blob/main/LICENSE.md

|GitHub Workflow Status|
|Documentation Status|
|PyPI|
|Python >= 3.7|
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

.. py:class:: SafetyContext
    :final:

    A struct representing a set of rules to be loaded into a seccomp filter and applied to the
    current thread, or all threads in the current process.

    The seccomp filters will not be loaded until either :meth:`apply_to_current_thread` or
    :meth:`apply_to_all_threads` is called.

    .. seealso::

        Struct `extrasafe::SafetyContext <https://docs.rs/extrasafe/0.1.2/extrasafe/struct.SafetyContext.html>`_

    .. py:method:: enable(*policies: list[RuleSet]) -> SafetyContext

        Enable the simple and conditional rules provided by the :class:`~pyextrasafe.RuleSet`.

        :param policies: :class:`~pyextrasafe.RuleSet`\s to enable.

        :return: This self object itself, so :meth:`enable()` can be chained.

        :raise TypeError: Argument was not an instance of :class:`~pyextrasafe.RuleSet`\.

    .. py:method:: apply_to_current_thread() -> None

        Load the :class:`~pyextrasafe.SafetyContext`\’s rules into a seccomp filter and apply the filter to the current thread.

        :raise ExtraSafeError: Could not apply policies.

    .. py:method:: apply_to_all_threads() -> None

        Load the :func:`~pyextrasafe.SafetyContext`\’s rules into a seccomp filter and apply the
        filter to all threads in this process.

        :raise ExtraSafeError: Could not apply policies.

.. py:class:: RuleSet

    A RuleSet is a collection of seccomp rules that enable a functionality.

    .. .. seealso::
       Trait `extrasafe::RuleSet <https://docs.rs/extrasafe/0.1.2/extrasafe/trait.RuleSet.html>`_

.. py:exception:: ExtraSafeError

    An exception thrown by PyExtraSafe.

Built-in profiles
-----------------

All built-in profiles inherit from :class:`~pyextrasafe.RuleSet`.
All methods return :code:`self`\, so calls can be chained.

.. inheritance-diagram::
    pyextrasafe.BasicCapabilities
    pyextrasafe.ForkAndExec
    pyextrasafe.Networking
    pyextrasafe.SystemIO
    pyextrasafe.Threads
    pyextrasafe.Time
    :parts: 1

..

    pyextrasafe.Custom

.. py:class:: BasicCapabilities
    :final:

    A :class:`~pyextrasafe.RuleSet` allowing basic required syscalls to do things like allocate memory,
    and also a few that are used by Rust to set up panic handling and segfault handlers.

    .. seealso::

        Trait `extrasafe::builtins::basic::BasicCapabilities
        <https://docs.rs/extrasafe/0.1.2/extrasafe/builtins/basic/struct.BasicCapabilities.html>`_

.. class:: ForkAndExec
    :final:

    ForkAndExec is in the danger zone because it can be used to start another process, including
    more privileged ones. That process will still be under seccomp’s restrictions but depending
    on your filter it could still do bad things.

    .. seealso::

        Struct `extrasafe::builtins::danger_zone::ForkAndExec
        <https://docs.rs/extrasafe/0.1.2/extrasafe/builtins/danger_zone/struct.ForkAndExec.html>`_

.. class:: Networking
    :final:

    A :class:`~pyextrasafe.RuleSet` representing syscalls that perform network operations - accept/listen/bind/connect etc.

    By default, allow no networking syscalls.

    .. seealso::

        Struct `extrasafe::builtins::network::Networking
        <https://docs.rs/extrasafe/0.1.2/extrasafe/builtins/network/struct.Networking.html>`_

    .. py:method:: allow_running_tcp_clients() -> Networking

        Allow a running TCP client to continue running.
        Does not allow socket or connect to prevent new sockets from being created.

    .. py:method:: allow_running_tcp_servers() -> Networking

        Allow a running TCP server to continue running.
        Does not allow socket or bind to prevent new sockets from being created.

    .. py:method:: allow_running_udp_sockets() -> Networking

        Allow a running UDP socket to continue running.
        Does not allow socket or bind to prevent new sockets from being created.

    .. py:method:: allow_running_unix_clients() -> Networking

        Allow a running Unix socket client to continue running.
        Does not allow socket or connect to prevent new sockets from being created.

    .. py:method:: allow_running_unix_servers() -> Networking

        Allow a running Unix server to continue running.
        Does not allow socket or bind to prevent new sockets from being created.

    .. py:method:: allow_start_tcp_clients() -> Networking

        Allow starting new TCP clients.

        .. warning::

            In some cases you can create the socket ahead of time, but in case it is not,
            we allow socket but not bind here.

    .. py:method:: allow_start_tcp_servers() -> Networking

        Allow starting new TCP servers.

        .. warning::

            You probably don’t need to use this. In most cases you can just run your server
            and then use :meth:`allow_running_tcp_servers`\.

    .. py:method:: allow_start_udp_servers() -> Networking

        Allow starting new UDP sockets.

        .. warning::

            You probably don’t need to use this. In most cases you can just run your server
            and then use :meth:`allow_running_udp_sockets`\.

    .. py:method:: allow_start_unix_servers() -> Networking

        Allow starting new Unix domain servers

        .. warning::

            You probably don’t need to use this. In most cases you can just run your server
            and then use :meth:`allow_running_unix_servers`\.

.. class:: SystemIO
    :final:

    A :class:`~pyextrasafe.RuleSet` representing syscalls that perform IO - open/close/read/write/seek/stat.

    By default, allow no IO syscalls.

    .. seealso::

        Struct `extrasafe::builtins::systemio::SystemIO
        <https://docs.rs/extrasafe/0.1.2/extrasafe/builtins/systemio/struct.SystemIO.html>`_

    .. py:method:: everything() -> SystemIO
        :staticmethod:

        Allow all IO syscalls.

    .. py:method:: allow_close() -> SystemIO

        Allow close syscalls.

    .. py:method:: allow_ioctl() -> SystemIO

        Allow ioctl and fcntl syscalls.

    .. py:method:: allow_metadata() -> SystemIO

        Allow stat syscalls.

    .. py:method:: allow_open() -> SystemIO

        Allow open syscalls.

        .. .. warning::

            It’s easy to accidentally combine this ruleset with another ruleset that allows write -
            for example the Network ruleset - even if you only want to read files.

    .. py:method:: allow_open_readonly() -> SystemIO

        Allow open syscalls but not with write flags.

        .. note::

            Without this ruleset your program most likely won't work, because Python won't be
            able to read any modules that are not loaded, yet.

    .. py:method:: allow_read() -> SystemIO

        Allow read syscalls.

    .. py:method:: allow_stderr() -> SystemIO

        Allow writing to stderr.

    .. py:method:: allow_stdin() -> SystemIO

        Allow reading from stdin.

    .. py:method:: allow_stdout() -> SystemIO

        Allow writing to stdout.

    .. py:method:: allow_write() -> SystemIO

        Allow write syscalls.

    .. py:method:: allow_file_read(fileno: int) -> SystemIO

        Allow reading a given open file descriptor.

        .. warning::

            If another file or socket is opened after the file provided to this function is closed,
            it’s possible that the fd will be reused and therefore may be read from.

    .. py:method:: allow_file_write(fileno: int) -> SystemIO

        Allow writing to a given open file descriptor.

        .. warning::

            If another file or socket is opened after the file provided to this function is closed,
            it’s possible that the fd will be reused and therefore may be read from.

.. class:: Threads
    :final:

    Allows clone and sleep syscalls, which allow creating new threads and processes, and pausing them.

    A new :class:`~pyextrasafe.Threads` ruleset allows nothing by default.

    .. seealso::

        Struct `extrasafe::builtins::danger_zone::Threads
        <https://docs.rs/extrasafe/0.1.2/extrasafe/builtins/danger_zone/struct.Threads.html>`_

    .. py:method:: allow_create() -> Threads

        Allow creating new threads and processes.

    .. py:method:: allow_sleep() -> Threads

        Allow sleeping on the current thread

        .. warning::

            An attacker with arbitrary code execution and access to a high resolution timer can mount
            timing attacks (e.g. spectre).

.. py:class:: Time
    :final:

    Enable syscalls related to time.

    A new Time :class:`~pyextrasafe.RuleSet` allows nothing by default.

    .. seealso::

        Struct `extrasafe::builtins::time::Time
        <https://docs.rs/extrasafe/0.1.2/extrasafe/builtins/time/struct.Time.html>`_

    .. py:method:: allow_gettime() -> Time

        On most 64 bit systems glibc and musl both use the vDSO to compute the time directly
        with rdtsc rather than calling the clock_gettime syscall, so in most cases you don’t
        need to actually enable this.

..
    Custom profiles

    .. autoclass:: Custom
        :members:

    .. autoclass:: Rule
        :members:

    .. autoclass:: Compare
        :members:

    .. class:: CompareOp
        :final:

        Represents a comparison operator which can be used in a filter rule.

        .. py:property:: Less
            :classmethod:
            :type: CompareOp

        .. py:property:: LessOrEqual
            :classmethod:
            :type: CompareOp

        .. py:property:: Equal
            :classmethod:
            :type: CompareOp

        .. py:property:: NotEqual
            :classmethod:
            :type: CompareOp

        .. py:property:: GreaterEqual
            :classmethod:
            :type: CompareOp

        .. py:property:: Greater
            :classmethod:
            :type: CompareOp

        .. py:method:: MaskedEqual(mask: int) -> CompareOp
            :staticmethod:

            This works like :data:`Equal` with the exception that the syscall argument is
            masked with :code:`mask` via an bitwise :code:`AND` (i.e. you can check specific bits in
            the argument).

            :param mask: bit mask

            :return: The newly crated instance

        .. py:property:: mask
            :type: typing.Optional[int]

            The parameter in :code:`CompareOp.MaskedEqual(mask)`, or :data:`None` for other values

Helper functions
----------------

These functions are not part of `extrasafe <https://docs.rs/extrasafe/0.1.2/extrasafe/index.html>`_\,
but they might come in handy anyways.

.. py:function::
    lock_pid_filelock_pid_file(path: Union[str, os.PathLike], *, closefd: bool = False, cloexec: bool = True, mode: int = 0o640, contents: Optional[bytes] = None) -> typing.BinaryIO

    Open and file-lock a PID file to prevent running multiple instances of a program.

    If the PID file was non-existent, then a new file is created.

    :param path:
        The path of the PID file.
    :param closefd:
        By default (unless the function is called with :code:`closefd=True`) the file descriptor of
        the opened PID file will leak if the returned :code:`File` is collected, so the lock will
        be held until the process terminates.
    :param cloexec:
        By default the file descriptor will not be passed to sub processes.
        To pass the file descriptor to subprocesses use :code:`cloexec=False`.

        If you want to keep the file-lock as long as a subprocess is around, then you should
        probably still not use this flag, but :func:`os.dup()` the file descriptor in
        :class:`~subprocess.Popen`\'s :code:`preexec_fn` parameter.
    :param mode:
        The file mode of the PID file. Only used if the file is newly created.
        If you supply a mode that is not readable and writable to the user, then all subsequent
        calls to this function will fail, whether the lock is still help or not.
        So make sure to always include :code:`0o600` in the mode!

        By default (:code:`0o640`) the file will be readable and writable for its user;
        readable for the user's group; and inaccessible for other users.
    :param contents:
        By default the file will contain the `PID <https://manpages.debian.org/bullseye/manpages-dev/getpid.2.en.html>`_
        of the current process followed by a newline.

    :return: The opened file descriptor that holds the file lock.

    :raise ExtraSafeError:
        If the file already existed, and a lock was held by another process, then the call will raise
        an exception.

.. py:function:: restrict_privileges()

    Basic security setup to prevent bootstrapping attacks.

    * This function `unshares <https://manpages.debian.org/bullseye/manpages-dev/unshare.2.en.html>`_
      file descriptors, filesystem, and semaphore adjustments with its parent process (if present).
    * It clears its `ambient capability set <https://manpages.debian.org/buster/manpages/capabilities.7.en.html>`_\.
    * And sets the `no new privileges bit <https://manpages.debian.org/bullseye/manpages-dev/prctl.2.en.html>`_\.
