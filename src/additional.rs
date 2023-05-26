use std::io::{Cursor, Write};
use std::mem::forget;
use std::path::PathBuf;

use pyo3::types::PyDict;
use pyo3::{pyfunction, Py, PyAny, PyResult, Python};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use rustix::fs::{
    cwd, flock, ftruncate, openat2, FlockOperation, Mode, OFlags, RawMode, ResolveFlags,
};
use rustix::io::{write, Errno};
use rustix::process::getpid;
use rustix::{io, thread};

use crate::ExtraSafeError;

/// Basic security setup to prevent bootstrapping attacks.
///
/// * This function `unshare <https://manpages.debian.org/bullseye/manpages-dev/unshare.2.en.html>`_\s
///   file descriptors, filesystem, and semaphore adjustments with its parent process (if present).
/// * It clears its `ambient capability set <https://manpages.debian.org/buster/manpages/capabilities.7.en.html>`_\.
/// * And sets the `no new privileges bit <https://manpages.debian.org/bullseye/manpages-dev/prctl.2.en.html>`_\.
#[pyfunction]
pub(crate) fn restrict_privileges() {
    let _: Result<(), io::Errno> = thread::unshare(
        thread::UnshareFlags::FILES | thread::UnshareFlags::FS | thread::UnshareFlags::SYSVSEM,
    );
    let _: Result<(), io::Errno> = thread::clear_ambient_capability_set();
    let _: Result<(), io::Errno> = thread::set_no_new_privs(true);
}

/// Open and file-lock a PID file to prevent running multiple instances of a program.
///
/// If the PID file was non-existent, then a new file is created.
/// If the file already existed, and a lock was held by another process, then the call will raise
/// an exception.
///
/// Arguments
/// ---------
/// path: os.PathLike
///     The path of the PID file.
/// closefd: bool
///     By default (unless the function is called with :code:`closefd=True`) the file descriptor of
///     the opened PID file will leak if the returned :class:`File` is collected, so the lock will
///     be held until the process terminates.
/// cloexec: bool
///     By default the file descriptor will not be passed to sub processes.
///     To pass the file descriptor to subprocesses use :code:`cloexec=False`.
///
///     If you want to keep the file-lock as long as a subprocess is around, then you should
///     probably still not use this flag, but :func:`os.dup()` the file descriptor in
///     :class:`~subprocess.Popen`\'s :code:`preexec_fn` parameter.
/// mode: int
///     The file mode of the PID file. Only used if the file is newly created.
///     If you supply a mode that is not readable and writable to the user, then all subsequent
///     calls to this function will fail, whether the lock is still help or not.
///     So make sure to always include :code:`0o600` in the mode!
///
///     By default (:code:`0o640`) the file will be readable and writable for its user;
///     readable for the user's group; and inaccessible for other users.
/// contents: bytes
///     By default the file will contain the `PID <https://manpages.debian.org/bullseye/manpages-dev/getpid.2.en.html>`_
///     of the current process followed by a newline.
///
/// Returns
/// -------
/// typing.BinaryIO
///     The opened file descriptor that holds the file lock.
#[pyfunction]
#[pyo3(
    signature = (path, *, closefd=false, cloexec=true, mode=0o640, contents=None),
    text_signature = "(path, *, closefd=False, cloexec=True, mode=416, contents=None)"
)]
pub(crate) fn lock_pid_file(
    py: Python<'_>,
    path: PathBuf,
    closefd: bool,
    cloexec: bool,
    mode: RawMode,
    contents: Option<&[u8]>,
) -> PyResult<Py<PyAny>> {
    let mode = Mode::from_bits(mode)
        .ok_or_else(|| ExtraSafeError::new_err("`mode` argument contains unknown bits"))?;

    let mut buffer;
    let contents = if let Some(contents) = contents {
        contents
    } else {
        buffer = [0u8; 24];
        let mut cursor = Cursor::new(&mut buffer[..]);
        #[allow(clippy::write_with_newline)]
        write!(cursor, "{}\n", getpid().as_raw_nonzero().get()).unwrap();
        let content_len = cursor.position().try_into().unwrap();
        &buffer[..content_len]
    };

    match py.allow_threads(|| lock_pid_file_nogil(path, cloexec, mode, contents)) {
        Ok(fd) => wrap_fd(py, fd, closefd),
        Err((errno, msg)) => raise_errno(py, errno, msg),
    }
}

fn raise_errno(py: Python<'_>, errno: Option<Errno>, msg: &str) -> PyResult<Py<PyAny>> {
    if errno == Some(Errno::INTR) {
        py.check_signals()?;
    }

    let err = ExtraSafeError::new_err(format!("Could not {msg} PID file."));
    let Some(errno) = errno else { return Err(err) };

    let locals = PyDict::new(py);
    locals.set_item("err", err)?;
    locals.set_item("errno", errno.raw_os_error())?;
    locals.set_item("strerr", format!("{errno}"))?;
    py.run("raise err from OSError(errno, strerr)", None, Some(locals))?;
    unreachable!()
}

fn wrap_fd(py: Python<'_>, owned_fd: OwnedFd, closefd: bool) -> PyResult<Py<PyAny>> {
    let locals = PyDict::new(py);
    locals.set_item("fd", owned_fd.as_raw_fd())?;
    locals.set_item("closefd", closefd)?;
    py.run(
        "ret = open(fd, mode='r+b', buffering=0, closefd=closefd)",
        None,
        Some(locals),
    )?;
    let Some(file) = locals.get_item("ret") else { unreachable!() };

    forget(owned_fd);
    Ok(file.into())
}

fn lock_pid_file_nogil(
    path: PathBuf,
    cloexec: bool,
    mode: Mode,
    contents: &[u8],
) -> Result<OwnedFd, (Option<Errno>, &'static str)> {
    let mut oflags = OFlags::RDWR | OFlags::CREATE | OFlags::NOCTTY;
    if cloexec {
        oflags |= OFlags::CLOEXEC;
    }

    let fd = openat2(cwd(), path, oflags, mode, ResolveFlags::NO_MAGICLINKS)
        .map_err(|err| (Some(err), "open or create"))?;

    flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|err| (Some(err), "file lock"))?;
    ftruncate(&fd, 0).map_err(|err| (Some(err), "truncate"))?;
    write_all(fd.as_fd(), contents)?;

    Ok(fd)
}

fn write_all(fd: BorrowedFd<'_>, mut contents: &[u8]) -> Result<(), (Option<Errno>, &'static str)> {
    let mut had_zero = false;
    while !contents.is_empty() {
        let amount = write(fd, contents).map_err(|err| (Some(err), "write to"))?;
        if amount > 0 {
            contents = &contents[amount..];
            had_zero = false;
        } else if !had_zero {
            had_zero = true;
        } else {
            return Err((None, "write all data to"));
        }
    }
    Ok(())
}
