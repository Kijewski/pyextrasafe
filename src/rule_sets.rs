use std::collections::hash_map::DefaultHasher;
use std::fmt::{self, Write};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, RawFd};

use bitflags::bitflags;
use extrasafe::builtins::danger_zone::{ForkAndExec, Threads};
use extrasafe::builtins::network::Networking;
use extrasafe::builtins::{BasicCapabilities, SystemIO, Time};
use extrasafe::SafetyContext;
use pyo3::pyclass::CompareOp;
use pyo3::{
    pyclass, pymethods, Py, PyAny, PyClassInitializer, PyRef, PyRefMut, PyResult, Python,
    ToPyObject,
};

use crate::ExtraSafeError;

trait EnableExtra<P> {
    fn enable_extra(&self, policy: P) -> P;
}

impl<P> EnableExtra<P> for () {
    #[inline]
    fn enable_extra(&self, policy: P) -> P {
        policy
    }
}

struct ReprExtra<'a, D>(&'a D);

const _: () = {
    impl<D: DebugExtra> fmt::Display for ReprExtra<'_, D> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.format_to(formatter)
        }
    }

    trait DebugExtra {
        fn format_to(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result;
    }

    impl DebugExtra for () {
        #[inline]
        fn format_to(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }

    impl DebugExtra for ReadWriteFilenos {
        fn format_to(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(", ")?;
            formatter
                .debug_map()
                .entry(&"rd", &self.rd)
                .entry(&"wr", &self.wr)
                .finish()
        }
    }
};

pub(crate) trait EnablePolicy {
    fn enable_to(&self, ctx: SafetyContext) -> Result<SafetyContext, extrasafe::ExtraSafeError>;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum DataRuleSet {
    PyBasicCapabilities(DataBasicCapabilities),
    PyForkAndExec(DataForkAndExec),
    PyThreads(DataThreads),
    PyNetworking(DataNetworking),
    PySystemIO(Box<DataSystemIO>),
    PyTime(DataTime),
}

impl EnablePolicy for PyRuleSet {
    #[inline]
    fn enable_to(&self, ctx: SafetyContext) -> Result<SafetyContext, extrasafe::ExtraSafeError> {
        self.0.enable_to(ctx)
    }
}

impl EnablePolicy for DataRuleSet {
    fn enable_to(&self, ctx: SafetyContext) -> Result<SafetyContext, extrasafe::ExtraSafeError> {
        match self {
            DataRuleSet::PyBasicCapabilities(policy) => policy.enable_to(ctx),
            DataRuleSet::PyForkAndExec(policy) => policy.enable_to(ctx),
            DataRuleSet::PyThreads(policy) => policy.enable_to(ctx),
            DataRuleSet::PyNetworking(policy) => policy.enable_to(ctx),
            DataRuleSet::PySystemIO(policy) => policy.enable_to(ctx),
            DataRuleSet::PyTime(policy) => policy.enable_to(ctx),
        }
    }
}

/// A RuleSet is a collection of seccomp rules that enable a functionality.
///
/// See also
/// --------
/// `Trait extrasafe::RuleSet <https://docs.rs/extrasafe/0.1.2/extrasafe/trait.RuleSet.html>`_
#[pyclass]
#[pyo3(name = "RuleSet", module = "pyextrasafe", subclass)]
#[derive(Debug, Clone)]
pub(crate) struct PyRuleSet(DataRuleSet);

unsafe impl pyo3::PyNativeType for PyRuleSet {}

#[pymethods]
impl PyRuleSet {
    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Lt => Ok(self.0 < other.0),
            CompareOp::Le => Ok(self.0 <= other.0),
            CompareOp::Eq => Ok(self.0 == other.0),
            CompareOp::Ne => Ok(self.0 != other.0),
            CompareOp::Gt => Ok(self.0 > other.0),
            CompareOp::Ge => Ok(self.0 >= other.0),
        }
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

macro_rules! impl_subclass {
    (
        $(#[$meta:meta])*
        $name_str:literal,
        $py_name:ident,
        $data_name:ident($flags_name:ident),
        $policy:ident: $type:ty = $ctor:expr =>
        {
            $(
                $(#[$flag_meta:meta])*
                [$value:expr] $flag:ident => $func:ident [$enable:expr]
            );* $(;)?
        }
        $extra:ty
    ) => {
        bitflags! {
            #[derive(Default)]
            struct $flags_name: u16 {
                $( const $flag = $value; )*
            }
        }

        #[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        struct $data_name {
            flags: $flags_name,
            #[allow(dead_code)]
            extra: $extra,
        }

        impl EnablePolicy for $data_name {
            fn enable_to(
                &self,
                ctx: SafetyContext,
            ) -> Result<SafetyContext, extrasafe::ExtraSafeError> {
                #[allow(unused_mut)]
                let mut $policy = $ctor;

                #[allow(unused)]
                let $data_name { flags, extra } = self;

                $(
                if flags.contains(<$flags_name>::$flag) {
                    $policy = $enable;
                }
                )*
                $policy = extra.enable_extra($policy);

                ctx.enable($policy)
            }
        }

        #[pyclass]
        #[pyo3(name = $name_str, module = "pyextrasafe", extends = PyRuleSet)]
        $(#[$meta])*
        pub(crate) struct $py_name;

        #[pymethods]
        impl $py_name {
            #[new]
            fn new() -> (Self, PyRuleSet) {
                (Self, PyRuleSet(DataRuleSet::$py_name(<$data_name>::default().into())))
            }

            $(
            $(#[$flag_meta])*
            fn $func(mut this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
                if let DataRuleSet::$py_name(data) = &mut this.as_mut().0 {
                    data.flags |= <$flags_name>::$flag;
                    Ok(this)
                } else {
                    unreachable!("Impossible content")
                }
            }
            )*

            fn __repr__(this: PyRef<'_, Self>) -> PyResult<String> {
                let DataRuleSet::$py_name(data) = &this.as_ref().0 else {
                    unreachable!("Impossible content");
                };

                let mut s = String::new();
                write!(s, "<{}({:?}{})>", $name_str, &data.flags, ReprExtra(&data.extra))
                    .map_err(|err| {
                        let msg = format!("could not debug??: {err}");
                        ExtraSafeError::new_err(msg)
                    })?;
                Ok(s)
            }
        }
    };
}

impl_subclass! {
    /// TODO: Doc
    "BasicCapabilities",
    PyBasicCapabilities,
    DataBasicCapabilities(FlagsBasicCapabilities),
    policy: BasicCapabilities = BasicCapabilities => {}
    ()
}

impl_subclass! {
    /// TODO: Doc
    "ForkAndExec",
    PyForkAndExec,
    DataForkAndExec(FlagsForkAndExec),
    policy: ForkAndExec = ForkAndExec => {}
    ()
}

impl_subclass! {
    /// TODO: Doc
    "Threads",
    PyThreads,
    DataThreads(FlagsThreads),
    policy: Threads = Threads::nothing() => {
        /// TODO: Doc
        [1 << 0] ALLOW_CREATE => allow_create [policy.allow_create()];

        /// TODO: Doc
        [1 << 1] ALLOW_SLEEP => allow_sleep [policy.allow_sleep().yes_really()];
    }
    ()
}

impl_subclass! {
    /// TODO: Doc
    "Networking",
    PyNetworking,
    DataNetworking(FlagsNetworking),
    policy: Networking = Networking::nothing() => {
        /// TODO: Docs
        [1 << 0] ALLOW_RUNNING_TCP_CLIENTS => allow_running_tcp_clients
        [policy.allow_running_tcp_clients()];

        /// TODO: Docs
        [1 << 1] ALLOW_RUNNING_TCP_SERVERS => allow_running_tcp_servers
        [policy.allow_running_tcp_servers()];

        /// TODO: Docs
        [1 << 2] ALLOW_RUNNING_UDP_SOCKETS => allow_running_udp_sockets
        [policy.allow_running_udp_sockets()];

        /// TODO: Docs
        [1 << 3] ALLOW_RUNNING_UNIX_CLIENTS => allow_running_unix_clients
        [policy.allow_running_unix_clients()];

        /// TODO: Docs
        [1 << 4] ALLOW_RUNNING_UNIX_SERVERS => allow_running_unix_servers
        [policy.allow_running_unix_servers()];

        /// TODO: Docs
        [1 << 5] ALLOW_START_TCP_CLIENTS => allow_start_tcp_clients
        [policy.allow_start_tcp_clients()];

        /// TODO: Docs
        [1 << 6] ALLOW_START_TCP_SERVERS => allow_start_tcp_servers
        [policy.allow_start_tcp_servers().yes_really()];

        /// TODO: Docs
        [1 << 7] ALLOW_START_UDP_SERVERS => allow_start_udp_servers
        [policy.allow_start_udp_servers().yes_really()];

        /// TODO: Docs
        [1 << 8] ALLOW_START_UNIX_SERVER => allow_start_unix_server
        [policy.allow_start_unix_server().yes_really()];
    }
    ()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ReadWriteFilenos {
    rd: Vec<RawFd>,
    wr: Vec<RawFd>,
}

impl EnableExtra<SystemIO> for ReadWriteFilenos {
    fn enable_extra(&self, mut policy: SystemIO) -> SystemIO {
        for &fileno in &self.rd {
            let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fileno) });
            policy = policy.allow_file_read(&file);
        }
        for &fileno in &self.wr {
            let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fileno) });
            policy = policy.allow_file_write(&file);
        }
        policy
    }
}

impl_subclass! {
    /// TODO: Doc
    "SystemIO",
    PySystemIO,
    DataSystemIO(FlagsSystemIO),
    policy: SystemIO = SystemIO::nothing() => {
        /// TODO: Docs
        [1 << 0] ALLOW_CLOSE => allow_close
        [policy.allow_close()];

        /// TODO: Docs
        [1 << 1] ALLOW_IOCTL => allow_ioctl
        [policy.allow_ioctl()];

        /// TODO: Docs
        [1 << 2] ALLOW_METADATA => allow_metadata
        [policy.allow_metadata()];

        /// TODO: Docs
        [1 << 3] ALLOW_OPEN => allow_open
        [policy.allow_open().yes_really()];

        /// TODO: Docs
        [1 << 4] ALLOW_OPEN_READONLY => allow_open_readonly
        [policy.allow_open_readonly()];

        /// TODO: Docs
        [1 << 5] ALLOW_READ => allow_read
        [policy.allow_read()];

        /// TODO: Docs
        [1 << 6] ALLOW_STDERR => allow_stderr
        [policy.allow_stderr()];

        /// TODO: Docs
        [1 << 7] ALLOW_STDIN => allow_stdin
        [policy.allow_stdin()];

        /// TODO: Docs
        [1 << 8] ALLOW_STDOUT => allow_stdout
        [policy.allow_stdout()];

        /// TODO: Docs
        [1 << 9] ALLOW_WRITE => allow_write
        [policy.allow_write()];
    }
    ReadWriteFilenos
}

#[pymethods]
impl PySystemIO {
    #[staticmethod]
    /// TODO: Doc
    fn everything(py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = DataSystemIO {
            flags: FlagsSystemIO::all(),
            extra: Default::default(),
        };
        let value = PyRuleSet(DataRuleSet::PySystemIO(value.into()));
        let init = PyClassInitializer::from(value).add_subclass(Self);
        Ok(pyo3::PyCell::new(py, init)?.to_object(py))
    }

    /// TODO: Doc
    fn allow_file_read(
        mut this: PyRefMut<'_, Self>,
        fileno: RawFd,
    ) -> PyResult<PyRefMut<'_, Self>> {
        if let DataRuleSet::PySystemIO(data) = &mut this.as_mut().0 {
            insert_sorted_fileno(&mut data.extra.rd, fileno)?;
            Ok(this)
        } else {
            unreachable!("Impossible content")
        }
    }

    /// TODO: Doc
    fn allow_file_write(
        mut this: PyRefMut<'_, Self>,
        fileno: RawFd,
    ) -> PyResult<PyRefMut<'_, Self>> {
        if let DataRuleSet::PySystemIO(data) = &mut this.as_mut().0 {
            insert_sorted_fileno(&mut data.extra.wr, fileno)?;
            Ok(this)
        } else {
            unreachable!("Impossible content")
        }
    }
}

fn insert_sorted_fileno(vec: &mut Vec<RawFd>, fileno: RawFd) -> PyResult<()> {
    if fileno < 0 {
        return Err(ExtraSafeError::new_err("illegal fileno"));
    }
    if let Err(pos) = vec.binary_search(&fileno) {
        vec.insert(pos, fileno);
    }
    Ok(())
}

impl_subclass! {
    /// TODO: Doc
    "Time",
    PyTime,
    DataTime(FlagsTime),
    policy: Time = Time::nothing() => {
        /// TODO: Docs
        [1 << 0] ALLOW_GETTIME => allow_gettime
        [policy.allow_gettime()];
    }
    ()
}
