use std::any::Any;
use std::fmt::Write;
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, RawFd};

use bitflags::bitflags;
use extrasafe::builtins::danger_zone::{ForkAndExec, Threads};
use extrasafe::builtins::network::Networking;
use extrasafe::builtins::{BasicCapabilities, SystemIO, Time};
use extrasafe::SafetyContext;
use pyo3::{
    pyclass, pymethods, Py, PyAny, PyClassInitializer, PyRefMut, PyResult, Python, ToPyObject,
};

use crate::ExtraSafeError;

fn downcast_any_rule<P: Any>(data: &mut dyn RuleSetData) -> PyResult<&mut P> {
    data.to_any()
        .downcast_mut::<P>()
        .ok_or_else(|| ExtraSafeError::new_err("illegal downcast (impossible)"))
}

trait EnableExtra<P> {
    fn enable_extra(&self, policy: P) -> P;
}

impl<P> EnableExtra<P> for () {
    #[inline(always)]
    fn enable_extra(&self, policy: P) -> P {
        policy
    }
}

pub(crate) trait RuleSetData: Any + Send + Sync + std::fmt::Debug {
    fn enable_to(&self, ctx: SafetyContext) -> Result<SafetyContext, extrasafe::ExtraSafeError>;

    fn to_any(&mut self) -> &mut dyn Any;

    fn clone_box(&self) -> Box<dyn RuleSetData>;
}

/// A RuleSet is a collection of seccomp rules that enable a functionality.
///
/// See also
/// --------
/// `Trait extrasafe::RuleSet <https://docs.rs/extrasafe/0.1.2/extrasafe/trait.RuleSet.html>`_
#[pyclass]
#[pyo3(name = "RuleSet", module = "pyextrasafe", subclass)]
pub(crate) struct PyRuleSet(Box<dyn RuleSetData>);

impl PyRuleSet {
    pub(crate) fn clone_inner(&self) -> Box<dyn RuleSetData> {
        self.0.clone_box()
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
            struct $flags_name: u32 {
                $( const $flag = $value; )*
            }
        }

        #[derive(Debug, Clone)]
        struct $data_name {
            flags: $flags_name,
            #[allow(dead_code)]
            extra: $extra,
        }

        impl std::ops::Deref for $data_name {
            type Target = $flags_name;

            #[inline(always)]
            fn deref(&self) -> &Self::Target {
                &self.flags
            }
        }

        impl std::ops::DerefMut for $data_name {
            #[inline(always)]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.flags
            }
        }

        impl RuleSetData for $data_name {
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

            fn to_any(&mut self) -> &mut dyn Any {
                self
            }

            fn clone_box(&self) -> Box<dyn RuleSetData> {
                Box::new(Self::clone(self))
            }
        }

        #[pyclass]
        #[pyo3(name = $name_str, module = "pyextrasafe", extends = PyRuleSet)]
        $(#[$meta])*
        pub(crate) struct $py_name;

        impl $py_name {
            fn _allow(
                mut this: PyRefMut<'_, Self>,
                bit: $flags_name,
            ) -> PyResult<PyRefMut<'_, Self>> {
                let any_data = this.as_mut().0.as_mut();
                let $data_name { flags, .. } = downcast_any_rule(any_data)?;
                *flags |= bit;
                Ok(this)
            }
        }

        #[pymethods]
        impl $py_name {
            #[new]
            fn new() -> (Self, PyRuleSet) {
                let value = $data_name {
                    flags: <$flags_name>::empty(),
                    extra: Default::default(),
                };
                (Self, PyRuleSet(Box::new(value) as Box<dyn RuleSetData>))
            }

            $(
            fn $func(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
                Self::_allow(this, <$flags_name>::$flag)
            }
            )*

            fn __repr__(mut this: PyRefMut<'_, Self>) -> PyResult<String> {
                let any_data = this.as_mut().0.as_mut();
                let data: &mut $data_name = downcast_any_rule(any_data)?;
                let mut result = String::new();
                write!(result, "<{}({:?}, {:?})>", $name_str, &data.flags, &data.extra)
                    .map_err(|err| ExtraSafeError::new_err(format!("could not debug??: {err}")))?;
                Ok(result)
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

#[derive(Debug, Clone, Default)]
struct ReadWriteFilenos {
    rd: Vec<i32>,
    wr: Vec<i32>,
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
            extra: ReadWriteFilenos::default(),
        };
        let value = Box::new(value) as Box<dyn RuleSetData>;
        let init = PyClassInitializer::from(PyRuleSet(value)).add_subclass(PySystemIO);
        Ok(pyo3::PyCell::new(py, init)?.to_object(py))
    }

    /// TODO: Doc
    fn allow_file_read(mut this: PyRefMut<'_, Self>, fileno: i32) -> PyResult<PyRefMut<'_, Self>> {
        if fileno == u32::MAX as RawFd {
            return Err(ExtraSafeError::new_err("illegal fileno"));
        }

        let any_data = this.as_mut().0.as_mut();
        let data: &mut DataSystemIO = downcast_any_rule(any_data)?;
        data.extra.rd.push(fileno);
        Ok(this)
    }

    /// TODO: Doc
    fn allow_file_write(mut this: PyRefMut<'_, Self>, fileno: i32) -> PyResult<PyRefMut<'_, Self>> {
        if fileno == u32::MAX as RawFd {
            return Err(ExtraSafeError::new_err("illegal fileno"));
        }

        let any_data = this.as_mut().0.as_mut();
        let data: &mut DataSystemIO = downcast_any_rule(any_data)?;
        data.extra.wr.push(fileno);
        Ok(this)
    }
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
