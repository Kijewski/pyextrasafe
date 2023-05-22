use std::any::Any;
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, RawFd};

use extrasafe::builtins::danger_zone::{ForkAndExec, Threads};
use extrasafe::builtins::network::Networking;
use extrasafe::builtins::{BasicCapabilities, SystemIO, Time};
use extrasafe::{RuleSet, SafetyContext};
use pyo3::types::{PyDict, PyList};
use pyo3::{
    pyclass, pymethods, Py, PyAny, PyClassInitializer, PyRefMut, PyResult, Python, ToPyObject,
};

use crate::ExtraSafeError;

fn downcast_any_rule<P: Any>(option: &mut Option<Box<dyn AnyRuleSet>>) -> PyResult<Box<P>> {
    option
        .take()
        .ok_or_else(|| ExtraSafeError::new_err("Thread instance was already consumed"))?
        .to_any()
        .downcast()
        .map_err(|_| ExtraSafeError::new_err("illegal downcast (impossible)"))
}

fn fake_file(fileno: i32) -> PyResult<ManuallyDrop<File>> {
    if fileno != u32::MAX as RawFd {
        Ok(ManuallyDrop::new(unsafe { File::from_raw_fd(fileno) }))
    } else {
        Err(ExtraSafeError::new_err("illegal fileno"))
    }
}

pub(crate) trait AnyRuleSet: Any + RuleSet + Send + Sync {
    fn enable_to(
        self: Box<Self>,
        ctx: SafetyContext,
    ) -> Result<SafetyContext, extrasafe::ExtraSafeError>;

    fn to_any(self: Box<Self>) -> Box<dyn Any>;
}

/// A RuleSet is a collection of seccomp rules that enable a functionality.
///
/// See also
/// --------
/// `Trait extrasafe::RuleSet <https://docs.rs/extrasafe/0.1.2/extrasafe/trait.RuleSet.html>`_
#[pyclass]
#[pyo3(name = "RuleSet", module = "pyextrasafe", subclass)]
pub(crate) struct PyRuleSet(Option<Box<dyn AnyRuleSet>>);

impl PyRuleSet {
    pub(crate) fn get(&self) -> PyResult<&dyn AnyRuleSet> {
        let policy = self
            .0
            .as_ref()
            .ok_or_else(|| ExtraSafeError::new_err("RuleSet instance was already consumed"))?
            .as_ref();
        Ok(policy)
    }

    pub(crate) fn apply(&mut self, ctx: SafetyContext) -> PyResult<SafetyContext> {
        let policy = self
            .0
            .take()
            .ok_or_else(|| ExtraSafeError::new_err("RuleSet instance was already consumed"))?;
        policy
            .enable_to(ctx)
            .map_err(|err| ExtraSafeError::new_err(format!("could not apply policy: {err}")))
    }
}

#[pymethods]
impl PyRuleSet {
    /// list[int]: A simple rule is one that just allows the syscall without restriction.
    #[getter]
    fn simple_rules(&self) -> PyResult<Vec<i32>> {
        let rules = self
            .get()?
            .simple_rules()
            .into_iter()
            .map(|sysno| sysno as i32)
            .collect();
        Ok(rules)
    }

    /// dict[int, str]: A conditional rule is a rule that uses a condition to restrict the syscall, e.g. only specific flags as parameters.
    #[getter]
    fn conditional_rules(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let rules = self.get()?.conditional_rules();

        let dict = PyDict::new(py);
        for (sysno, rules) in rules {
            let rules = rules.into_iter().map(|rule| {
                let comparators = rule.comparators.into_iter().map(|cmp| format!("{cmp:?}"));
                (rule.syscall as i32, PyList::new(py, comparators))
            });
            let rules = PyList::new(py, rules);
            dict.set_item(sysno as i32, rules)?;
        }
        Ok(dict.into())
    }

    /// str: The name of the profile.
    #[getter]
    fn name(&self) -> PyResult<&'static str> {
        Ok(self.get()?.name())
    }
}

macro_rules! impl_subclass {
    (
        $(#[$meta:meta])*
        $name_str:literal, $py_name:ident, $type:ty, $ctor:expr
    ) => {
        #[pyclass]
        #[pyo3(name = $name_str, module = "pyextrasafe", extends = PyRuleSet)]
        $(#[$meta])*
        pub(crate) struct $py_name;

        impl AnyRuleSet for $type {
            fn enable_to(
                self: Box<Self>,
                ctx: SafetyContext,
            ) -> Result<SafetyContext, extrasafe::ExtraSafeError> {
                ctx.enable(*self)
            }

            fn to_any(self: Box<Self>) -> Box<dyn Any> {
                self as Box<dyn Any>
            }
        }

        impl $py_name {
            fn _allow(
                mut this: PyRefMut<'_, Self>,
                allow: impl Fn($type) -> $type,
            ) -> PyResult<PyRefMut<'_, Self>> {
                let option = &mut this.as_mut().0;
                let policy: Box<$type> = downcast_any_rule(option)?;
                *option = Some(Box::new(allow(*policy)));
                Ok(this)
            }
        }

        #[pymethods]
        impl $py_name {
            #[new]
            fn new() -> (Self, PyRuleSet) {
                let value = Box::new($ctor) as Box<dyn AnyRuleSet>;
                (Self, PyRuleSet(Some(value)))
            }

            fn __repr__(&self) -> &'static str {
                concat!("<pyextrasafe.", $name_str, ">")
            }
        }
    };
}

impl_subclass! {
    /// TODO: Doc
    "BasicCapabilities",
    PyBasicCapabilities,
    BasicCapabilities,
    BasicCapabilities
}

impl_subclass! {
    /// TODO: Doc
    "ForkAndExec",
    PyForkAndExec,
    ForkAndExec,
    ForkAndExec
}

impl_subclass! {
    /// TODO: Doc
    "Threads",
    PyThreads,
    Threads,
    Threads::nothing()
}

#[pymethods]
impl PyThreads {
    /// TODO: Doc
    fn allow_create(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Threads::allow_create)
    }

    /// TODO: Doc
    fn allow_sleep(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, |p| p.allow_sleep().yes_really())
    }
}

impl_subclass! {
    /// TODO: Doc
    "Networking",
    PyNetworking,
    Networking,
    Networking::nothing()
}

#[pymethods]
impl PyNetworking {
    /// TODO: Doc
    fn allow_running_tcp_servers(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Networking::allow_running_tcp_servers)
    }

    /// TODO: Doc
    fn allow_start_tcp_servers(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, |p| p.allow_start_tcp_servers().yes_really())
    }

    /// TODO: Doc
    fn allow_running_udp_sockets(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Networking::allow_running_udp_sockets)
    }

    /// TODO: Doc
    fn allow_start_udp_servers(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, |p| p.allow_start_udp_servers().yes_really())
    }

    /// TODO: Doc
    fn allow_start_tcp_clients(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Networking::allow_start_tcp_clients)
    }

    /// TODO: Doc
    fn allow_running_tcp_clients(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Networking::allow_running_tcp_clients)
    }

    /// TODO: Doc
    fn allow_start_unix_server(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, |p| p.allow_start_unix_server().yes_really())
    }

    /// TODO: Doc
    fn allow_running_unix_servers(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Networking::allow_running_unix_servers)
    }

    /// TODO: Doc
    fn allow_running_unix_clients(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Networking::allow_running_unix_clients)
    }
}

impl_subclass! {
    /// TODO: Doc
    "SystemIO",
    PySystemIO,
    SystemIO,
    SystemIO::nothing()
}

#[pymethods]
impl PySystemIO {
    #[staticmethod]
    /// TODO: Doc
    fn everything(py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = Some(Box::new(SystemIO::everything()) as Box<dyn AnyRuleSet>);
        let init = PyClassInitializer::from(PyRuleSet(value)).add_subclass(PySystemIO);
        Ok(pyo3::PyCell::new(py, init)?.to_object(py))
    }

    /// TODO: Doc
    fn allow_read(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_read)
    }

    /// TODO: Doc
    fn allow_write(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_write)
    }

    /// TODO: Doc
    fn allow_open(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, |p| p.allow_open().yes_really())
    }

    /// TODO: Doc
    fn allow_open_readonly(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_open_readonly)
    }

    /// TODO: Doc
    fn allow_metadata(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_metadata)
    }

    /// TODO: Doc
    fn allow_ioctl(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_ioctl)
    }

    /// TODO: Doc
    fn allow_close(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_close)
    }

    /// TODO: Doc
    fn allow_stdin(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_stdin)
    }

    /// TODO: Doc
    fn allow_stdout(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_stdout)
    }

    /// TODO: Doc
    fn allow_stderr(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, SystemIO::allow_stderr)
    }

    /// TODO: Doc
    fn allow_file_read(this: PyRefMut<'_, Self>, fileno: i32) -> PyResult<PyRefMut<'_, Self>> {
        let file = fake_file(fileno)?;
        Self::_allow(this, |p| p.allow_file_read(&file))
    }

    /// TODO: Doc
    fn allow_file_write(this: PyRefMut<'_, Self>, fileno: i32) -> PyResult<PyRefMut<'_, Self>> {
        let file = fake_file(fileno)?;
        Self::_allow(this, |p| p.allow_file_write(&file))
    }
}

impl_subclass! {
    /// TODO: Doc
    "Time",
    PyTime,
    Time,
    Time::nothing()
}

#[pymethods]
impl PyTime {
    /// TODO: Doc
    fn allow_gettime(this: PyRefMut<'_, Self>) -> PyResult<PyRefMut<'_, Self>> {
        Self::_allow(this, Time::allow_gettime)
    }
}
