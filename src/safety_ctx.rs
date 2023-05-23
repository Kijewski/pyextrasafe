use std::fmt::Write;

use extrasafe::SafetyContext;
use pyo3::types::PyList;
use pyo3::{pyclass, pymethods, Py, PyAny, PyRef, PyRefMut, PyResult, Python};

use crate::rule_sets::{EnablePolicy, PyRuleSet};
use crate::ExtraSafeError;

/// A struct representing a set of rules to be loaded into a seccomp filter and applied to the
/// current thread, or all threads in the current process.
///
/// The seccomp filters will not be loaded until either :meth:`.apply_to_current_thread()` or
/// :meth:`.apply_to_all_threads()` is called.
///
/// See also
/// --------
/// `Struct extrasafe::SafetyContext <https://docs.rs/extrasafe/0.1.2/extrasafe/struct.SafetyContext.html>`_
#[pyclass]
#[pyo3(name = "SafetyContext", module = "pyextrasafe")]
#[derive(Debug)]
pub(crate) struct PySafetyContext(Py<PyList>);

impl PySafetyContext {
    fn to_context(&self, py: Python<'_>) -> PyResult<SafetyContext> {
        let mut ctx = SafetyContext::new();
        for policy in self.0.as_ref(py) {
            let policy = policy.downcast::<PyRuleSet>()?;
            ctx = policy.enable_to(ctx).map_err(|err| {
                ExtraSafeError::new_err(format!("policy {policy:?} could not be applied: {err}"))
            })?;
        }
        Ok(ctx)
    }
}

#[pymethods]
impl PySafetyContext {
    #[new]
    pub(crate) fn new(py: Python<'_>) -> Self {
        Self(PyList::empty(py).into())
    }

    /// Enable the simple and conditional rules provided by the :class:`~pyextrasafe.RuleSet`.
    ///
    /// Parameters
    /// ----------
    /// policy: RuleSet
    ///     :class:`~pyextrasafe.RuleSet` to enable.
    ///
    /// Returns
    /// -------
    /// SafetyContext
    ///     This self object itself, so :meth:`.enable()` can be chained.
    ///
    /// Raises
    /// ------
    /// TypeError
    ///     Argument was not an instance of :class:`~pyextrasafe.RuleSet`.
    fn enable<'p>(
        ctx: PyRefMut<'p, Self>,
        py: Python<'_>,
        policy: Py<PyRuleSet>,
    ) -> PyResult<PyRefMut<'p, Self>> {
        ctx.0.as_ref(py).append(policy)?;
        Ok(ctx)
    }

    /// Load the SafetyContext’s rules into a seccomp filter and apply the filter to the current thread.
    ///
    /// Raises
    /// ------
    /// ExtraSafeError
    ///     Could not apply policies.
    fn apply_to_current_thread(&mut self, py: Python<'_>) -> PyResult<()> {
        self.to_context(py)?
            .apply_to_current_thread()
            .map_err(|err| {
                ExtraSafeError::new_err(format!("could not apply to current thread: {err}"))
            })
    }

    /// Load the SafetyContext’s rules into a seccomp filter and apply the filter to all threads in this process.
    ///
    /// Raises
    /// ------
    /// ExtraSafeError
    ///     Could not apply policies.
    fn apply_to_all_threads(&mut self, py: Python<'_>) -> PyResult<()> {
        self.to_context(py)?.apply_to_all_threads().map_err(|err| {
            ExtraSafeError::new_err(format!("could not apply to all threads: {err}"))
        })
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let mut s = String::new();
        let list_repr = self.0.as_ref(py).repr()?.to_str()?;
        write!(s, "<SafetyContext {list_repr}>")
            .map_err(|err| ExtraSafeError::new_err(format!("could not debug??: {err}")))?;
        Ok(s)
    }

    fn __iter__(&self) -> Iter {
        Iter {
            lst: self.0.clone(),
            idx: 0,
        }
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.0.as_ref(py).len()
    }

    fn __bool__(&self, py: Python<'_>) -> bool {
        !self.0.as_ref(py).is_empty()
    }
}

#[pyclass]
#[pyo3(name = "_SafetyContextIter")]
#[derive(Debug, Clone)]
struct Iter {
    lst: Py<PyList>,
    idx: usize,
}

#[pymethods]
impl Iter {
    fn __iter__(this: PyRef<'_, Self>) -> PyRef<'_, Self> {
        this
    }

    fn __next__(&mut self, py: Python<'_>) -> Option<Py<PyAny>> {
        let result = self.lst.as_ref(py).get_item(self.idx).ok()?;
        self.idx += 1;
        Some(result.into())
    }

    fn __index__(&self) -> usize {
        self.idx
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.lst.as_ref(py).len().saturating_sub(self.idx)
    }
}
