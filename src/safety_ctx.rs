use std::fmt::Write;

use extrasafe::SafetyContext;
use pyo3::{pyclass, pymethods, PyRefMut, PyResult};

use crate::rule_sets::RuleSetData;
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
pub(crate) struct PySafetyContext(Vec<Box<dyn RuleSetData>>);

impl PySafetyContext {
    fn to_context(&self) -> PyResult<SafetyContext> {
        let mut ctx = SafetyContext::new();
        for policy in &self.0 {
            let policy = policy.as_ref();
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
    pub(crate) fn new() -> Self {
        Self(Vec::new())
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
    fn enable<'p>(
        mut ctx: PyRefMut<'p, Self>,
        policy: &crate::rule_sets::PyRuleSet,
    ) -> PyResult<PyRefMut<'p, Self>> {
        ctx.0.push(policy.clone_inner());
        Ok(ctx)
    }

    /// Load the SafetyContext’s rules into a seccomp filter and apply the filter to the current thread.
    fn apply_to_current_thread(&mut self) -> PyResult<()> {
        self.to_context()?.apply_to_current_thread().map_err(|err| {
            ExtraSafeError::new_err(format!("could not apply to current thread: {err}"))
        })
    }

    /// Load the SafetyContext’s rules into a seccomp filter and apply the filter to all threads in this process.
    fn apply_to_all_threads(&mut self) -> PyResult<()> {
        self.to_context()?.apply_to_all_threads().map_err(|err| {
            ExtraSafeError::new_err(format!("could not apply to all threads: {err}"))
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        let mut s = String::new();
        write!(s, "<SafetyContext{:?}>", &self.0)
            .map_err(|err| ExtraSafeError::new_err(format!("could not debug??: {err}")))?;
        Ok(s)
    }
}
