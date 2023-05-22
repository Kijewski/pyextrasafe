use extrasafe::SafetyContext;
use pyo3::{pyclass, pymethods, PyRefMut, PyResult};

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
pub(crate) struct PySafetyContext(Option<SafetyContext>);

#[pymethods]
impl PySafetyContext {
    #[new]
    pub(crate) fn new() -> Self {
        Self(Some(SafetyContext::new()))
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
    /// ExtraSafeError
    ///     The :class:`~pyextrasafe.SafetyContext` was already consumed by :meth:`.apply_to_current_thread()` or :meth:`.apply_to_all_threads()`.
    ///     The :class:`~pyextrasafe.RuleSet` was already consumed by this method.
    fn enable<'p>(
        mut ctx: PyRefMut<'p, Self>,
        policy: &mut crate::rule_sets::PyRuleSet,
    ) -> PyResult<PyRefMut<'p, Self>> {
        let old_ctx = ctx.0.take().ok_or_else(|| {
            ExtraSafeError::new_err("SafetyContext instance was already consumed")
        })?;
        ctx.0 = Some(policy.apply(old_ctx)?);
        Ok(ctx)
    }

    /// Load the SafetyContext’s rules into a seccomp filter and apply the filter to the current thread.
    fn apply_to_current_thread(&mut self) -> PyResult<()> {
        self.0
            .take()
            .ok_or_else(|| ExtraSafeError::new_err("instance was already consumed"))?
            .apply_to_current_thread()
            .map_err(|err| {
                ExtraSafeError::new_err(format!("could not apply to current thread: {err}"))
            })
    }

    /// Load the SafetyContext’s rules into a seccomp filter and apply the filter to all threads in this process.
    fn apply_to_all_threads(&mut self) -> PyResult<()> {
        self.0
            .take()
            .ok_or_else(|| ExtraSafeError::new_err("instance was already consumed"))?
            .apply_to_all_threads()
            .map_err(|err| {
                ExtraSafeError::new_err(format!("could not apply to all threads: {err}"))
            })
    }

    fn __repr__(&self) -> String {
        match &self.0 {
            Some(this) => format!("<pyextrasafe.{this:?}>"),
            None => "<consumed pyextrasafe.SafetyContext>".to_owned(),
        }
    }
}
