use extrasafe::SafetyContext;
use pyo3::{pyclass, pymethods, Py, PyRef, PyRefMut, PyResult, Python};

use crate::rule_sets::{EnablePolicy, PyRuleSet};
use crate::ExtraSafeError;

#[pyclass]
#[pyo3(name = "SafetyContext", module = "pyextrasafe")]
#[derive(Debug)]
pub(crate) struct PySafetyContext(Vec<Py<PyRuleSet>>);

impl PySafetyContext {
    fn to_context(&self, py: Python<'_>) -> PyResult<SafetyContext> {
        let mut ctx = SafetyContext::new();
        for policy in &self.0 {
            let policy = &*policy.borrow(py);
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

    #[pyo3(signature = (*policies))]
    fn enable(
        mut ctx: PyRefMut<'_, Self>,
        mut policies: Vec<Py<PyRuleSet>>,
    ) -> PyResult<PyRefMut<'_, Self>> {
        ctx.0.append(&mut policies);
        Ok(ctx)
    }

    fn apply_to_current_thread(&mut self, py: Python<'_>) -> PyResult<()> {
        self.to_context(py)?
            .apply_to_current_thread()
            .map_err(|err| {
                ExtraSafeError::new_err(format!("could not apply to current thread: {err}"))
            })
    }

    fn apply_to_all_threads(&mut self, py: Python<'_>) -> PyResult<()> {
        self.to_context(py)?.apply_to_all_threads().map_err(|err| {
            ExtraSafeError::new_err(format!("could not apply to all threads: {err}"))
        })
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let mut s = "<SafetyContext [".to_owned();
        for (idx, policy) in self.0.iter().enumerate() {
            if idx > 0 {
                s.push_str(", ");
            }
            s.push_str(policy.as_ref(py).repr()?.to_str()?);
        }
        s.push_str("]>");
        Ok(s)
    }

    fn __iter__(ctx: PyRef<'_, Self>) -> SafetyContextIter {
        SafetyContextIter {
            ctx: ctx.into(),
            idx: 0,
        }
    }

    fn __len__(&self) -> usize {
        self.0.len()
    }

    fn __bool__(&self) -> bool {
        !self.0.is_empty()
    }
}

#[pyclass]
#[pyo3(name = "_SafetyContextIter")]
#[derive(Debug)]
struct SafetyContextIter {
    ctx: Py<PySafetyContext>,
    idx: usize,
}

#[pymethods]
impl SafetyContextIter {
    fn __iter__(this: PyRef<'_, Self>) -> PyRef<'_, Self> {
        this
    }

    fn __next__(&mut self, py: Python<'_>) -> Option<Py<PyRuleSet>> {
        let result = self.ctx.borrow(py).0.get(self.idx)?.clone();
        self.idx += 1;
        Some(result)
    }

    fn __index__(&self) -> usize {
        self.idx
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.ctx.borrow(py).0.len().saturating_sub(self.idx)
    }
}
