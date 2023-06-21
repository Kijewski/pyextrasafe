use std::collections::hash_map::{DefaultHasher, Entry};
use std::collections::HashMap;
use std::fmt::{self, Write};
use std::hash::{Hash, Hasher};

use extrasafe::{Rule, RuleSet, SafetyContext};
use libseccomp::{ScmpArgCompare, ScmpCompareOp};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::pyclass::CompareOp;
use pyo3::types::PyDict;
use pyo3::{pyclass, pymethods, FromPyObject, Py, PyAny, PyCell, PyRefMut, PyResult, Python};
use syscalls::Sysno;

use crate::rule_sets::{DataRuleSet, EnablePolicy, PyRuleSet};
use crate::ExtraSafeError;

pub(crate) fn make_syscall_dict(py: Python<'_>) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    for sysno in Sysno::iter() {
        dict.set_item(sysno.name(), sysno.id())?;
    }
    Ok(dict.as_mapping().into())
}

#[derive(Debug, Default)]
pub(crate) struct DataCustom {
    simple: Vec<Sysno>,
    conditional: HashMap<Sysno, Vec<Rule>>,
}

impl EnablePolicy for DataCustom {
    fn enable_to(&self, ctx: SafetyContext) -> Result<SafetyContext, extrasafe::ExtraSafeError> {
        ctx.enable(self)
    }
}

impl RuleSet for &DataCustom {
    fn simple_rules(&self) -> Vec<Sysno> {
        self.simple.clone()
    }

    fn conditional_rules(&self) -> HashMap<Sysno, Vec<Rule>> {
        self.conditional.clone()
    }

    fn name(&self) -> &'static str {
        "custom"
    }
}

#[pyclass(name = "Custom", module = "pyextrasafe", extends = PyRuleSet)]
pub(crate) struct PyCustom;

#[pymethods]
impl PyCustom {
    #[new]
    fn new() -> (Self, PyRuleSet) {
        (
            Self,
            PyRuleSet(DataRuleSet::PyCustom(DataCustom::default().into())),
        )
    }

    fn add_simple(mut this: PyRefMut<'_, Self>, sysno: usize) -> PyResult<PyRefMut<'_, Self>> {
        let sysno =
            Sysno::new(sysno).ok_or_else(|| ExtraSafeError::new_err("unknown syscall number"))?;
        let simple = match &mut this.as_mut().0 {
            DataRuleSet::PyCustom(custom) => &mut custom.as_mut().simple,
            _ => unreachable!("Impossible content"),
        };

        if let Err(pos) = simple.binary_search(&sysno) {
            simple.insert(pos, sysno);
        }
        Ok(this)
    }

    fn add_conditional(mut this: PyRefMut<'_, Self>, rule: PyRule) -> PyResult<PyRefMut<'_, Self>> {
        let PyRule(syscall, comparators) = rule;
        let syscall =
            Sysno::new(syscall).ok_or_else(|| ExtraSafeError::new_err("unknown syscall number"))?;
        let rule = Rule {
            syscall,
            comparators: comparators.iter().map(Into::into).collect(),
        };

        let conditional = match &mut this.as_mut().0 {
            DataRuleSet::PyCustom(custom) => &mut custom.as_mut().conditional,
            _ => unreachable!("Impossible content"),
        };
        match conditional.entry(syscall) {
            Entry::Occupied(mut rules) => rules.get_mut().push(rule),
            Entry::Vacant(rules) => {
                let _: &mut Vec<Rule> = rules.insert(Vec::with_capacity(1));
            },
        }

        Ok(this)
    }
}

#[pyclass(name = "Rule", module = "pyextrasafe", frozen)]
#[derive(Debug, FromPyObject)]
pub(crate) struct PyRule(usize, Vec<PyCompare>);

#[pymethods]
impl PyRule {
    #[new]
    fn new(syscall: usize, comparators: Vec<PyCompare>) -> Self {
        Self(syscall, comparators)
    }

    fn __repr__(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for PyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let &Self(syscall, ref comparators) = self;
        write!(f, "Rule({}, {})", syscall, Slice(comparators.as_slice()))
    }
}

struct Slice<'a, T>(&'a [T]);

impl<T: fmt::Display> fmt::Display for Slice<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('[')?;
        for (idx, elem) in self.0.iter().enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{elem}")?;
        }
        f.write_char(']')
    }
}

#[pyclass(name = "Compare", module = "pyextrasafe", frozen)]
#[derive(Debug, FromPyObject)]
pub(crate) struct PyCompare(u32, PyCompareOp, u64);

#[pymethods]
impl PyCompare {
    #[new]
    fn new(arg: u32, op: PyCompareOp, datum: u64) -> PyResult<Self> {
        Ok(Self(arg, op, datum))
    }

    fn __repr__(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for PyCompare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Compare({}, {}, {})", &self.0, &self.1, &self.2)
    }
}

impl From<&PyCompare> for ScmpArgCompare {
    fn from(value: &PyCompare) -> Self {
        ScmpArgCompare::new(value.0, value.1.0, value.2)
    }
}

#[pyclass(name = "CompareOp", module = "pyextrasafe", frozen)]
#[derive(Debug)]
pub(crate) struct PyCompareOp(ScmpCompareOp);

impl From<&PyCompareOp> for ScmpCompareOp {
    fn from(value: &PyCompareOp) -> Self {
        value.0
    }
}

impl PyCompareOp {
    fn as_tuple(&self) -> (u8, u64) {
        match self.0 {
            ScmpCompareOp::NotEqual => (0, 0),
            ScmpCompareOp::Less => (1, 0),
            ScmpCompareOp::LessOrEqual => (2, 0),
            ScmpCompareOp::Equal => (3, 0),
            ScmpCompareOp::GreaterEqual => (4, 0),
            ScmpCompareOp::Greater => (5, 0),
            ScmpCompareOp::MaskedEqual(v) => (6, v),
            _ => unreachable!(),
        }
    }
}

#[pymethods]
#[allow(non_snake_case)]
impl PyCompareOp {
    #[classattr]
    fn NotEqual() -> Self {
        Self(ScmpCompareOp::NotEqual)
    }

    #[classattr]
    fn Less() -> Self {
        Self(ScmpCompareOp::Less)
    }

    #[classattr]
    fn LessOrEqual() -> Self {
        Self(ScmpCompareOp::LessOrEqual)
    }

    #[classattr]
    fn Equal() -> Self {
        Self(ScmpCompareOp::Equal)
    }

    #[classattr]
    fn GreaterEqual() -> Self {
        Self(ScmpCompareOp::GreaterEqual)
    }

    #[classattr]
    fn Greater() -> Self {
        Self(ScmpCompareOp::Greater)
    }

    #[staticmethod]
    fn MaskedEqual(mask: u64) -> Self {
        Self(ScmpCompareOp::MaskedEqual(mask))
    }

    #[getter]
    fn mask(&self) -> Option<u64> {
        if let ScmpCompareOp::MaskedEqual(mask) = self.0 {
            Some(mask)
        } else {
            None
        }
    }

    fn __repr__(&self) -> String {
        self.to_string()
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> bool {
        op.matches(self.as_tuple().cmp(&other.as_tuple()))
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.as_tuple().hash(&mut hasher);
        hasher.finish()
    }
}

impl fmt::Display for PyCompareOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ScmpCompareOp::NotEqual => "CompareOp.NotEqual",
            ScmpCompareOp::Less => "CompareOp.Less",
            ScmpCompareOp::LessOrEqual => "CompareOp.LessOrEqual",
            ScmpCompareOp::Equal => "CompareOp.Equal",
            ScmpCompareOp::GreaterEqual => "CompareOp.GreaterEqual",
            ScmpCompareOp::Greater => "CompareOp.Greater",
            ScmpCompareOp::MaskedEqual(v) => return write!(f, "CompareOp.MaskedEqual({v})"),
            _ => unreachable!("impossible content"),
        })
    }
}

impl<'source> FromPyObject<'source> for PyCompareOp {
    fn extract(obj: &'source PyAny) -> PyResult<Self> {
        let cell: Result<&PyCell<Self>, _> = obj.downcast();
        if let Ok(cell) = cell {
            return Ok(Self(cell.try_borrow()?.0));
        }

        let mask: Result<u64, _> = obj.extract();
        if let Ok(mask) = mask {
            return Ok(Self(ScmpCompareOp::MaskedEqual(mask)));
        }

        let s: Result<String, _> = obj.extract();
        if let Ok(s) = s {
            return match s.as_str() {
                "!=" => Ok(Self(ScmpCompareOp::NotEqual)),
                "<" => Ok(Self(ScmpCompareOp::Less)),
                "<=" => Ok(Self(ScmpCompareOp::LessOrEqual)),
                "==" => Ok(Self(ScmpCompareOp::Equal)),
                ">=" => Ok(Self(ScmpCompareOp::GreaterEqual)),
                ">" => Ok(Self(ScmpCompareOp::Greater)),
                s => Err(PyValueError::new_err(format!("unknown comparator: {s}"))),
            };
        }

        Err(PyTypeError::new_err("expected: CompareOp | str | int"))
    }
}
