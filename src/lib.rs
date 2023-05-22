// Copyright (c) 2023 Kijewski <pypi.org@k6i.de>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![warn(absolute_paths_not_starting_with_crate)]
#![warn(elided_lifetimes_in_paths)]
#![warn(explicit_outlives_requirements)]
#![warn(meta_variable_misuse)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(non_ascii_idents)]
#![warn(noop_method_call)]
#![warn(single_use_lifetimes)]
#![warn(unreachable_pub)]
#![warn(unused_extern_crates)]
#![warn(unused_lifetimes)]
#![warn(unused_results)]

//! PyExtraSafe is a library that makes it easy to improve your program’s security by selectively
//! allowing the syscalls it can perform via the Linux kernel’s seccomp facilities.

mod rule_sets;
mod safety_ctx;

use pyo3::exceptions::PyException;
use pyo3::types::PyModule;
use pyo3::{pymodule, PyResult, PyTypeInfo, Python};

pyo3::create_exception!(
    pyextrasafe,
    ExtraSafeError,
    PyException,
    "An exception thrown by PyExtraSafe."
);

#[pymodule]
fn _pyextrasafe(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<self::rule_sets::PyBasicCapabilities>()?;
    m.add_class::<self::rule_sets::PyForkAndExec>()?;
    m.add_class::<self::rule_sets::PyNetworking>()?;
    m.add_class::<self::rule_sets::PyRuleSet>()?;
    m.add_class::<self::rule_sets::PySystemIO>()?;
    m.add_class::<self::rule_sets::PyThreads>()?;
    m.add_class::<self::rule_sets::PyTime>()?;
    m.add_class::<self::safety_ctx::PySafetyContext>()?;
    m.add("__author__", env!("CARGO_PKG_AUTHORS"))?;
    m.add("__license__", env!("CARGO_PKG_LICENSE"))?;
    m.add("__version__", env!("pyextrasafe-version"))?;
    m.add("ExtraSafeError", ExtraSafeError::type_object(py))?;
    Ok(())
}
