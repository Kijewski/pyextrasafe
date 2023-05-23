import os
import re
import sys

sys.path.insert(0, os.path.abspath(".."))

import pyextrasafe


needs_sphinx = "6.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx_autodoc_typehints",
]

display_toc = True
autodoc_default_flags = ["members"]
autosummary_generate = True
napoleon_google_docstring = False
autosectionlabel_prefix_document = True
templates_path = ["_templates"]
source_suffix = ".rst"
master_doc = "index"
language = "en"
exclude_patterns = []
pygments_style = "sphinx"
todo_include_todos = False
autoclass_content = "both"

html_theme = "furo"
html_static_path = ["_static"]
html_css_files = ["custom.css"]

project = "PyExtraSafe"
copyright = "2023, René Kijewski"
author = "René Kijewski"

release = pyextrasafe.__version__
version = re.match(r"\A\d+\.\d+\.\d+", release).group(0)

intersphinx_mapping = {
    "python": ("https://docs.python.org/3.11", None),
}
