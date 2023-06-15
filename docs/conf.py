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
    "sphinx.ext.inheritance_diagram",
    "sphinx.ext.graphviz",
    "sphinx_immaterial",
]

display_toc = True
autodoc_default_flags = ["members"]
autosummary_generate = True
napoleon_google_docstring = False
napoleon_numpy_docstring = True
autosectionlabel_prefix_document = True
templates_path = ["_templates"]
source_suffix = ".rst"
master_doc = "index"
language = "en"
exclude_patterns = []
pygments_style = "sphinx"
todo_include_todos = False
autoclass_content = "both"
add_module_names = False
nitpicky = True

graphviz_output_format = "svg"
inheritance_graph_attrs = {
    "size": '"6.0, 8.0"',
    "fontsize": 32,
    "bgcolor": "transparent",
}
inheritance_node_attrs = {
    "color": '"#ef5552"',
    "fillcolor": "white",
    "fontcolor": '"#000000de"',
    "style": '"filled,solid"',
}
inheritance_edge_attrs = {
    "penwidth": 1.2,
    "arrowsize": 0.8,
    "color": '"#ef5552"',
}

html_theme = "sphinx_immaterial"
# html_static_path = ["_static"]
# html_css_files = ["custom.css"]

project = "PyExtraSafe"
copyright = "2023, René Kijewski"
author = "René Kijewski"

release = pyextrasafe.__version__
version = re.match(r"\A\d+\.\d+\.\d+", release).group(0)

intersphinx_mapping = {
    "python": ("https://docs.python.org/3.11", None),
}

html_theme_options = {
    "icon": {
        "repo": "fontawesome/brands/github",
        "edit": "material/file-edit-outline",
    },
    "site_url": "https://pyextrasafe.readthedocs.io/",
    # "repo_url": "https://www.github.com/Kijewski/pyextrasafe/",
    "repo_name": "PyExtraSafe",
    "globaltoc_collapse": True,
    "features": [
        "navigation.top",
        "navigation.tracking",
        "search.highlight",
        "search.share",
        "toc.follow",
        "toc.sticky",
        "content.tabs.link",
        "announce.dismiss",
    ],
    "palette": [
        {
            "media": "(prefers-color-scheme: dark)",
            "scheme": "slate",
            "primary": "red",
            "accent": "light-green",
            "toggle": {
                "icon": "material/weather-night",
                "name": "Switch to light mode",
            },
        },
        {
            "media": "(prefers-color-scheme: light)",
            "scheme": "default",
            "primary": "red",
            "accent": "light-green",
            "toggle": {
                "icon": "material/weather-sunny",
                "name": "Switch to dark mode",
            },
        },
    ],
    "toc_title_is_page_title": True,
    "social": [
        {
            "icon": "fontawesome/brands/github",
            "link": "https://github.com/Kijewski/pyextrasafe/",
            "name": "Source on github.com",
        },
        {
            "icon": "fontawesome/brands/python",
            "link": "https://pypi.org/project/pyextrasafe/",
        },
    ],
    "font": {
        "text": "Source Sans 3",
        "code": "Source Code Pro",
    },
    "version_dropdown": True,
    "version_info": [
        {
            "version": "https://pyextrasafe.readthedocs.io",
            "title": "Read the Docs",
            "aliases": [],
        },
        {
            "version": "https://github.com/Kijewski/pyextrasafe",
            "title": "Github",
            "aliases": [],
        },
        {
            "version": "https://pypi.org/project/pyextrasafe",
            "title": "PyPI",
            "aliases": [],
        },
    ],
}
sphinx_immaterial_bundle_source_maps = True

templates_path = ["_templates"]
