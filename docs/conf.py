# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
from sphinx.application import Sphinx

sys.path.append(os.path.join(os.getcwd(), ".."))


# -- Project information -----------------------------------------------------

project = "GHAS Compliance"
copyright = "2021, GeekMasher"
author = "GeekMasher"

# The full version, including alpha/beta/rc tags
release = "v1.5"


# -- General configuration ---------------------------------------------------
extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.todo",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.autosectionlabel",
]

master_doc = "index"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

source_suffix = {
    ".rst": "restructuredtext",
    ".txt": "markdown",
    ".md": "markdown",
}

pygments_style = "sphinx"

# -- Options for HTML output -------------------------------------------------
html_theme = "alabaster"
html_static_path = ["_static"]

html_logo = "_static/SecurityPolicy.png"

htmlhelp_basename = "GHASComplianceDoc"

# -- Options for Napoleon output ------------------------------------------------

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True

# -- Options for manual page output ------------------------------------------
man_pages = [
    (master_doc, "ghascompliance", "GHASCompliance Documentation", [author], 1)
]

# -- Options for Texinfo output ----------------------------------------------
texinfo_documents = [
    (
        master_doc,
        "GHASCompliance",
        "GHASCompliance Documentation",
        author,
        "GHASCompliance",
        "One line description of project.",
        "Miscellaneous",
    ),
]


# unwrap decorators
def unwrap_decorators():
    import sphinx.util.inspect as inspect
    import functools

    old_getargspec = inspect.getargspec

    def getargspec(x):
        return old_getargspec(getattr(x, "_original_function", x))

    inspect.getargspec = getargspec

    old_update_wrapper = functools.update_wrapper

    def update_wrapper(wrapper, wrapped, *a, **kw):
        rv = old_update_wrapper(wrapper, wrapped, *a, **kw)
        rv._original_function = wrapped
        return rv

    functools.update_wrapper = update_wrapper


unwrap_decorators()
del unwrap_decorators


def setup(app: Sphinx):
    def cut_module_meta(app, what, name, obj, options, lines):
        """Remove metadata from autodoc output."""
        if what != "module":
            return

        lines[:] = [
            line for line in lines if not line.startswith((":copyright:", ":license:"))
        ]

    app.connect("autodoc-process-docstring", cut_module_meta)
