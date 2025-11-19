"""Compatibility shim to avoid shadowing the real ``flask`` package.

This project previously had an executable named ``flask.py`` at the repository
root. When tools (or the application itself) import :mod:`flask` they would
resolve to this file instead of the actual Flask package from site-packages,
resulting in confusing "module is not callable" errors.  To keep backwards
compatibility without breaking imports, this shim dynamically loads the real
Flask package from the Python installation and re-exports its public members.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from types import ModuleType


def _load_real_flask() -> ModuleType:
    """Locate and load the Flask package from site-packages.

    We iterate over entries in ``sys.path`` looking for a ``flask/__init__.py``
    that does *not* live alongside this shim. Once found, we construct a module
    from that specification and execute it so that callers receive the genuine
    package implementation.
    """

    current_path = pathlib.Path(__file__).resolve()
    current_dir = current_path.parent

    search_paths = [pathlib.Path(p).resolve() for p in sys.path]
    for entry in search_paths:
        if entry == current_dir:
            continue

        candidate_init = entry / "flask" / "__init__.py"
        if candidate_init.exists():
            spec = importlib.util.spec_from_file_location("flask", candidate_init)
            if spec is None or spec.loader is None:
                continue

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)  # type: ignore[assignment]
            return module

    raise ImportError(
        "Unable to locate the real Flask package because the repository contains "
        "a conflicting 'flask.py' shim."
    )


_real_flask = _load_real_flask()

# Mirror the real module's attributes into our module's namespace so that
# ``from flask import Flask`` continues to work as expected.
globals().update({name: getattr(_real_flask, name) for name in dir(_real_flask)})

# Ensure future imports resolve to the genuine module instance.
sys.modules[__name__] = _real_flask

# Provide explicit bindings for common symbols so static analyzers can resolve
# them without having to evaluate the dynamic import machinery above.
Flask = _real_flask.Flask
render_template = _real_flask.render_template
jsonify = _real_flask.jsonify