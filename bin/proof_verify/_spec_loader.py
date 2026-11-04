"""Resolve a command-line ``module:attr`` or ``/abs/path/file.py:attr`` spec to a Python object (stdlib only).

Shared by every CLI that imports reviewer-named code: ``proof-verify --profile``, ``proof-reproduce --runner`` /
``--profile`` and ``proof-seal --profile``. The spec is read ONLY from the command line, never from a bundle.

The current directory is never added to the import path. A reviewer often runs these tools inside an unpacked
bundle folder, and a sender can put a ``myrunner.py`` or ``acme_profile.py`` there; if the cwd were importable,
that file would replace the reviewer's own runner or profile (a reproduce that hands back the sealed value, or a
profile that pins the sender's key). So:

- ``pkg.module:attr`` imports through the normal import path only (installed packages, ``PYTHONPATH``);
- ``/abs/path/file.py:attr`` loads exactly that file. The path MUST be absolute (on Windows a drive and a root,
  ``C:\\...``, or a UNC ``\\\\server\\share\\...`` path): a relative path, and on Windows a drive-relative
  ``\\x.py`` or ``C:x.py``, is resolved against the current directory (or the current drive's), which is the folder
  a sender can fill -- the same rule as ``PROOF_POLICY``. A relative file spec is a usage error.

Note that ``python -m <tool>`` itself puts the current directory first on ``sys.path`` (a Python behavior, not
this module's); use the console script (``proof-verify``, ``proof-reproduce``, ``proof-seal``) or ``python -P -m``
when the working directory holds files you did not write.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import uuid


def is_file_spec(module_part: str) -> bool:
    """True when the part before the last ``:`` names a file (``.py`` suffix or a path separator)."""
    return module_part.endswith(".py") or "/" in module_part or "\\" in module_part


def is_absolute_file_path(path: str, *, windows: bool | None = None) -> bool:
    """True only for a path that does not depend on the current directory. POSIX: starts at ``/``. Windows: a drive
    AND a root (``C:\\x``) or a UNC share (``\\\\server\\share\\x``); ``\\x`` (root of the current drive) and
    ``C:x`` (cwd of drive C) are refused, though some Pythons call ``\\x`` absolute."""
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        import posixpath
        return posixpath.isabs(path)
    import ntpath
    drive, rest = ntpath.splitdrive(path)
    return bool(drive) and rest[:1] in ("\\", "/")


def split_spec(spec: str, flag: str, form: str) -> tuple[str, str]:
    """Split ``spec`` at its LAST ``:`` (so a Windows ``C:\\...\\x.py:attr`` path works). ValueError (a usage error)
    if malformed, or if it names a file by a path that is not absolute."""
    module_part, sep, attr_path = spec.rpartition(":")
    if not sep or not module_part or not attr_path or is_file_spec(attr_path):
        raise ValueError(f"{flag} must be '{form}' or '/abs/path/file.py:attr' (got {spec!r})")
    if is_file_spec(module_part) and not is_absolute_file_path(module_part):
        raise ValueError(
            f"{flag}: a file must be named by an ABSOLUTE path (got {module_part!r}): a relative path is read from "
            "the current directory, which may be an unpacked bundle folder whose sender put a file there. Use "
            f"'/abs/path/file.py:attr', or put the module on PYTHONPATH and use '{form}'")
    return module_part, attr_path


def _load_file(path: str, what: str):
    full = os.path.abspath(path)
    if not os.path.isfile(full):
        raise ImportError(f"no such file {full!r}")
    name = f"_proof_cli_{what}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, full)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {full!r} as a Python module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses / pickling look a module up by name while it executes
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def import_spec_module(module_part: str, what: str):
    """Import the module half of a spec: a named file, or a module on the normal import path (never the cwd)."""
    if is_file_spec(module_part):
        return _load_file(module_part, what)
    return importlib.import_module(module_part)
