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
when the working directory holds files you did not write. Each ``python -m`` entry warns on stderr when run that
way (:func:`warn_if_cwd_on_path`), but cannot warn if a planted module has already replaced it.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import uuid

#: the one stderr line a ``python -m`` run prints when the current directory is first on the import path.
CWD_ON_PATH_WARNING = ("warning: running without -P: modules in the current folder could shadow this tool; use the "
                       "installed command or python -P -m")


def cwd_first_on_path() -> bool:
    """True when ``sys.path[0]`` is the current directory: ``python -m`` without ``-P`` (or ``-I`` / PYTHONSAFEPATH).
    False under ``-P`` and for a console script (whose ``sys.path[0]`` is the script's own folder)."""
    if getattr(sys.flags, "safe_path", False) or not sys.path:
        return False
    first = sys.path[0]
    if first == "":
        return True
    try:
        return os.path.normcase(os.path.realpath(first)) == os.path.normcase(os.path.realpath(os.getcwd()))
    except (OSError, ValueError):
        return False


def warn_if_cwd_on_path() -> None:
    """A cheap mitigation, not a fix: called from each ``if __name__ == "__main__"`` block (the ``python -m`` entry,
    never a console script), it prints :data:`CWD_ON_PATH_WARNING` to stderr when the cwd is first on the import
    path. Exit codes and stdout (the JSON verdict) are unchanged. Its limit: if a module planted in the current
    folder does shadow this tool (a ``proof_verify/`` or ``proof_core/`` package there), the planted code runs
    INSTEAD of this one and this warning never prints. Only ``-P`` or the installed command closes that."""
    if cwd_first_on_path():
        print(CWD_ON_PATH_WARNING, file=sys.stderr)


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


def resolve_profile(spec: str):
    """Import the reviewer-named ``pkg.module:attr`` dialect Profile and return it (a class is instantiated with no
    args; a constructed Profile is used as-is). Duck-typed: the verifier reads a profile attribute-only, so any object
    carrying the dialect fields works, and this stdlib-only module imports the CONSUMER's module, never proof_core.
    It reads ONLY the command-line ``spec``, never the bundle, and the current directory is never on the import path:
    a sender-planted profile in an unpacked bundle folder would pin the sender's key and read as an origin pass. A
    module comes from the normal import path (PYTHONPATH / installed); a file is named by an absolute path,
    ``/abs/path/file.py:attr``. Every failure -- a module, attribute or class that calls ``sys.exit()``, or raises
    anything at all (any BaseException but KeyboardInterrupt, which is the reviewer's own and propagates) -- is a
    ValueError with a plain reason, which each CLI maps to a usage exit; the reason is built by
    :func:`describe_exception`, so an exception whose ``__str__`` or type name is itself broken cannot turn the reason
    into a second exception. The one resolver behind ``--profile`` in proof-verify, proof-reproduce and proof-seal."""
    module_name, attr_path = split_spec(spec, "--profile", "pkg.module:attr")
    try:
        obj = import_spec_module(module_name, "profile")
    except ImportError as exc:
        raise ValueError(f"cannot import profile module {module_name!r}: {exception_text(exc)}") from exc
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:  # a module that calls sys.exit() at import is an unusable --profile arg, never our exit
        raise ValueError(f"profile module {module_name!r} called sys.exit({exit_code_text(exc.code)}) at import") from exc
    except BaseException as exc:  # any other import-time failure is a bad --profile arg, not a CLI crash
        raise ValueError(f"profile module {module_name!r} failed to import: {describe_exception(exc)}") from exc
    for part in attr_path.split("."):
        try:
            obj = getattr(obj, part)
        except AttributeError as exc:
            raise ValueError(f"profile {spec!r} not found: {exception_text(exc)}") from exc
        except KeyboardInterrupt:
            raise
        except SystemExit as exc:  # a module __getattr__ / descriptor that calls sys.exit()
            raise ValueError(f"reading profile {spec!r} called sys.exit({exit_code_text(exc.code)})") from exc
        except BaseException as exc:  # a module __getattr__ / descriptor that raises anything else: a bad --profile arg
            raise ValueError(f"reading profile {spec!r} failed: {describe_exception(exc)}") from exc
    try:
        return obj() if isinstance(obj, type) else obj
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:
        raise ValueError(f"constructing profile {spec!r} called sys.exit({exit_code_text(exc.code)})") from exc
    except BaseException as exc:  # a Profile whose construction raises is a bad --profile arg, not a crash
        raise ValueError(f"cannot construct profile {spec!r}: {describe_exception(exc)}") from exc


#: the most characters of reviewer-code text (an exception message, a type name, a sys.exit code) a message carries
_TEXT_LIMIT = 200


def _clip(text: str) -> str:
    return text if len(text) <= _TEXT_LIMIT else text[:_TEXT_LIMIT] + "..."


def safe_type_name(obj) -> str:
    """``type(obj).__name__`` for a message, never a second exception: a metaclass whose ``__name__`` raises or is not
    a string is named as such. Truncated."""
    try:
        name = type(obj).__name__
        if not isinstance(name, str):
            raise TypeError(name)           # one fallback for both shapes
    except KeyboardInterrupt:
        raise
    except BaseException:  # noqa: BLE001 -- reviewer-code metaclass (any exception type); the message must still print
        return "<type whose __name__ could not be read>"
    return _clip(name)


def exception_text(exc: BaseException) -> str:
    """``str(exc)`` for a message, never a second exception: a ``__str__`` that raises (a RecursionError from one that
    recurses included), or returns a non-string, is named as such; the text is truncated (a 5 MB message is 200
    characters), so the message is always printable."""
    try:
        text = str(exc)
    except KeyboardInterrupt:
        raise
    except BaseException as inner:  # noqa: BLE001 -- reviewer-code __str__ (any exception type); must still print
        return f"<str() raised {safe_type_name(inner)}>"
    return _clip(text)


def describe_exception(exc: BaseException) -> str:
    """``TypeName: text`` of an exception raised by reviewer code (a profile, a runner), built so that formatting it
    can never raise: see :func:`safe_type_name` and :func:`exception_text`."""
    return f"{safe_type_name(exc)}: {exception_text(exc)}"


def exit_code_text(code) -> str:
    """``repr(code)`` of a SystemExit's code for a message, never a second exception: a code whose ``__repr__`` raises
    is named by type, and a long one is truncated. (``sys.exit(x)`` accepts any object as ``x``.)"""
    try:
        text = repr(code)
    except KeyboardInterrupt:
        raise
    except BaseException:  # noqa: BLE001 -- reviewer-code repr (any exception type); the message must still print
        return f"<{safe_type_name(code)} whose repr raised>"
    return _clip(text)


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
