"""Conformance: certify a verifier against the canonical evidence-envelope vectors.

Anyone who writes (or uses) an independent verifier can prove it CONFORMS by running it against
these vectors: every VALID bundle must verify, every INVALID bundle must be rejected. A tool
that passes here behaves like the reference on the whole battery of accept/reject cases -- it is
how "verify without the tool that produced it" is made checkable rather than promised.

stdlib only; imports nothing from the producer. `run_conformance(verify_fn, vectors_dir)` takes
any callable returning either `bool` or `(ok, problems)`.
"""
from __future__ import annotations

import json
import pathlib
from collections.abc import Callable

from .verify import loads as _loads  # the ONE guarded loader (dup-key / NaN / depth / size)

CONFORMANCE_SCHEMA = "evidence.conformance.v1"


def _ok(result) -> bool:
    """Normalise a verifier's return: accept bool or (ok, problems)."""
    if isinstance(result, tuple):
        return bool(result[0])
    return bool(result)


def load_manifest(vectors_dir) -> dict:
    d = pathlib.Path(vectors_dir)
    return json.loads((d / "manifest.json").read_text(encoding="utf-8"))


def _safe_vector_path(d: pathlib.Path, name) -> pathlib.Path:
    """Resolve a manifest-supplied vector path, CONSTRAINED to stay inside the vectors dir.

    The manifest is data the certifier is merely pointed at; without a guard, an entry naming an absolute
    path or a `..` traversal would let an untrusted manifest read files OUTSIDE the vectors dir. Reject an
    absolute path, any `..` component, and anything that resolves outside `d`; a legitimate in-tree subpath
    (e.g. `valid/good_ops.json`) is allowed. A rejected entry raises ValueError, which the caller records as
    a conformance FAILURE (fail closed) rather than reading the file."""
    if not isinstance(name, str) or not name:
        raise ValueError(f"vector 'file' must be a non-empty string, got {name!r}")
    p = pathlib.PurePath(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"vector 'file' must be a relative path inside the vectors dir "
                         f"(no absolute path or '..'): {name!r}")
    base = d.resolve()
    resolved = (base / p).resolve()
    if resolved != base and base not in resolved.parents:
        raise ValueError(f"vector 'file' resolves outside the vectors dir: {name!r}")
    return resolved


def run_conformance(verify_fn: Callable, vectors_dir) -> dict:
    """Run `verify_fn` over every vector and check it matches the expected verdict.

    Returns {conformant, total, passed, failures:[{file, expected, got}]}. A verifier is
    conformant iff it accepts every 'valid' vector and rejects every 'invalid' one.
    """
    d = pathlib.Path(vectors_dir)
    manifest = load_manifest(d)
    vectors = manifest.get("vectors")
    if vectors is None:
        raise ValueError("conformance manifest has no 'vectors' list -- cannot certify a verifier")
    if not isinstance(vectors, list):
        raise TypeError("conformance manifest 'vectors' must be a list")
    failures = []
    passed = 0
    for entry in vectors:
        try:
            bundle = _loads(_safe_vector_path(d, entry["file"]).read_text(encoding="utf-8"))
        except (OSError, KeyError, ValueError) as exc:
            # a missing/renamed vector file or a malformed entry is a conformance FAILURE, not an
            # uncaught crash -- a misconfigured battery must never read as conformant.
            failures.append({"file": entry.get("file", "<missing>"), "expected": entry.get("expect"),
                             "got": f"error: {exc}", "note": entry.get("note", "")})
            continue
        got = _ok(verify_fn(bundle))
        expected = entry["expect"] == "valid"
        if got == expected:
            passed += 1
        else:
            failures.append({"file": entry["file"], "expected": entry["expect"],
                             "got": "valid" if got else "invalid", "note": entry.get("note", "")})
    total = len(vectors)
    # Conformant iff the verifier passed a NON-EMPTY battery with zero failures. An empty vector set
    # must never certify -- otherwise a reject-everything verifier passes vacuously.
    return {"conformant": bool(vectors) and not failures, "total": total, "passed": passed,
            "failures": failures}
