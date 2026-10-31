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

from .verify import (
    STATE_UNSUPPORTED_ALG,  # signature-suite fail-forward verdict
    STATE_UNSUPPORTED_CANON,  # ADR-050: the named fail-forward verdict
)
from .verify import loads as _loads  # the ONE guarded loader (dup-key / NaN / depth / size)

CONFORMANCE_SCHEMA = "evidence.conformance.v1"


def _interpret(result) -> tuple[bool, str | None, list[str]]:
    """Normalise a verifier's return to `(accepted, state, problems)`.

    `accepted` is the conformance ACCEPT answer (well-formed + signed under the pinned key). A verifier may
    return a bare bool (that answer, no detail), an `(ok, problems)` tuple, or a `classify_bundle`-style dict
    (ADR-050: the shape needed to tell a fail-FORWARD `unsupported-canon` verdict from a plain rejection --
    `state` carries the named verdict, or the token appears in `problems`)."""
    if isinstance(result, dict):
        accepted = bool(result.get("key_matches_pin", result.get("integrity_ok", False)))
        problems = [str(p) for p in (result.get("problems") or [])]
        return accepted, result.get("state"), problems
    if isinstance(result, tuple):
        problems = [str(p) for p in (result[1] if len(result) > 1 and isinstance(result[1], (list, tuple)) else [])]
        return bool(result[0]), None, problems
    return bool(result), None, []


def _is_unsupported_canon(state: str | None, problems: list[str]) -> bool:
    """ADR-050: did the verifier report the DISTINCT fail-forward verdict (not a plain rejection)? True when
    the named state is exposed, or the literal token rides in the problems list."""
    # `state` is authoritative when exposed; the substring fallback is only for verifiers that expose none
    # (a problem string can echo attacker-chosen text, so it must never override a named state).
    if state is not None:
        return state == STATE_UNSUPPORTED_CANON
    return any(STATE_UNSUPPORTED_CANON in p for p in problems)


def _is_unsupported_alg(state, problems) -> bool:
    # `state` is authoritative. The substring fallback is ONLY for verifiers that expose no state
    # (bool/tuple): the unsupported-alg MESSAGE also rides in `problems` of a plain FAIL (an unknown
    # suite PLUS a real tamper), where the verdict is `fail`, not the fail-forward.
    if state is not None:
        return state == STATE_UNSUPPORTED_ALG
    return any(STATE_UNSUPPORTED_ALG in p for p in problems)


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
            text = _safe_vector_path(d, entry["file"]).read_text(encoding="utf-8")
        except (OSError, KeyError, ValueError) as exc:
            # a missing/renamed/undecodable vector file or a malformed entry is a conformance FAILURE, not an
            # uncaught crash -- a misconfigured battery must never read as conformant.
            failures.append({"file": entry.get("file", "<missing>"), "expected": entry.get("expect"),
                             "got": f"error: {exc}", "note": entry.get("note", "")})
            continue
        try:
            bundle = _loads(text)
        except ValueError as exc:
            # the hardened loader REFUSED the text (dup key, NaN, too deep, too big): that is a rejection, the
            # same verdict the CLI gives -- correct for an 'invalid' vector, a failure for any other expectation
            # (the JS runner counts a parse rejection the same way).
            accepted, state, problems = False, "fail", [f"unreadable: {exc}"]
        else:
            accepted, state, problems = _interpret(verify_fn(bundle))
        expect = entry["expect"]
        unsupported = _is_unsupported_canon(state, problems)
        unsupported_alg = _is_unsupported_alg(state, problems)
        if accepted:
            got = "valid"
        elif unsupported:
            got = "unsupported"
        elif unsupported_alg:
            got = "unsupported-alg"
        else:
            got = "invalid"
        if expect == "valid":
            ok = accepted
        elif expect == "unsupported":
            ok = (not accepted) and unsupported
        elif expect == "unsupported-alg":
            ok = (not accepted) and unsupported_alg
        elif expect == "invalid":
            ok = (not accepted) and not unsupported and not unsupported_alg
        else:
            ok = False  # an UNRECOGNIZED expect token is a conformance FAILURE, never coerced
            got = f"{got} (unknown expect {expect!r})"
        if ok:
            passed += 1
        else:
            failures.append({"file": entry["file"], "expected": expect,
                             "got": got, "note": entry.get("note", "")})
    total = len(vectors)
    # Conformant iff the verifier passed a NON-EMPTY battery with zero failures. An empty vector set
    # must never certify -- otherwise a reject-everything verifier passes vacuously.
    return {"conformant": bool(vectors) and not failures, "total": total, "passed": passed,
            "failures": failures}
