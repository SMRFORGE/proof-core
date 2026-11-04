"""Conformance: certify a verifier against the canonical evidence-envelope vectors.

This is a coarse, library-mode CLASS check: every 'valid' vector must verify, every 'invalid' one must be
rejected with a plain rejection, every 'unsupported' / 'unsupported-alg' one must get that named fail-forward
verdict, every 'policy' vector must get its exact state under its own policy (or be refused when it carries
expect_error), and 'unreadable' vectors are reported not applicable (see run_conformance). Conformance to SPEC v4
13.3 means the EXACT state of expected_states.json and every expect_* field for every vector, which only
envelope-spec's conformance/run.py checks; use that to call a verifier conformant.

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

#: The manifest's runner protocol. v2 (SPEC v4 draft 13.3) adds the `unreadable` and `policy` expectations, the
#: policy/ directory and the exact-state file `expected_states.json` one directory above the vectors.
CONFORMANCE_SCHEMA = "evidence.conformance.v2"

#: The state of an input the guarded loader refuses (SPEC v4 draft 13.1: "Not a parseable bundle (section 4)").
STATE_UNREADABLE = "unreadable"


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


def _policy_entry(d: pathlib.Path, entry: dict, text: str, policy_fn, states: dict,
                  corpus_as_of: str | None = None) -> tuple[bool, str]:
    """Run one vector under its own policy file (an `expect: "policy"` vector, or a `valid` one that names a policy;
    SPEC v4 13.3), at the vector's `as_of`, else the manifest's `corpus_as_of` (13.3), so a vector whose answer
    depends on time (aging, an archive's end) never reads the wall clock. Returns (ok, got)."""
    if policy_fn is None:
        return False, "not run (the vector has its own policy and no policy_fn was given)"
    try:
        # SPEC 13.3: "the vector's policy, or `policy/default.json` when the vector names none"
        policy = _loads(_safe_vector_path(d, entry.get("policy", "policy/default.json")).read_text(encoding="utf-8"))
        bundle = text                   # the vector's BYTES: the verifier parses them itself (SPEC 4)
    except (OSError, KeyError, ValueError) as exc:
        return False, f"error: {exc}"
    caller_pins = entry.get("caller_pins")
    if caller_pins is None and "expect_policy_sha256" in entry:
        # SPEC 13.3: `expect_policy_sha256` is the digest the runner's verifier COMMAND prints. A CLI with no key of
        # its own merges its built-in demo pins as caller pins (13.4.1 step 3), and they are in the effective policy
        # the digest covers, so this vector runs with them, as the command does.
        from .verify import BUILTIN_DEMO_PINS
        caller_pins = [dict(p) for p in BUILTIN_DEMO_PINS]
    try:
        as_of = entry.get("as_of", corpus_as_of)
        result = (policy_fn(bundle, policy, caller_pins, as_of=as_of) if as_of is not None
                  else policy_fn(bundle, policy, caller_pins))
    except Exception as exc:  # noqa: BLE001 -- the verifier REFUSED the policy: right only when the vector expects that error
        kind = getattr(exc, "kind", None)
        if "expect_error" in entry:
            return kind == entry["expect_error"], f"error {kind!r}"
        return False, f"refused ({type(exc).__name__}: {exc})"
    if "expect_error" in entry:
        return False, "a verdict, but the vector expects the policy to be refused"
    state = result.get("state") if isinstance(result, dict) else None
    if entry.get("expect") == "valid" and not result.get("key_matches_pin"):
        return False, f"a valid vector, but the verdict does not accept ({state!r})"
    want = states.get(entry["file"])
    if want is None:
        return False, "no expected state for this vector in expected_states.json"
    if state != want:
        return False, f"state {state!r}, expected {want!r}"
    if "expect_key_matches_pin" in entry and result.get("key_matches_pin") is not entry["expect_key_matches_pin"]:
        return False, f"key_matches_pin {result.get('key_matches_pin')!r}, expected {entry['expect_key_matches_pin']}"
    # SPEC 13.3: "every `expect_*` field the manifest gives for that vector" -- the decision and the dimensions too
    decision = result.get("decision") if isinstance(result.get("decision"), dict) else {}
    if "expect_decision" in entry and decision.get("accept") is not entry["expect_decision"]:
        return False, f"decision.accept {decision.get('accept')!r}, expected {entry['expect_decision']}"
    if "expect_reasons" in entry and decision.get("reasons") != entry["expect_reasons"]:
        return False, f"decision.reasons {decision.get('reasons')!r}, expected {entry['expect_reasons']}"
    if "expect_policy_sha256" in entry and decision.get("policy_sha256") != entry["expect_policy_sha256"]:
        return False, (f"decision.policy_sha256 {decision.get('policy_sha256')!r}, expected "
                       f"{entry['expect_policy_sha256']}")
    dims = result.get("dims") if isinstance(result.get("dims"), dict) else {}
    for dim, want_dim in entry.get("expect_dims", {}).items():
        if dims.get(dim) != want_dim:
            return False, f"dims.{dim} {dims.get(dim)!r}, expected {want_dim!r}"
    return True, "policy"


def classify_with_policy(bundle, policy, caller_pins=None, as_of=None) -> dict:
    """The reference verifier as a ``policy_fn`` for `run_conformance`: ``classify_bundle`` of the vector's bytes under the vector's
    receiver policy and its out-of-policy caller pins (SPEC v4 draft 13.4.1 step 3), at ``as_of`` (the vector's, or
    the corpus's; None: the current time)."""
    from .verify import classify_bundle
    return classify_bundle(bundle, policy=policy, pins=caller_pins, as_of=as_of)


def walk_chain_with_policy(bundle, upstreams, policy=None, caller_pins=None, as_of=None) -> dict:
    """The reference chain walk as a ``chain_fn`` for `run_conformance`: ``verify_chain`` of the root's bytes through
    the upstreams' bytes, under the vector's receiver policy, caller pins and ``as_of`` (SPEC v4 9.3 trust inputs:
    the same ones as the root's single-bundle verdict). ``policy`` None: the default pin, as `classify_bundle`."""
    from .verify import index_upstreams, verify_chain
    judge = {"policy": policy, "pins": caller_pins, "as_of": as_of}
    return verify_chain(bundle, index_upstreams(upstreams, **judge).get, **judge)


def _chain_entry(d: pathlib.Path, entry: dict, raw: bytes, chain_fn, corpus_as_of) -> tuple[bool, str]:
    """Walk a chain vector (`upstreams` + `expect_chain`) with ``chain_fn`` under the vector's own policy (or none)
    and compare the chain and link states exactly. Returns (ok, got)."""
    try:
        ups = [_safe_vector_path(d, u).read_bytes() for u in entry["upstreams"]]
        policy = (_loads(_safe_vector_path(d, entry["policy"]).read_text(encoding="utf-8"))
                  if "policy" in entry else None)
        want = entry["expect_chain"]
        report = chain_fn(raw, ups, policy, entry.get("caller_pins"),
                          as_of=entry.get("as_of", corpus_as_of) if policy is not None else entry.get("as_of"))
    except Exception as exc:  # noqa: BLE001 -- a walk that raises is a failure of the vector, never a pass
        return False, f"chain walk error ({type(exc).__name__}: {exc})"
    links = [ln.get("state") for ln in report.get("links", [])] if isinstance(report, dict) else None
    got = report.get("chain") if isinstance(report, dict) else None
    if got != want["chain"] or links != want["links"]:
        return False, f"chain {got!r} links {links}, expected chain {want['chain']!r} links {want['links']}"
    return True, "chain"


def _load_states(d: pathlib.Path) -> dict:
    path = d.parent / "expected_states.json"
    if not path.is_file():
        return {}
    states = json.loads(path.read_text(encoding="utf-8")).get("states")
    return states if isinstance(states, dict) else {}


def run_conformance(verify_fn: Callable, vectors_dir, *, policy_fn: Callable | None = None,
                    chain_fn: Callable | None = None) -> dict:
    """Run `verify_fn` over every vector and check it matches the expected verdict.

    Returns {conformant, total, passed, not_applicable, failures:[{file, expected, got}]}. A verifier is
    conformant iff it accepts every 'valid' vector, rejects every 'invalid' one with a plain rejection, and
    reports the named fail-forward verdict for every 'unsupported' / 'unsupported-alg' one.

    `verify_fn` (and ``policy_fn``) receive each vector's exact BYTES and parse them themselves (SPEC 4, 17.3.2), so
    an 'unreadable' vector is checked like any other: the verifier must report the state `unreadable`.
    `not_applicable` is always empty (kept for callers that read it).

    'policy' vectors (runner protocol v2) carry their own receiver policy file. They run through ``policy_fn(bundle,
    policy, caller_pins, as_of=...)`` (the vector's `as_of`, else the manifest's `corpus_as_of`), which returns a classify_bundle-style dict or raises an exception whose ``kind`` names
    the refusal (``"policy"`` for a malformed policy, SPEC 13.4.1). Each must give exactly the state listed in
    ``expected_states.json`` beside the vectors directory, or be refused when it carries ``expect_error``. Without
    a ``policy_fn`` they are NOT RUN, which is a failure (13.3: "the others count as not run, which is a failure of
    the run").

    'chain' vectors (`upstreams` + `expect_chain`, SPEC v4 9.3) are also walked with ``chain_fn(bundle, upstreams,
    policy, caller_pins, as_of=...)`` (the bytes of the root and of each upstream; the vector's policy or None),
    which returns a `verify_chain`-style report whose chain and link states must equal `expect_chain`. Without a
    ``chain_fn`` (a verifier that does not walk chains) only the root's verdict is checked and the vector is listed in
    ``chain_not_checked``: never reported as a checked chain.
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
    not_applicable = []   # 'unreadable' vectors the runner's own loader refused; verify_fn was not consulted
    chain_not_checked = []   # chain vectors whose expect_chain was not walked (no chain_fn)
    states = _load_states(d)
    for entry in vectors:
        try:
            raw = _safe_vector_path(d, entry["file"]).read_bytes()
        except (OSError, KeyError, ValueError) as exc:
            # a missing/renamed/undecodable vector file or a malformed entry is a conformance FAILURE, not an
            # uncaught crash -- a misconfigured battery must never read as conformant.
            failures.append({"file": entry.get("file", "<missing>"), "expected": entry.get("expect"),
                             "got": f"error: {exc}", "note": entry.get("note", "")})
            continue
        # a vector that names its own policy runs under it, whatever its `expect` (SPEC 13.3; a `valid` vector with its
        # own policy, such as the trusted-time vectors that carry test-TSA pins, must reach an accept state under it)
        if isinstance(entry, dict) and (entry.get("expect") == "policy" or "policy" in entry):
            ok, got = _policy_entry(d, entry, raw, policy_fn, states, manifest.get("corpus_as_of"))
            if ok and "expect_chain" in entry:
                if chain_fn is None:
                    chain_not_checked.append(entry["file"])
                else:
                    ok, got = _chain_entry(d, entry, raw, chain_fn, manifest.get("corpus_as_of"))
            if ok:
                passed += 1
            else:
                failures.append({"file": entry["file"], "expected": entry.get("expect"), "got": got,
                                 "note": entry.get("note", "")})
            continue
        # SPEC 4 / 17.3.2: the verifier gets the vector's exact BYTES and parses them itself, so the parse rules
        # (invalid UTF-8, a duplicate key, NaN, an overflowing literal, too deep, too big) are its own verdict
        # (`unreadable`), never a verdict on an object someone else parsed
        try:
            accepted, state, problems = _interpret(verify_fn(raw))
        except (TypeError, ValueError) as exc:
            accepted, state, problems = False, None, [f"the verifier raised {type(exc).__name__}: {exc}"]
        expect = entry["expect"]
        unsupported = _is_unsupported_canon(state, problems)
        unsupported_alg = _is_unsupported_alg(state, problems)
        if state == STATE_UNREADABLE:
            got = "unreadable"
        elif accepted:
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
            ok = got == "invalid"
        elif expect == "unreadable":
            ok = got == "unreadable"
        else:
            ok = False  # an UNRECOGNIZED expect token is a conformance FAILURE, never coerced
            got = f"{got} (unknown expect {expect!r})"
        if ok and isinstance(entry, dict) and "expect_chain" in entry:
            if chain_fn is None:
                chain_not_checked.append(entry["file"])
            else:
                ok, got = _chain_entry(d, entry, raw, chain_fn, manifest.get("corpus_as_of"))
        if ok:
            passed += 1
        else:
            failures.append({"file": entry["file"], "expected": expect,
                             "got": got, "note": entry.get("note", "")})
    total = len(vectors)
    # Conformant iff the verifier passed a NON-EMPTY battery with zero failures. An empty vector set
    # must never certify -- otherwise a reject-everything verifier passes vacuously. The same holds for a
    # battery whose every vector is not applicable: `verify_fn` was never called, so nothing was certified.
    applicable = total - len(not_applicable)
    return {"conformant": applicable > 0 and not failures, "total": total, "passed": passed,
            "not_applicable": not_applicable, "failures": failures, "chain_walk": chain_fn is not None,
            "chain_not_checked": chain_not_checked}


def main(argv: list[str] | None = None) -> int:
    """``python -m proof_verify.conformance VECTORS_DIR``: run THIS package's reference verifier over a vectors
    directory (library mode, `run_conformance` with `classify_with_policy`) and print a one-line summary plus any
    failures. Exit 0 when conformant, 1 when not, 2 on a usage error. To test another verifier, drive it as a
    command with envelope-spec's ``conformance/run.py`` (runner protocol v2) instead."""
    import sys

    from .verify import classify_bundle, safe_text

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] in ("-h", "--help"):
        print("usage: python -P -m proof_verify.conformance VECTORS_DIR   (the directory holding manifest.json;\n"
              "       -P: under -m Python puts the cwd first on the import path, so a planted module would win)",
              file=sys.stderr if args[:1] not in (["-h"], ["--help"]) else sys.stdout)
        return 0 if args[:1] in (["-h"], ["--help"]) else 2
    try:
        report = run_conformance(classify_bundle, args[0], policy_fn=classify_with_policy,
                                 chain_fn=walk_chain_with_policy)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: cannot run the vectors in {safe_text(args[0])}: {safe_text(exc)}", file=sys.stderr)
        return 2
    verdict = "CONFORMANT" if report["conformant"] else "NOT CONFORMANT"
    print(f"{verdict}  passed {report['passed']}, not applicable in library mode "
          f"{len(report['not_applicable'])}, failed {len(report['failures'])}, total {report['total']}")
    for f in report["failures"]:
        print(safe_text(f"  - {f['file']}: expected {f['expected']}, got {f['got']}"))
    return 0 if report["conformant"] else 1


if __name__ == "__main__":
    # `python -m` without -P: say the cwd could shadow this tool (stderr only; see _spec_loader)
    from ._spec_loader import warn_if_cwd_on_path
    warn_if_cwd_on_path()
    raise SystemExit(main())
