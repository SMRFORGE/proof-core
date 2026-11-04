"""The evidence.result.v1 core: one lightweight, schema-tagged result envelope emitted identically
by every surface a producer exposes (CLI / REST / MCP / library call) -- a `result` payload keyed by
capability name, a mandatory `fidelity`, a `verdict` (pass/advisory/fail), optional `caveats`, a
`provenance` stub. The evidence envelope is a strict superset that embeds THIS shape unchanged.
"""
from __future__ import annotations

from collections.abc import Sequence

from .contract import Case, Result

SCHEMA = "evidence.result.v1"
REQUIRED = ("schema", "schema_version", "result", "fidelity", "verdict")  # per ADR-036


def build_result_core(case: Case, result: Result, *, profile=None) -> dict:
    # `profile` (domain-neutral, additive) selects the schema NAMESPACE; None = the spine's own
    # `evidence.*` dialect, whose literals equal the module constants below, so the default path's bytes
    # are unchanged. A branded producer passes its own proof_core.profile.Profile.
    from .profile import NEUTRAL
    p = profile or NEUTRAL
    core = {
        "schema": p.result_schema,
        "schema_version": p.result_schema_version,
        "result": {result.capability: result.outputs},   # keyed by capability name
        "fidelity": result.fidelity.value,                # mandatory, never dropped
        "verdict": result.verdict.value,                  # drives the process exit code
        "caveats": list(result.caveats),
        # Provenance names the capability only -- the raw inputs are NOT duplicated here. They live in
        # the dedicated `inputs` manifest section (which `reproduce` reads); embedding a second copy in
        # the sealed+public result core meant redacting `inputs` did not actually withhold them (they
        # survived in result.provenance.inputs), defeating the docket-safe redaction the feature exists
        # for (proprietary or export-controlled inputs). See proof_core.redaction and the verifier's
        # leak guard.
        "provenance": {"capability": case.capability},
    }
    # Only emitted when a card declares one, so a deterministic card's core is byte-identical to
    # before (canon sorts keys, so a conditional key changes bytes only when present).
    if result.reproduce_tolerance is not None:
        core["reproduce_tolerance"] = result.reproduce_tolerance
    return core


def exact_tolerance() -> dict:
    """Declare that a card's result is deterministic: `reproduce` compares it exactly. Put the returned dict,
    exactly ``{"kind": "exact"}``, on ``Result.reproduce_tolerance``; like a stat band it rides in the signed core,
    and a verifier reports the tolerance state ``exact``. A receiver policy with ``require_reproduce_tolerance``
    (SPEC 13.4.3 row 24, e.g. the ``calc-package`` preset) accepts a bundle only if it declares this or a sound
    statistical band (`stat_tolerance`).

    Nothing seals it for you: a bundle that leaves ``reproduce_tolerance`` unset declares nothing, and reproduce
    still compares it exactly. Declaring exact is a deliberate claim that a re-run gives the same result core, so
    use it only for a deterministic result; a stochastic one declares a `stat_tolerance` band. A fresh dict each
    call, so a caller that edits it cannot change the next one."""
    return {"kind": "exact"}


def stat_tolerance(quantity: str, sigma_key: str, sigmas: float = 3.0,
                   derived: Sequence[str] = ()) -> dict:
    """Declare that `quantity` in a card's outputs is stochastic. `reproduce` then accepts a re-run
    whose value agrees within `sigmas` times the combined 1-sigma (read from `sigma_key` in the same
    outputs), instead of demanding a bit-identical match. Put the returned dict on
    ``Result.reproduce_tolerance``; it rides in the signed core, so the tolerance is part of the
    record a reviewer checks against -- not a choice made at reproduce time.

    `derived` names output fields that are deterministic functions of `quantity` (e.g. a computed-over-
    measured ratio ``score / reference_score``) and therefore move every run too. `reproduce` excludes
    them from the bit-identical remainder check -- the quantity they derive from is already bounded by
    the band. The key is emitted ONLY when non-empty, so a producer that declares none keeps a
    byte-identical tolerance dict (and sealed core).

    `derived` may only name genuinely derived output fields. It is REJECTED (ValueError) if it names
    an integrity pin -- `engine`, `benchmark_id`, `generator_sha256`, `model_sha256`, any `*_sha256`:
    excluding those from the remainder check would let a re-run of a DIFFERENT model or generator
    "reproduce" a sealed number, which is exactly the forgery the pins exist to catch. `sigma_key`
    must differ from `quantity` (a self-referential band is meaningless)."""
    from .envelope import is_integrity_field  # single definition, shared with the mint belt
    if sigma_key == quantity:
        raise ValueError(f"stat_tolerance: sigma_key {sigma_key!r} must not be the quantity itself")
    bad = sorted(d for d in derived if not isinstance(d, str) or is_integrity_field(d))
    if bad:
        raise ValueError(f"stat_tolerance: derived may not name integrity fields {bad} "
                         "(engine / benchmark_id / *_sha256 are never excluded from the remainder check)")
    tol = {"kind": "stat", "quantity": quantity, "sigma_key": sigma_key, "sigmas": sigmas}
    if derived:
        tol["derived"] = list(derived)   # given order, JSON-serializable
    return tol
