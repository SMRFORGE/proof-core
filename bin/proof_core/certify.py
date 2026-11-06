"""Certify / reproduce harness -- the consumer-side half of the evidence spine.

Two verbs, deliberately distinct (see the VERIFY-vs-REPRODUCE distinction the whole product
turns on):

  * VERIFY (proof_verify.verify_bundle) -- authenticity + integrity, using NO domain code: the
    signature holds under the pinned key and every hash recomputes. Answers "was this bundle
    edited, and did it come from the pinned signer's key?"
  * REPRODUCE (`reproduce_bundle`) -- re-derive the numbers by RUNNING the open engine on the
    bundle's own recorded inputs, and check the result core comes back identical. Answers "do
    these numbers actually fall out of the code, or were they just asserted?"

`certify_bundle` runs BOTH and returns an attestation record. It is something a REVIEWER runs
(not the producer signing its own homework), so the record is an honest report, not itself a
signed claim -- a reviewer trusts their own run.

Lean bundles are deterministic (same inputs -> identical result core, and usually a byte-identical
bundle too), so reproduction is an exact result-core match. Reproduction needs the producer that
made the bundle to be available to the runner and its inputs present: a redacted-inputs or unknown-
capability bundle raises ReproduceError naming that specific gap. A re-run that *starts* but cannot
finish (a composed capability whose sub-steps are not available, or a missing data dependency) is a
different thing -- `certify_bundle` catches it and reports `reproduce_error`, and it must not be read
as a result-core mismatch (a possible forgery). `reproduced` is true ONLY on a genuine match.

ONE GATE. Whether the bundle is accepted is never decided here: `reproduce_bundle`, `certify_bundle` and
`seal_certification` ask `proof_verify.gate.gate` -- the SAME decision `proof-verify` makes for the same bytes and the
same receiver trust inputs (`policy`, `pins`, `as_of`, `profile`) -- and report it as `gate`. `verified` is that
gate's pass (proof-verify exit 0: intact, signed under a non-demo pin of the receiver, every sign-off valid, accepted
by the receiver's policy), never a looser integrity-and-origin reading. A bundle verify rejects (a signed rejection,
a forged sign-off, an aged suite under the receiver's policy) is never `verified` and never `certified`.

REPRODUCE CHECKS INTEGRITY FIRST. The library API refuses to re-derive a bundle whose INTEGRITY fails
(a hash/seal problem, or a signature that is invalid under the bundle's own key -- edited, forged,
malformed): the report then carries `unverified: True` and `reproduced: False`, so a `reproduced` read
off the report can never be mistaken for a trustworthy standalone verdict over a tampered bundle.
ORIGIN is a separate question and does NOT gate re-derivation: a bundle validly signed under a key
other than the pinned one (the public demo key on a dev machine) has sealed inputs that are exactly
what its signer sealed, so re-running them is safe and is the ONLY way its number gets checked. Such a
report carries `integrity_ok: True`, `origin_ok: False`, `verified: False` and a real `reproduced`.
`certified` still requires origin (a reviewer's attestation never vouches for an unknown signer).

ENVIRONMENT. A number that re-derives within its statistical band on a DIFFERENT data library or
snapshot (or seed, or run controls) is not a reproduction of the sealed claim -- it is a different calculation
that happened to land nearby. So `reproduce` also compares the sealed provenance's content pins against
the fresh run's (`data_library_sha256`, every `*_sha256` model/deck/generator pin, `rng_seed`, the
sealed run controls) and reports `environment_mismatch`; a bundle whose data library was never pinned
(`unpinned`) reports `environment_unverifiable`. Either blocks `certified`. `code_version` and
`engine_version` are deliberately IGNORED here -- a reviewer at another commit is expected, and that
difference is what `bundle_identical` already reflects.
"""
from __future__ import annotations

import contextvars
import copy
import math
from collections.abc import Callable

from .contract import ReproduceRunner
from .envelope import _CANON, _json_number, canon, is_integrity_field, stat_tolerance_problem
from .provenance import DATA_LIBRARY

CERTIFICATION_SCHEMA = "evidence.certification.v1"

#: capability name of a sealed reproduction record (see `seal_certification`). Domain-neutral, like every
#: other evidence.* name -- it says nothing about any particular producer.
REPRODUCTION_CAPABILITY = "proof:reproduction-record"

#: Upper bound on a sealed statistical tolerance. A legitimate stochastic reproduce band is a few
#: sigma (3-6); a bundle sealing an implausibly wide band (e.g. 1e9) would "reproduce" any value and
#: certify. Treat anything wider than this as a malformed tolerance and fall back to an EXACT match
#: (conservative -- an absurd band can never turn a mismatch into a pass).
_MAX_SIGMAS = 10.0

#: The fresh run's 1-sigma must sit within this factor of the sealed one: a fresh sigma far wider than the
#: sealed one (a re-run with far fewer samples than the sealed run controls) or far narrower means the re-run
#: did not use the sealed controls. Same controls -> the two sigma estimates agree to well within 1.5x.
#: Together with the band rule below (`sigmas * hypot(min(sealed, fresh), fresh)`) an honest stochastic
#: re-run is reported not reproduced about 2% of the time at 1.5 and 3 sigma (reviewer's Monte Carlo).
_SIGMA_RATIO = 1.5


def _by_value_numbers(value):
    """``value`` with every integral finite float made an int (``20.0`` -> ``20``), recursively; everything else
    unchanged. The --command (outputs-only) comparison runs on this, so a JSON number is compared BY VALUE: a
    reviewer's tool in another language that writes ``20.0`` for a sealed ``20`` (or the reverse) matches, under
    every canon (canon 1 is type-sensitive, canon 2 and 3 already encode the two alike). It never makes a
    non-number equal to a number: a boolean (``type(x) is bool``, not float) and a string such as ``"20"`` are left
    as they are, so they still mismatch; a non-finite float is left as it is and the canon refuses it. Two ints, or
    an int and a float, end up equal exactly when their values are equal (Python's int/float equality is exact)."""
    if type(value) is float:
        return int(value) if math.isfinite(value) and value.is_integer() else value
    if isinstance(value, dict):
        return {k: _by_value_numbers(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_by_value_numbers(v) for v in value]
    return value


def _outputs_by_value(core):
    """A copy of a result core whose ``result`` (the outputs, the only part an outputs-only reproducer supplies) has
    its JSON numbers in by-value form (``_by_value_numbers``). The claim fields are left byte for byte."""
    if not (isinstance(core, dict) and "result" in core):
        return core
    return {**core, "result": _by_value_numbers(core["result"])}

#: Result-core keys that are not computed values or integrity: a stat reproduce lifts them out of the strict
#: byte-for-byte remainder and reports a difference as `metadata_drift`. Of these only `caveats` is cosmetic
#: (a re-worded caveat does not change the claim); `fidelity`, `verdict` and `reproduce_tolerance` are CLAIM
#: fields (CLAIM_CORE_KEYS below), and any drift in them fails `reproduced` in every mode via `claim_drift`.
#: Everything else in the core (the outputs' engine, counts, generator/model pins, benchmark id, the
#: provenance stub) stays in the strict byte-for-byte remainder.
METADATA_KEYS = ("caveats", "reproduce_tolerance", "verdict", "fidelity")

#: Of the metadata keys, these two are the MATERIAL claim fields: the result's self-declared `verdict`
#: and `fidelity` tier. A caveat re-wording or an (only-tightening) tolerance change is cosmetic, but if
#: the fresh re-run's result declares a DIFFERENT verdict or fidelity than the sealed one, `certified`
#: must not silently assert the sealed claim -- the drift is surfaced as `metadata_conflict` and blocks
#: certification. Since the claim-drift rule (CLAIM_CORE_KEYS) such a drift also fails `reproduced`;
#: `metadata_conflict` is kept as the certify-record view of the same two fields. Domain-neutral
#: (verdict/fidelity are kernel contract fields), so this is unconditional hardening, not a profile knob.
MATERIAL_METADATA_KEYS = ("verdict", "fidelity")


def _material_metadata_conflict(reproduce_detail) -> dict:
    """The drift that is MATERIAL to certification: a verdict/fidelity difference in a stat reproduce's
    `metadata_drift`, plus the verdict/fidelity/caveats entries of the claim drift every mode reports (a caveat
    the fresh run declares and the sealed bundle omits widens the claim). Empty for a clean reproduce, a missing
    detail, or cosmetic-only drift (extra sealed caveats)."""
    if not isinstance(reproduce_detail, dict):
        return {}
    meta = {k: v for k, v in (reproduce_detail.get("metadata_drift") or {}).items() if k in MATERIAL_METADATA_KEYS}
    claim = {k: v for k, v in (reproduce_detail.get("claim_drift") or {}).items()
             if k in MATERIAL_METADATA_KEYS + ("caveats",)}
    return {**meta, **claim}


#: Sealed-provenance pins that legitimately differ when a reviewer re-runs at another commit.
ENV_IGNORED = ("code_version", "engine_version")
#: Sealed `data` pins compared INFORMATIONALLY only. Example: a data library's INDEX file hash
#: (`data_index_sha256`) can cover bytes that embed the library's on-disk PATHS -- it flips on a relocated
#: library alone, so it cannot be a hard block. (The content pin is `data_library_sha256`.) A consumer with
#: its own path-sensitive index pin adds it here.
ENV_INFORMATIONAL = ("data_index_sha256",)
#: Sealed `data` run controls that a genuine reproduction must have re-used (with every `*_sha256`).
ENV_RUN_CONTROLS = ("samples", "iterations", "warmup", "batch_seed", "rng_seed", "seed")
#: Top-level sealed-provenance pins compared hard.
ENV_TOP_PINS = ("data_library", "data_library_sha256", "rng_seed", "produced_by")


#: Why a re-derived result is still NOT `reproduced` (the same names in the library report, proof-reproduce's
#: `shortfalls` and the Adapter): `reproduced` is True only when the result core and claim re-derive
#: (`result_rederived`) AND none of these applies.
SHORTFALL_GATE = "gate_not_passed"                     # proof-verify would not exit 0 under the receiver's trust inputs
SHORTFALL_INPUTS = "inputs_not_identical"              # the re-run did not use the sealed inputs
SHORTFALL_ENVIRONMENT = "environment_mismatch"         # a sealed environment pin differs
SHORTFALL_ENV_UNVERIFIABLE = "environment_unverifiable"  # the sealed or fresh data environment was never pinned


def reproduction_shortfalls(report: dict) -> list[str]:
    """The shortfalls of a reproduce report, in a fixed order. `environment_unverifiable` is not counted for an
    outputs-only reproducer (proof-reproduce --command), which cannot capture its environment by construction and
    is never a full reproduction anyway (`claims_not_rederived`)."""
    out = []
    if report.get("verified") is not True:
        out.append(SHORTFALL_GATE)
    if report.get("inputs_identical") is not True:
        out.append(SHORTFALL_INPUTS)
    if report.get("environment_mismatch"):
        out.append(SHORTFALL_ENVIRONMENT)
    if report.get("environment_unverifiable") and report.get("outputs_only") is not True:
        out.append(SHORTFALL_ENV_UNVERIFIABLE)
    return out


class ReproduceError(RuntimeError):
    """Raised when a bundle cannot be reproduced with the open engine."""


#: The canonicalization used to COMPARE a re-run against its subject: the subject's own sealed canon (set per
#: call in `reproduce_bundle`). Under canon v2 a whole float and its integer (2.0 / 2) seal identically, so a
#: v2 comparison must not tell them apart either; v1 keeps its exact, type-sensitive comparison.
_CMP_CANON: contextvars.ContextVar = contextvars.ContextVar("proof_core_cmp_canon", default=canon)


def subject_canon(bundle) -> tuple[int, Callable[[object], bytes]]:
    """The subject's sealed ``canon_version`` N and the canon function ``canon_N`` a re-run is compared under.

    SPEC (evidence.envelope.v4 draft) section 15 step 3: "compare the fresh result with the sealed one under the
    subject's canon: `canon_N` for the subject's `canon_version` N, for every supported N, including canon 3
    (this closes open issue 17.3.10)". The lookup is over every canon this kernel implements (`_CANON`: 1, 2 and
    3), never "2 if N == 2 else 1": open issue 17.3.10 was exactly that a newer canon would silently be compared
    under v1. Canon 3 is compared on the DISCLOSED values (``canon_disclosed``), not under ``canon_3`` itself,
    because a fresh bundle has fresh salts. A canon_version this kernel does not
    implement (or a malformed one) raises ReproduceError instead of falling back. ``reproduce_bundle`` only gets
    here after the integrity check passed, which an unsupported canon never does, so the raise is a guard
    against a future caller that skips that check, not a reachable reproduce outcome today."""
    sums = bundle.get("sha256sums") if isinstance(bundle, dict) else None
    cv = sums.get("canon_version") if isinstance(sums, dict) else None
    if type(cv) is not int or cv not in _CANON:
        raise ReproduceError(f"cannot compare a re-run under canon_version {cv!r}: this kernel implements "
                             f"canon versions {sorted(_CANON)} only (no fallback to another canon)")
    if cv == 3:
        # SPEC 15 step 3: "Under canon 3 a fresh bundle has fresh salts, so the comparison is made on the disclosed
        # values (T applied to both after full disclosure) rather than on the stored item forms". canon_3 itself
        # would compare commitments, which differ for every honest re-run (fresh salts).
        from .committed import canon_disclosed
        return cv, canon_disclosed
    return cv, _CANON[cv]


def _ccanon(value):
    """Canonical bytes for a re-run comparison, under the subject's canon. If the v2 canon cannot represent a
    value (an int beyond +/-(2^53-1) in a FRESH pin), fall back to v1's exact, type-sensitive bytes, tagged so
    they can never equal v2 bytes: that only makes two values compare UNEQUAL, so it reports a mismatch instead
    of raising."""
    fn = _CMP_CANON.get()
    try:
        return fn(value)
    except (ValueError, TypeError, AttributeError):
        if fn is canon:
            raise
        return b"v1-fallback:" + canon(value)


def differing_output_keys(bundle, sealed_outputs, fresh_outputs, *, outputs_only: bool = False) -> list[str]:
    """The output keys whose sealed and fresh values differ, judged by the SAME rule the reproduce verdict used:
    under the subject's sealed canon (``subject_canon``: canon 1 is type-sensitive, canon 2 and 3 encode 20 and
    20.0 alike; a boolean never equals a number under any canon), and for an outputs-only reproducer (--command)
    with JSON numbers by value (``_by_value_numbers``). A key present on one side only differs. For explaining a
    verdict (the CLI's diff lines); the verdict itself is ``_cores_match``. Sorted."""
    try:
        fn = subject_canon(bundle)[1]
    except ReproduceError:
        fn = canon
    sealed = sealed_outputs if isinstance(sealed_outputs, dict) else {}
    fresh = fresh_outputs if isinstance(fresh_outputs, dict) else {}
    if outputs_only:
        sealed, fresh = _by_value_numbers(sealed), _by_value_numbers(fresh)

    def _form(value):
        try:
            return fn(value)
        except (ValueError, TypeError, AttributeError):
            try:
                return b"v1-fallback:" + canon(value)
            except (ValueError, TypeError):
                return object()          # not JSON (NaN, Infinity): the verdict refuses it, so it never matches

    return [k for k in sorted(set(sealed) | set(fresh))
            if (k in sealed) != (k in fresh) or _form(sealed[k]) != _form(fresh[k])]


def _without_caveats(core):
    """``core`` without its `caveats`: caveats are judged by the claim-drift subset rule (`_claim_drift`), in
    every mode, never by byte equality, so exact and stat comparisons treat them the same way."""
    return {k: v for k, v in core.items() if k != "caveats"} if isinstance(core, dict) else core


def _exact_match(orig_core, fresh_core) -> tuple[bool, dict]:
    try:
        return (orig_core is not None
                and _ccanon(_without_caveats(orig_core)) == _ccanon(_without_caveats(fresh_core))), {"mode": "exact"}
    except ValueError as exc:
        # a NaN/Infinity in either core: not RFC 8259 JSON, so it can neither be sealed (canon refuses at
        # mint) nor compared -- a closed negative, never a crash and never a pass
        return False, {"mode": "exact", "reason": f"non-JSON value in a result core ({exc})"}


def _exact_fallback(orig_core, fresh_core, reason: str) -> tuple[bool, dict]:
    ok, detail = _exact_match(orig_core, fresh_core)
    return ok, {**detail, "mode": "exact-fallback", "reason": reason}


def _split_metadata(core: dict) -> tuple[dict, dict]:
    """(strict remainder, metadata) -- the metadata keys lifted out of a copy of the core."""
    rest = copy.deepcopy(core)
    meta = {k: rest.pop(k) for k in METADATA_KEYS if k in rest}
    return rest, meta


def _stat_match(orig_core: dict, fresh_core: dict, tol: dict, *, fresh_tol: dict | None = None,
                fresh_sigma_only: bool = False) -> tuple[bool, dict]:
    """Statistical (stochastic) reproduce: the declared quantity must agree within `sigmas`
    times the combined 1-sigma, and EVERY other value/integrity byte of the core must be identical
    (except fields the tolerance declares `derived` from the quantity -- see below). Prose/metadata
    keys (METADATA_KEYS) are compared separately and reported as `metadata_drift`; the claim fields among them
    (fidelity / verdict / reproduce_tolerance) then fail `reproduced` via `_claim_drift` in the caller.

    Falls back to an EXACT match (conservative -- a malformed band can never turn a mismatch into a
    pass), with a named reason, when: the sealed tolerance is unusable (fields missing/non-numeric,
    sigma_key == quantity, a sealed relative sigma >= 5% of the value, `derived` naming an integrity
    field); the band is non-finite/negative/wider than _MAX_SIGMAS; or the fresh sigma is not within
    _SIGMA_RATIO of the sealed one (the re-run did not use the sealed run controls).

    The effective band is the TIGHTER of the sealed tolerance and the fresh (code-declared) one, and
    the effective `derived` set is their intersection: the sealed tolerance is what the reviewer is
    held to, but a re-signed bundle that widened its own band or declared extra `derived` fields can
    never loosen the comparison beyond what the open engine's card actually declares. (A tolerance that
    differs at all is a claim drift and fails `reproduced` anyway; a fresh run that declares NO tolerance
    is deterministic and is handled by `_cores_match`.)"""
    from proof_verify.verify import stat_band_outputs
    cap = next(iter(orig_core.get("result", {})), None)
    q, sigma_key = tol.get("quantity"), tol.get("sigma_key")
    o_out = stat_band_outputs(orig_core)      # the ONE output lookup the verifier and the mint use (SPEC 14 item 7)
    f_out = fresh_core.get("result", {}).get(cap, {})
    problem = (stat_tolerance_problem(tol, o_out) if o_out is not None
               else "the sealed result must hold one capability")
    if problem:
        return _exact_fallback(orig_core, fresh_core, f"sealed tolerance unusable: {problem}")
    if not (isinstance(f_out, dict) and q in f_out and sigma_key in f_out):
        return _exact_fallback(orig_core, fresh_core, "tolerance fields missing or non-numeric")
    sigmas = _json_number(tol.get("sigmas"))
    if sigmas is None:
        return _exact_fallback(orig_core, fresh_core, "tolerance fields missing or non-numeric")
    nums = [_json_number(o_out[q]), _json_number(f_out[q]), _json_number(o_out[sigma_key]),
            _json_number(f_out[sigma_key])]
    if None in nums:
        # a string ("20.0") or a boolean on either side is a MISMATCH, never coerced into the band
        return False, {"mode": "stat", "quantity": q, "within_tolerance": False,
                       "reason": f"{q!r} and {sigma_key!r} must be finite JSON numbers (not strings or booleans) "
                                 "in both the sealed and the fresh outputs"}
    o_val, f_val, o_sig, f_sig = nums
    if not math.isfinite(sigmas) or sigmas < 0 or sigmas > _MAX_SIGMAS:
        return _exact_fallback(
            orig_core, fresh_core,
            f"non-finite, non-positive, or implausibly wide (>{_MAX_SIGMAS:g}-sigma) tolerance")
    if not (math.isfinite(f_val) and math.isfinite(f_sig)) or f_sig <= 0 \
            or not (o_sig / _SIGMA_RATIO <= f_sig <= o_sig * _SIGMA_RATIO):
        return _exact_fallback(
            orig_core, fresh_core,
            f"fresh sigma {f_sig!r} is not within {_SIGMA_RATIO:g}x of the sealed sigma {o_sig!r}; "
            "the re-run did not reproduce the sealed run controls")

    # the fresh (code-declared) tolerance can only TIGHTEN the sealed one, never loosen it
    # (`fresh_tol` overrides the fresh core's own declaration: the --command path passes the REVIEWER's band)
    if fresh_tol is None:
        fresh_tol = fresh_core.get("reproduce_tolerance")
    fresh_tol = fresh_tol if isinstance(fresh_tol, dict) and fresh_tol.get("kind") == "stat" else {}
    declared_sigmas = sigmas
    fs = _json_number(fresh_tol.get("sigmas"))
    if fs is not None and 0 <= fs < sigmas:
        sigmas = fs
    # compare two independent estimates: the band is sigmas * hypot(min(sealed, fresh), fresh). The sealed sigma is a
    # producer claim, so it can only NARROW the band (a smaller sealed sigma counts as is; a larger one is capped at
    # the fresh sigma), never inflate it; the band is never wider than sigmas * hypot(sealed, fresh).
    # (`fresh_sigma_only`: the REVIEWER's band of the --command path is built from the fresh 1-sigma alone.)
    combined = math.hypot(f_sig, f_sig) if fresh_sigma_only else math.hypot(min(o_sig, f_sig), f_sig)
    if not math.isfinite(combined) or combined <= 0:
        return _exact_fallback(orig_core, fresh_core, "non-finite or non-positive combined sigma")
    delta = abs(o_val - f_val)
    within = delta <= sigmas * combined

    # Fields the sealed tolerance declares as DERIVED are deterministic functions of the tolerance
    # quantity (e.g. a ratio of the quantity to a reference value), so they move every run exactly as the quantity
    # does. Requiring them to bit-match would be equivalent to requiring the quantity itself to
    # bit-match, defeating the statistical tolerance. Blanking them does not weaken forgery detection:
    # the signature/seal still covers the original core (derived values included), and the quantity
    # they derive from is still bounded by the band above. Names absent from the outputs are skipped;
    # integrity pins are never blanked whatever a tolerance says; only names BOTH tolerances declare.
    def _derived_of(t):
        d = t.get("derived", [])
        return [x for x in d if isinstance(x, str)] if isinstance(d, (list, tuple)) else []
    fresh_derived = set(_derived_of(fresh_tol))
    derived = [d for d in _derived_of(tol) if d in fresh_derived and not is_integrity_field(d)]

    def _blanked(core):
        c = copy.deepcopy(core)
        c["result"][cap][q] = None          # the stochastic value ...
        c["result"][cap][sigma_key] = None  # ... and its (also stochastic) 1-sigma
        for name in derived:                # ... and its declared deterministic functions
            if name in c["result"][cap]:
                c["result"][cap][name] = None
        return c

    o_rest, o_meta = _split_metadata(_blanked(orig_core))
    f_rest, f_meta = _split_metadata(_blanked(fresh_core))
    rest_identical = _ccanon(o_rest) == _ccanon(f_rest)
    metadata_drift = {
        k: {"sealed": o_meta.get(k), "fresh": f_meta.get(k)}
        for k in METADATA_KEYS if _ccanon(o_meta.get(k)) != _ccanon(f_meta.get(k))
    }
    return bool(within and rest_identical), {
        "mode": "stat", "quantity": q, "sigmas": sigmas,
        # the band width the governing tolerance declared before any tightening: the reviewer's in reviewer mode
        ("reviewer_sigmas" if fresh_sigma_only else "sealed_sigmas"): declared_sigmas,
        "delta": delta, "sigma": combined, "n_sigma": delta / combined,
        "sigma_basis": "fresh" if fresh_sigma_only else "min(sealed,fresh)+fresh",
        "within_tolerance": within, "rest_identical": rest_identical,
        # prose/metadata that changed since the mint -- informational, never a failure
        "metadata_drift": metadata_drift,
    }


def _declares_stat_tolerance(core) -> bool:
    tol = core.get("reproduce_tolerance") if isinstance(core, dict) else None
    return isinstance(tol, dict) and tol.get("kind") == "stat"


#: The reason a deterministic re-run that landed inside the producer's sealed band is NOT a reproduction.
DETERMINISTIC_BAND_REASON = (
    "matched within the producer's sealed band, not exactly; the fresh run is deterministic (it declares no "
    "reproduce_tolerance), so it must re-derive the sealed values exactly and a band match is not a reproduction")


def _cores_match(orig_core, fresh_core, *, outputs_only: bool = False, reviewer_tol: dict | None = None
                 ) -> tuple[bool, dict]:
    """Compare the recorded result core against a fresh re-run. Exact by default; a core that
    declares a statistical `reproduce_tolerance` is compared within that tolerance instead.

    The sealed band is the producer's commitment for a genuinely STOCHASTIC run, so it only applies when the
    fresh run is stochastic too (its own core declares a `stat` tolerance). A fresh run that declares none is
    deterministic: the same inputs give the same numbers, so it is held to an exact match of every value. If
    it lands inside the sealed band but not exactly, the comparison says so (mode `stat-deterministic`,
    reason DETERMINISTIC_BAND_REASON) and is NOT a reproduction: otherwise a re-signed bundle could seal a
    wrong number with a wide band over a deterministic capability and "reproduce" it.

    ``outputs_only`` (the --command path: the reviewer's tool returns outputs only, and every claim field of the
    fresh core was copied from the sealed one) never applies the SEALED band: the outputs must match exactly,
    unless the REVIEWER supplied ``reviewer_tol`` (a `stat` tolerance), which is then the band (mode
    `stat-reviewer`, `band: "reviewer"`), built from the fresh 1-sigma alone (`sigma_basis: "fresh"`)."""
    if outputs_only:
        # a reviewer's tool may be written in any language: its outputs are compared by JSON number VALUE, so
        # 20 and 20.0 are equal; a boolean or a numeric string is still a mismatch (strict numbers stay strict)
        orig_core, fresh_core = _outputs_by_value(orig_core), _outputs_by_value(fresh_core)
        if reviewer_tol is not None:
            ok, detail = _stat_match(orig_core, fresh_core, reviewer_tol, fresh_tol=reviewer_tol, fresh_sigma_only=True)
            if detail.get("mode") == "stat":
                detail = {**detail, "mode": "stat-reviewer"}
            return ok, {**detail, "band": "reviewer", "outputs_only": True}
        ok, detail = _exact_match(orig_core, fresh_core)
        return ok, {**detail, "outputs_only": True}
    tol = orig_core.get("reproduce_tolerance") if isinstance(orig_core, dict) else None
    if isinstance(tol, dict) and tol.get("kind") == "stat":
        ok, detail = _stat_match(orig_core, fresh_core, tol)
        if _declares_stat_tolerance(fresh_core) or detail.get("mode") != "stat":
            return ok, detail
        # deterministic fresh run: exact on every value (the tolerance key itself is a claim field, compared
        # separately by _claim_drift)
        o_vals = {k: v for k, v in orig_core.items() if k != "reproduce_tolerance"}
        f_vals = ({k: v for k, v in fresh_core.items() if k != "reproduce_tolerance"}
                  if isinstance(fresh_core, dict) else fresh_core)
        exact, _ = _exact_match(o_vals, f_vals)
        detail = {**detail, "fresh_deterministic": True, "values_exact": exact}
        if exact:
            return True, detail
        if ok:
            return False, {**detail, "mode": "stat-deterministic", "reason": DETERMINISTIC_BAND_REASON}
        return False, detail
    return _exact_match(orig_core, fresh_core)


#: Sealed CLAIM fields a reproduction must re-declare identically: the result core's `fidelity`, `verdict`
#: and `reproduce_tolerance`, and the provenance's `produced_by`. A re-run that re-derives the number but
#: declares a different tier, verdict, band or producer has not reproduced the sealed claim, so any drift
#: here makes `reproduced` False and is named in `claim_drift`. `caveats` follow a subset rule: a caveat the
#: fresh run declares that the sealed bundle omits (verbatim) is a drift, since removing a caveat widens the
#: claim; extra sealed caveats only narrow it and are allowed. (A reworded engine caveat is a removal: the
#: verbatim text is gone.) `code_version` / `engine_version` stay environment notes, since a reviewer may
#: legitimately re-run at another commit.
CLAIM_CORE_KEYS = ("fidelity", "verdict", "reproduce_tolerance")
CLAIM_PROVENANCE_KEYS = ("produced_by",)
_ABSENT = object()


def _claim_drift(orig_core, fresh_core, sealed_prov, fresh_prov) -> dict:
    """{field: {sealed, fresh}} for every sealed claim field the fresh run re-declares differently."""
    def _get(d, k):
        return d.get(k, _ABSENT) if isinstance(d, dict) else _ABSENT

    def _differs(a, b):
        if a is _ABSENT or b is _ABSENT:
            return a is not b
        try:
            return _ccanon(a) != _ccanon(b)
        except ValueError:
            return True

    drift = {}
    pairs = [(k, orig_core, fresh_core) for k in CLAIM_CORE_KEYS]
    if isinstance(sealed_prov, dict):        # a withheld provenance is an environment gap, not a claim drift
        pairs += [(k, sealed_prov, fresh_prov) for k in CLAIM_PROVENANCE_KEYS]
    for key, sealed_d, fresh_d in pairs:
        s_val, f_val = _get(sealed_d, key), _get(fresh_d, key)
        if _differs(s_val, f_val):
            drift[key] = {"sealed": None if s_val is _ABSENT else s_val,
                          "fresh": None if f_val is _ABSENT else f_val}
    s_cav, f_cav = _get(orig_core, "caveats"), _get(fresh_core, "caveats")
    s_list = [] if s_cav is _ABSENT else s_cav
    f_list = [] if f_cav is _ABSENT else f_cav
    if isinstance(s_list, list) and isinstance(f_list, list):
        try:
            have = {_ccanon(c) for c in s_list}
            missing = [c for c in f_list if _ccanon(c) not in have]
        except ValueError:
            missing = list(f_list)
        if missing:
            drift["caveats"] = {"sealed": s_list, "fresh": f_list, "missing_from_sealed": missing}
    elif _differs(s_cav, f_cav):
        drift["caveats"] = {"sealed": None if s_cav is _ABSENT else s_cav,
                            "fresh": None if f_cav is _ABSENT else f_cav, "missing_from_sealed": []}
    return drift


def _claim_drift_reason(drift: dict) -> str:
    parts = [f"caveats (the fresh run declares {v['missing_from_sealed']!r}, which the sealed bundle omits)"
             if k == "caveats" and v.get("missing_from_sealed")
             else f"{k} (sealed {v['sealed']!r}, fresh {v['fresh']!r})"
             for k, v in drift.items()]
    return ("the fresh run re-declares the sealed claim differently: " + "; ".join(parts)
            + " -- a reproduction must re-derive the sealed fidelity, verdict, reproduce_tolerance and "
              "produced_by unchanged, and the sealed bundle must keep every caveat the fresh run declares")


#: The claim fields an outputs-only reproducer (--command) copies from the sealed bundle instead of re-deriving.
CLAIMS_NOT_REDERIVED_OUTPUTS_ONLY = ("fidelity", "verdict", "caveats", "reproduce_tolerance", "produced_by")


def _compare_environment(sealed_prov, fresh_prov, *, profile=None) -> dict:
    """Compare the sealed provenance's CONTENT pins against the fresh run's.

    Returns {ok, mismatch: {pin: {sealed, fresh}}, notes: [...], unverifiable: str|None, ignored}.
    `ok` is True only when every hard pin matches AND the data environment was pinned at all.

    `profile` (optional) supplies the dialect's `env_informational` / `env_run_controls` pin names; None/
    default uses the neutral tuples, so the comparison is byte/verdict-identical unless a dialect opts in."""
    # None (profile absent, or a duck-typed object without the field) -> the neutral tuple; a dialect that
    # sets an explicit tuple is honored AS-IS, including an empty () meaning "no informational pin / no
    # run-controls -- compare every data pin hard". Using `is None` (not `or`) so a deliberate () is never
    # silently reverted to the neutral tuple, which would SOFTEN that dialect's environment check.
    env_informational = getattr(profile, "env_informational", None)
    if env_informational is None:
        env_informational = ENV_INFORMATIONAL
    env_run_controls = getattr(profile, "env_run_controls", None)
    if env_run_controls is None:
        env_run_controls = ENV_RUN_CONTROLS
    env: dict = {"ok": False, "mismatch": {}, "notes": [], "unverifiable": None, "ignored": list(ENV_IGNORED)}
    if not isinstance(sealed_prov, dict):
        env["unverifiable"] = ("sealed provenance is withheld or absent; the data environment of the "
                               "sealed run cannot be confirmed")
        return env
    fresh_prov = fresh_prov if isinstance(fresh_prov, dict) else {}
    # A reproducer that could not capture its own data environment marks it so (the --command path runs an
    # external tool that returns only the recomputed outputs). The data environment is then UNVERIFIABLE:
    # the result core was compared, but the sealed data pins were NOT independently re-derived. Report that
    # honestly instead of a false clean match (sealed pins vs copies of themselves) or a false mismatch.
    fresh_data = fresh_prov.get("data")
    if isinstance(fresh_data, dict) and fresh_data.get("environment_captured") is False:
        env["unverifiable"] = (
            "the reproducer did not capture its own data environment (e.g. the --command path runs an "
            "external tool that returns only the recomputed outputs), so the sealed data pins were not "
            "independently re-derived; the result core was compared, the data environment was not")
        return env
    dl, dls = sealed_prov.get("data_library"), sealed_prov.get("data_library_sha256")
    if dl in (None, DATA_LIBRARY) or dls is None:
        env["unverifiable"] = (
            f"sealed data_library is {dl!r} (digest {dls!r}): the sealed run pinned no data-library "
            "or snapshot content, so a re-run on different data cannot be told apart from this one")
    pins: dict[str, tuple] = {}
    for key in ENV_TOP_PINS:
        if key in sealed_prov:
            pins[key] = (sealed_prov.get(key), fresh_prov.get(key))
    s_data = sealed_prov.get("data") if isinstance(sealed_prov.get("data"), dict) else {}
    f_data = fresh_prov.get("data") if isinstance(fresh_prov.get("data"), dict) else {}
    for key, s_val in s_data.items():
        f_val = f_data.get(key)
        if key in env_informational:
            if _ccanon(s_val) != _ccanon(f_val):
                env["notes"].append(
                    f"data.{key} differs (sealed {s_val!r}, fresh {f_val!r}) -- a path-sensitive index "
                    "hash, informational only; the content pin is data_library_sha256")
        elif key.endswith("_sha256") or key in env_run_controls:
            pins[f"data.{key}"] = (s_val, f_val)
    for name, (s_val, f_val) in pins.items():
        if _ccanon(s_val) != _ccanon(f_val):
            env["mismatch"][name] = {"sealed": s_val, "fresh": f_val}
    # toolchain (python / platform / engine image): ADVISORY -- recorded so a reviewer sees whether their
    # runtime matches the minting one below the version string, but NEVER a hard block (a reviewer on a
    # different toolchain is expected; the result core re-derives regardless). Old packs carry none -> skip.
    s_tc = sealed_prov.get("toolchain")
    if isinstance(s_tc, dict):
        f_tc = fresh_prov.get("toolchain") if isinstance(fresh_prov.get("toolchain"), dict) else {}
        if _ccanon(s_tc) != _ccanon(f_tc):
            env["notes"].append(
                f"toolchain differs (sealed {s_tc}, fresh {f_tc}) -- advisory only; the result core "
                "re-derives across toolchains, so this does not block certification")
    env["ok"] = not env["mismatch"] and env["unverifiable"] is None
    return env


def _inputs_of(bundle: dict) -> dict:
    block = bundle.get("manifest", {}).get("inputs", {})
    if "value" not in block:
        raise ReproduceError(
            "bundle inputs are withheld (redacted) or absent; reproduction needs the recorded inputs"
        )
    value = block["value"]
    if not isinstance(value, dict) or "capability" not in value or "inputs" not in value:
        raise ReproduceError("bundle inputs block is not a {capability, inputs} record")
    _refuse_withheld(value, "inputs")
    return value


def _refuse_withheld(value, section: str) -> None:
    """SPEC v4 draft 10.6: a plaintext consumer "MUST refuse a value that contains a withheld-form item. They MUST
    report "N items withheld; reproduce not possible here"" (a named gap, like a withheld section)."""
    from .committed import refuse_withheld_items
    try:
        refuse_withheld_items(value, f"sealed {section}")
    except ValueError as exc:
        raise ReproduceError(str(exc)) from None


def _result_core_of(bundle: dict) -> dict:
    """The sealed result core, or a clear ReproduceError if the result is withheld/redacted.

    Symmetric with `_inputs_of`: a bundle may legitimately redact its result (ITAR/EAR, a customer
    withholding the number). Without this guard a redacted result left `orig_core = None`, and the
    comparison below returned `reproduced = False` with no reason -- INDISTINGUISHABLE from a forged
    bundle whose number genuinely failed to re-derive. A redacted result is a NAMED gap, never a
    silent False that reads like a forgery (certify_bundle surfaces it as reproduce_error).
    """
    block = bundle.get("manifest", {}).get("result", {})
    if "value" not in block:
        raise ReproduceError(
            "bundle result is withheld (redacted) or absent; reproduction needs the sealed result "
            "core to compare the re-derived numbers against"
        )
    value = block["value"]
    if not isinstance(value, dict):
        raise ReproduceError("bundle result block is not a result-core record")
    _refuse_withheld(value, "result")
    return value


def _sealed_provenance_of(bundle: dict):
    """The sealed provenance value, or None when withheld/absent (an environment gap, not an error)."""
    block = bundle.get("manifest", {}).get("provenance", {})
    return block.get("value") if isinstance(block, dict) else None


def _gate_fields(data, profile, policy, pins, as_of) -> tuple[dict, object]:
    """The ONE gate's decision on ``data`` (`proof_verify.gate.gate`) and the verify fields every report carries."""
    from proof_verify.gate import gate
    from proof_verify.verify import pinned_key_is_demo

    decision = gate(data, policy, pins, as_of, profile=profile)
    ver = decision.report
    return {
        # the gate's pass, exactly proof-verify's exit 0 for these bytes under these trust inputs (never a separate,
        # looser integrity-and-origin reading): a rejected or integrity-only bundle is never `verified`
        "verified": decision.passed,
        "integrity_ok": ver["integrity_ok"],
        "origin_ok": ver["origin_ok"],
        # surfaced so a consumer sees WHY origin is unproven: while the pin is the public demo identity
        # origin_ok is False even for a pin-signed bundle, so `verified`/`certified` are never origin.
        # an `unreadable` verdict (SPEC 13.1) carries no signer and no pin facts: read them with .get so
        # unreadable bytes give the not-attempted report below, never a KeyError
        "pinned_key_is_demo": ver.get("pinned_key_is_demo", pinned_key_is_demo()),
        "signer": ver.get("signer"),
        "verify_problems": ver["problems"],
        # the whole decision: proof-verify's single-bundle exit code, the rejecting reasons, the policy digest
        "gate": decision.summary(),
    }, decision


def reproduce_bundle(data: bytes | str, runner: ReproduceRunner, *, profile=None, policy=None, pins=None,
                     as_of: str | None = None) -> dict:
    """Check INTEGRITY, then re-derive `bundle` by running its capability on its recorded inputs; compare.

    `runner` is the consumer-injected reproduce harness (contract.ReproduceRunner): the domain-agnostic
    core never imports a domain engine, so the caller supplies the thing that can re-execute the capability
    (an analytics pipeline's scorer, a modeling engine's registry, an AI-output replayer, ...).
    `runner.can_run(cap)` gates re-derivation
    and `runner.run(cap, inputs)` returns the freshly minted bundle dict.

    `profile` (optional, duck-typed, additive) selects the on-disk DIALECT the integrity check is run
    under -- a branded consumer whose bundle carries its own `envelope_schema` / `result_schema` /
    pinned key MUST pass its `Profile` here, or the integrity check inside falls back to the neutral
    dialect and the bundle is never re-derived (the proven integration blocker this closes). `profile=None`
    (the default) resolves to the neutral dialect, so every existing call is byte- and behaviour-identical.

    `policy` / `pins` / `as_of` are the RECEIVER's trust inputs, handed to the one gate (`proof_verify.gate.gate`)
    exactly as `proof-verify` uses them (None / None: the single-pin path under the module pin). The report's `gate`
    is that decision and `verified` is its pass; a malformed policy raises PolicyError before anything is run.

    Returns a report: {capability, reproduced (result core re-derives), inputs_identical (the re-run
    used the sealed inputs, not substituted ones), reproduce_detail, claim_drift (sealed fidelity / verdict /
    reproduce_tolerance / produced_by re-declared differently -- any entry fails `reproduced`), environment,
    environment_mismatch,
    environment_unverifiable, bundle_identical, original_bundle_sha256, reproduced_bundle_sha256,
    fresh_bundle, verified, integrity_ok, origin_ok, signer, verify_problems}.
    A bundle whose INTEGRITY fails (hashes inconsistent, or the signature invalid under the bundle's own
    embedded key) is not re-run: the report carries `unverified: True`, `reproduced: False` and the verify
    problems, so `reproduced` can never be read as trustworthy over a tampered bundle. A bundle that is
    intact but signed under a key other than the pinned one IS re-run -- its sealed inputs are exactly
    what the signer sealed -- and reports `origin_ok: False`, `verified: False` alongside the real
    re-derivation result. Raises ReproduceError if the inputs OR the result are withheld, or the
    capability is not registered.

    ``data`` is the bundle's BYTES or text (SPEC 4: the verifier parses them itself; for a bundle you just minted,
    ``bundle_bytes(b)``). A parsed object raises TypeError, so no re-serialization path hides the duplicate keys of
    the bytes a reviewer received.
    """
    from .envelope import received_bundle
    data, bundle = received_bundle(data, "reproduce_bundle")
    # the verifier reads the bytes (SPEC 4), through the ONE gate proof-verify itself uses
    verify_fields, _decision = _gate_fields(data, profile, policy, pins, as_of)
    if not verify_fields["integrity_ok"]:
        # best-effort capability name for the report; the bundle may be arbitrarily malformed here
        # (verify already returned a closed verdict on it), so never trust its shape
        manifest = bundle.get("manifest") if isinstance(bundle, dict) else None
        inputs_blk = manifest.get("inputs") if isinstance(manifest, dict) else None
        inputs = inputs_blk.get("value") if isinstance(inputs_blk, dict) else None
        capability = inputs.get("capability") if isinstance(inputs, dict) else None
        unverifiable = "bundle integrity fails; the sealed provenance cannot be trusted"
        return {
            "capability": capability,
            "reproduced": False,
            "result_rederived": False,
            "shortfalls": [],
            "inputs_identical": False,          # never re-run, so the sealed inputs were not re-derived
            "unverified": True,
            **verify_fields,
            "reproduce_detail": {"mode": "not-attempted",
                                 "reason": "bundle integrity fails (seal/signature/hash problems); "
                                           "an edited or forged record is never re-derived"},
            "claim_drift": {},
            "outputs_only": getattr(runner, "outputs_only", False) is True,
            "claims_not_rederived": [],
            "environment": {"ok": False, "mismatch": {}, "notes": [], "unverifiable": unverifiable,
                            "ignored": list(ENV_IGNORED)},
            "environment_mismatch": {},
            "environment_unverifiable": unverifiable,
            "bundle_identical": False,
            "original_bundle_sha256": bundle.get("bundle_sha256") if isinstance(bundle, dict) else None,
            "reproduced_bundle_sha256": None,
            "fresh_bundle": None,
        }

    spec = _inputs_of(bundle)
    capability = spec["capability"]
    if not runner.can_run(capability):
        raise ReproduceError(
            f"capability {capability!r} is not available to the reproduce runner; register the producer "
            f"that made this bundle to reproduce it (reproduction re-runs the open engine, unlike verify)"
        )
    orig_core = _result_core_of(bundle)     # a withheld result raises here, not a silent False below
    # ADR-053/054: compare the re-run under the subject's sealed canon (see _CMP_CANON). The runner gets the
    # sealed inputs exactly as parsed: under v2 a whole number may arrive as 2 or 2.0 (the seal cannot tell them
    # apart), so a v2 runner must accept either -- see docs/INTEGRATING.md.
    # SPEC v4 draft 15 step 3 (closes 17.3.10): canon_N for the subject's N, for every supported N.
    subject_cv, cmp_canon = subject_canon(bundle)
    run_inputs = spec["inputs"]
    if subject_cv == 3:
        # the engine computes on VALUES, never on item wrappers (salts are not inputs): hand it the disclosed values,
        # and compare cores by value (15 steps 3-4)
        from .committed import disclosed_values
        run_inputs = disclosed_values(run_inputs)
        orig_core = disclosed_values(orig_core)
    token = _CMP_CANON.set(cmp_canon)
    try:
        return _reproduce_compare(bundle, runner, spec, capability, orig_core, run_inputs, profile, verify_fields)
    finally:
        _CMP_CANON.reset(token)


def _reproduce_compare(bundle, runner, spec, capability, orig_core, run_inputs, profile, verify_fields) -> dict:
    fresh = runner.run(capability, run_inputs)
    fresh_core = fresh["manifest"]["result"]["value"]
    if subject_canon(bundle)[0] == 3:
        from .committed import disclosed_values
        try:
            fresh_core = disclosed_values(fresh_core)
        except ValueError:
            pass                       # a fresh bundle with withheld items cannot match; the comparison says so
    # an outputs-only runner (proof-reproduce --command) copies every claim field from the sealed bundle, so the
    # sealed band is never applied (only a band the REVIEWER passed) and the claim is not re-derived at all
    outputs_only = getattr(runner, "outputs_only", False) is True
    reviewer_tol = getattr(runner, "reviewer_tolerance", None) if outputs_only else None
    result_match, reproduce_detail = _cores_match(orig_core, fresh_core, outputs_only=outputs_only,
                                                  reviewer_tol=reviewer_tol)
    sealed_prov = _sealed_provenance_of(bundle)
    fresh_prov = fresh["manifest"]["provenance"]["value"]
    # the sealed CLAIM (fidelity / verdict / reproduce_tolerance / produced_by / caveats) must be re-declared
    # unchanged; an outputs-only run cannot re-declare it, which the report names instead (claims_not_rederived)
    claim_drift = {} if outputs_only else _claim_drift(orig_core, fresh_core, sealed_prov, fresh_prov)
    if claim_drift:
        result_match = False
        reproduce_detail = {**reproduce_detail, "claim_drift": claim_drift,
                            "claim_drift_reason": _claim_drift_reason(claim_drift)}
    # The re-run must have honored the SEALED inputs, not substituted its own. `reproduce_bundle` hands
    # the runner the sealed inputs, but a runner that ignores a field, drops a sealed threshold, or
    # returns a fixed result would re-derive the number off DIFFERENT inputs than the ones the bundle
    # sealed -- so compare the fresh bundle's own sealed inputs against this bundle's. A mismatch means
    # the reproduction did not actually re-run the sealed case; it must not certify.
    fresh_inputs_blk = fresh.get("manifest", {}).get("inputs", {}) if isinstance(fresh, dict) else {}
    fresh_inputs = fresh_inputs_blk.get("value") if isinstance(fresh_inputs_blk, dict) else None
    try:
        inputs_identical = _ccanon(spec) == _ccanon(fresh_inputs)
    except ValueError:
        inputs_identical = False
    environment = _compare_environment(sealed_prov, fresh_prov, profile=profile)
    report = {
        "capability": capability,
        # `reproduced` is the ONE reproduction verdict, the same rule as proof-reproduce's exit 0 (filled in below):
        # the result core and claim re-derive AND the gate passes AND the sealed inputs were used AND the
        # environment is pinned and matches. The raw comparison alone is `result_rederived`.
        "reproduced": False,
        "result_rederived": result_match,
        "inputs_identical": inputs_identical,   # the re-run used the sealed inputs, not substituted ones
        "unverified": False,                    # integrity held, so the re-derivation was attempted
        **verify_fields,
        "reproduce_detail": reproduce_detail,   # how it compared: exact, or a stat-tolerance delta
        # sealed claim fields the fresh run re-declared differently ({} when none) -- any entry fails `reproduced`
        "claim_drift": claim_drift,
        # True for an outputs-only reproducer (--command): only the outputs were compared, and these claim fields
        # were taken from the bundle, NOT re-derived
        "outputs_only": outputs_only,
        "claims_not_rederived": list(CLAIMS_NOT_REDERIVED_OUTPUTS_ONLY) if outputs_only else [],
        # the sealed environment (data library / deck / generator / seed / run controls) vs the re-run's
        "environment": environment,
        "environment_mismatch": environment["mismatch"],          # {pin: {sealed, fresh}} -- blocks certify
        "environment_unverifiable": environment["unverifiable"],  # named gap (unpinned data) -- blocks certify
        "bundle_identical": fresh["bundle_sha256"] == bundle.get("bundle_sha256"),
        "original_bundle_sha256": bundle.get("bundle_sha256"),
        "reproduced_bundle_sha256": fresh["bundle_sha256"],
        # the freshly re-derived bundle itself, so a consumer (e.g. `reproduce --out`) can
        # emit it for an INDEPENDENT reviewer diff without re-running the engine. Not serialized into
        # the certification record; a transient re-derivation.
        "fresh_bundle": fresh,
    }
    shortfalls = reproduction_shortfalls(report)
    report["shortfalls"] = shortfalls if result_match else []
    report["reproduced"] = bool(result_match and not outputs_only and not shortfalls)
    return report


def certify_bundle(data: bytes | str, runner: ReproduceRunner, *, profile=None, policy=None, pins=None,
                   as_of: str | None = None) -> dict:
    """VERIFY + REPRODUCE, returning an attestation record (evidence.certification.v1).

    `runner` is the consumer-injected reproduce harness (see `reproduce_bundle`).
    `profile` (optional, duck-typed, additive) selects the on-disk dialect for the integrity/origin check
    and the re-derivation; `profile=None` (the default) is the neutral dialect, byte/behaviour-unchanged.

    `policy` / `pins` / `as_of` are the receiver's trust inputs for the one gate (see `reproduce_bundle`).

    `certified` is true iff the bundle passes the ONE gate (`verified`: proof-verify's exit 0 under the receiver's
    trust inputs -- integrity, origin under the receiver's pins, valid sign-offs, an accepting decision) AND its
    result core re-derives from the open engine AND the re-run honored the SEALED inputs
    (`inputs_identical`: a runner that substitutes inputs or ignores a sealed threshold never certifies)
    AND the re-run's environment matches the sealed pins (no `environment_mismatch`, no
    `environment_unverifiable` gap). If reproduction cannot even be
    attempted (inputs withheld or the producer absent), `reproduced` is false and `reproduce_error`
    names why -- never a silent pass. An intact bundle signed under a non-pinned key is re-derived
    (`reproduced` is real) but reports `origin_ok: False` and is never `certified`. While proof-core
    pins the public demo identity (`pinned_key_is_demo` True), origin can never be established, so a
    demo-signed bundle is reproduced-but-not-origin-certified: `reproduced` may be True yet `certified`
    is False.
    """
    from proof_verify.verify import (  # the independent verifier (no kernel import)
        pinned_key_fingerprint,
        pinned_key_is_demo,
    )

    from .envelope import received_bundle
    data, bundle = received_bundle(data, "certify_bundle")   # bytes or text (SPEC 4); a parsed object: TypeError
    if as_of is None:
        # ONE evaluation instant for this gate and the one reproduce_bundle runs below (never straddle trusted_until)
        from proof_verify.verify import utc_now
        as_of = utc_now()
    gate_fields, decision = _gate_fields(data, profile, policy, pins, as_of)   # the ONE gate (SPEC 4: the bytes)
    ver = decision.report
    record = {
        # a dialect brands its own certification-record schema; None/default -> the neutral tag.
        "schema": getattr(profile, "certification_schema", None) or CERTIFICATION_SCHEMA,
        "bundle_sha256": bundle.get("bundle_sha256") if isinstance(bundle, dict) else None,
        # the ONE gate's pass (proof-verify exit 0 under the receiver's trust inputs), never a looser reading
        "verified": decision.passed,
        "gate": gate_fields["gate"],
        "verify_problems": ver["problems"],
        # the two halves of `verified`, separately: an intact record signed under a non-pinned key is
        # integrity_ok / not origin_ok -- re-derivable, but never certified (origin is unproven)
        "integrity_ok": ver["integrity_ok"],
        "origin_ok": ver["origin_ok"],
        "signer": ver.get("signer"),   # absent on an `unreadable` verdict (SPEC 13.1)
        # Carry the origin caveat INTO the machine-readable record, not just the CLI print layer: a
        # consumer that renders `verified: true` must be able to see whether that is integrity-only
        # (demo key) or integrity+origin (production key), so "Verified" is never mistaken for origin.
        # When a dialect profile supplies its OWN trust root, these two record fields must reflect the
        # PROFILE's pin (which classify_bundle already resolved), not the verifier's module-global demo
        # pin -- otherwise a branded certify record is self-inconsistent (the record is an unsigned
        # report, so this is a correctness fix, not a sealed-byte change). profile=None keeps the
        # module-global pin, byte/behaviour-unchanged.
        "pinned_key_is_demo": (ver.get("pinned_key_is_demo", pinned_key_is_demo()) if profile is not None
                               else pinned_key_is_demo()),
        "pinned_key_fingerprint": (ver.get("pinned_key", pinned_key_fingerprint()) if profile is not None
                                   else pinned_key_fingerprint()),
        # Seed the FULL documented reproduce key set with safe defaults BEFORE the try, so every return
        # path (happy path, ReproduceError, or a re-run that started but could not finish) hands back a
        # record of consistent shape. Without this a consumer reading e.g. `environment_mismatch` or
        # `reproduced_bundle_sha256` off a redacted-inputs / unavailable-capability record would KeyError.
        "capability": None,
        "reproduced": False,
        "result_rederived": False,
        "shortfalls": [],
        "inputs_identical": False,
        "reproduce_detail": {},
        "claim_drift": {},
        "outputs_only": getattr(runner, "outputs_only", False) is True,
        "claims_not_rederived": [],
        "environment": {"ok": False, "mismatch": {}, "notes": [], "unverifiable": None,
                        "ignored": list(ENV_IGNORED)},
        "environment_mismatch": {},
        "environment_unverifiable": None,
        "bundle_identical": False,
        "reproduced_bundle_sha256": None,
    }
    environment_ok = False
    try:
        repro = reproduce_bundle(data, runner, profile=profile, policy=policy, pins=pins, as_of=as_of)
        record.update({
            "capability": repro["capability"],
            "reproduced": repro["reproduced"],
            "result_rederived": repro["result_rederived"],
            "shortfalls": repro["shortfalls"],
            "inputs_identical": repro["inputs_identical"],
            "reproduce_detail": repro["reproduce_detail"],
            "claim_drift": repro["claim_drift"],
            "outputs_only": repro["outputs_only"],
            "claims_not_rederived": repro["claims_not_rederived"],
            "environment": repro["environment"],
            "environment_mismatch": repro["environment_mismatch"],
            "environment_unverifiable": repro["environment_unverifiable"],
            "bundle_identical": repro["bundle_identical"],
            "reproduced_bundle_sha256": repro["reproduced_bundle_sha256"],
        })
        environment_ok = bool(repro["environment"].get("ok"))
    except ReproduceError as exc:
        # inputs redacted, or the producing capability is not available -- a specific, named gap.
        record.update({"reproduced": False, "reproduce_error": str(exc)})
    except Exception as exc:  # noqa: BLE001 -- reproduction re-runs arbitrary producer code
        # the re-run started but could not finish (composed capability missing a sub-step, missing data
        # dependency, ...). This is NOT a result-core mismatch -> `reproduced` stays unknown, never a
        # silent False that reads like a forgery.
        record.update({"reproduced": None, "result_rederived": None,
                       "reproduce_error": f"{type(exc).__name__}: {exc}"})

    # A MATERIAL metadata drift (the fresh re-run's result self-declares a different verdict or fidelity
    # tier than the sealed core) must not ride under certified:True -- a downgrade would otherwise sit in a
    # note next to a green verdict. Surfaced as `metadata_conflict` and blocks certification; it also fails
    # `reproduced` (claim_drift). A caveat the fresh run declares that the sealed bundle omits is material too (it is
    # in claim_drift and metadata_conflict); only EXTRA sealed caveats stay informational (`metadata_drift`).
    # Unconditional (verdict/fidelity/caveats are kernel contract fields), so it is byte-neutral hardening of the
    # unsigned report, not a profile knob.
    metadata_conflict = _material_metadata_conflict(record.get("reproduce_detail"))
    record["metadata_conflict"] = metadata_conflict
    # an outputs-only reproduction (the claim fields were copied, not re-derived) never certifies; `verified` is the
    # ONE gate's pass, so a bundle proof-verify rejects is never certified (certified = gate AND reproduced AND ...)
    record["certified"] = bool(
        record["verified"] and record.get("reproduced") and not record.get("outputs_only")
        and record.get("inputs_identical") and environment_ok and not metadata_conflict
    )
    return record


def seal_certification(data: bytes | str, runner: ReproduceRunner, *, role: str = "reproduced",
                       profile=None, canon_version: int | None = None, policy=None, pins=None,
                       as_of: str | None = None) -> dict:
    """Run certify over `bundle` and SEAL the reproduction verdict into its OWN signed evidence bundle,
    cryptographically CHAINED to the subject via the existing `derived_from` mechanism.

    `policy` / `pins` / `as_of` are the receiver's trust inputs for the ONE gate (see `certify_bundle`): the record's
    `certified` is never True for a subject that gate does not pass, and the record carries the gate's verdict
    (`verified`, `gate_exit_code`, `gate_reasons`), so no signed `certified: true` is minted for a bundle proof-verify
    rejects.

    `canon_version` (ADR-054) selects the record's canon; None (default) uses the SUBJECT's sealed canon. A
    record may not use a LOWER canon than its subject (the mint refuses a v1 link to a v2 upstream).

    `certify_bundle` returns an UNSIGNED report on purpose -- a reviewer trusts their own run, it is not a
    signed claim. But a reviewer (or a paid independent-reproduction service) often needs to HAND SOMEONE a
    checkable artifact that says "I re-ran this subject and here is what came back". This builds exactly that:
    a new, signed evidence bundle whose result core carries the reproduction verdict (reproduced /
    inputs_identical / environment_ok / certified / mode) and whose `derived_from` binds it to the subject's
    exact seal. Editing either the verdict or the link breaks this bundle's own signature, and the chain is
    walkable -- a reader re-verifies the subject by its sealed digest. This is deliberately the same shape a
    paid independent reproduction would produce; the open spine mints it, it does not gate who may.

    The existing unsigned-report default (`certify_bundle`) is unchanged; this is an ADDED path. Signed with
    whatever key `signing` is configured for (the public demo key by default, so the record is honest about
    its own origin exactly as every other proof-core bundle is).

    Returns the new signed bundle (verify it with proof_verify like any other). Raises ValueError if the
    subject carries no `bundle_sha256` to chain to.
    """
    from .contract import Case, Fidelity, Result, Verdict
    from .envelope import build_bundle, received_bundle, sha

    data, bundle = received_bundle(data, "seal_certification")   # the subject's bytes or text (SPEC 4)
    subject_seal = bundle.get("bundle_sha256") if isinstance(bundle, dict) else None
    subject_sums = bundle.get("sha256sums") if isinstance(bundle, dict) else None
    subject_core = bundle.get("result") if isinstance(bundle, dict) else None
    if not isinstance(subject_seal, str) or not subject_seal:
        raise ValueError("cannot seal a reproduction record: the subject bundle has no bundle_sha256 "
                         "to chain to (seal the subject first)")
    # ADR-049 (one strict dialect): the chain link is BINDING, and the chain WALKER requires `consumed.path`
    # to address the upstream's result map (/result/<capability>). So the record consumes the subject's
    # sealed result FOR ITS CAPABILITY by digest -- it needs the subject's sha256sums (the link's digest
    # triple), its result core, and a single readable capability to scope the consumed pointer.
    res_map = subject_core.get("result") if isinstance(subject_core, dict) else None
    if not isinstance(subject_sums, dict) or not isinstance(res_map, dict):
        raise ValueError(  # noqa: TRY004 -- a redacted/malformed subject is a value precondition, not a caller type bug
            "cannot seal a reproduction record: the subject must carry its sealed result core "
            "and sha256sums to bind to (a subject with its result redacted cannot be sealed)")
    record = certify_bundle(data, runner, profile=profile, policy=policy, pins=pins, as_of=as_of)
    reproduced = record.get("reproduced")
    # the subject's capability scopes the binding pointer /result/<cap>; the walker cross-checks it against
    # the upstream's sealed kind, so take it from the reproduce record and confirm it keys the result map.
    subject_cap = record.get("capability")
    if not isinstance(subject_cap, str) or subject_cap not in res_map:
        raise ValueError("cannot seal a reproduction record: the subject's result core is not single-capability "
                         f"(capability {subject_cap!r} does not key its result map) -- no scoped value to bind to")
    consumed_value = res_map[subject_cap]
    # ADR-054: the record is minted under the SUBJECT's sealed canon by default (a v2 subject gets a v2 record;
    # a v1 subject -- which may carry a bare big int v2 cannot represent -- stays v1), and its link's consumed
    # digest is taken under the RECORD's canon, which is what the walker re-derives.
    if canon_version is None:
        sv = subject_sums.get("canon_version")
        canon_version = sv if type(sv) is int and sv in _CANON else 1
    if type(canon_version) is not int or canon_version not in _CANON:
        raise ValueError(f"unsupported canon_version {canon_version!r}; supported: {sorted(_CANON)}")
    consumed_sha = sha(_CANON[canon_version](consumed_value))
    verdict = (Verdict.PASS if reproduced is True
               else Verdict.FAIL if reproduced is False else Verdict.ADVISORY)
    outputs = {
        "subject_bundle_sha256": subject_seal,
        "subject_capability": record.get("capability"),
        # True only by proof-reproduce's exit-0 rule (gate AND re-derived AND inputs identical AND environment ok);
        # False / None (could not be attempted). The raw result-core comparison alone is `result_rederived`.
        "reproduced": reproduced,
        "result_rederived": record.get("result_rederived"),
        "shortfalls": list(record.get("shortfalls") or []),
        "inputs_identical": record.get("inputs_identical"),
        "environment_ok": bool((record.get("environment") or {}).get("ok")),
        "certified": record.get("certified") is True and record.get("verified") is True,
        "mode": (record.get("reproduce_detail") or {}).get("mode"),
        # the ONE gate's verdict on the subject (proof-verify's single-bundle exit code under the trust inputs used)
        "verified": record.get("verified") is True,
        "gate_exit_code": (record.get("gate") or {}).get("exit_code"),
        "gate_reasons": list((record.get("gate") or {}).get("reasons") or []),
        # WHAT produced that gate verdict, so the record cannot be re-presented for the same subject seal under other
        # trust inputs or with other sign-offs (a signed rejection appended after a clean-copy record was minted):
        # the policy digest, the evaluation instant, the effective pin set's digest, and the digest of the subject's
        # unsealed decision members (sign-offs, time tokens, archive) as evaluated -- see proof_verify.gate
        "gate_policy_sha256": (record.get("gate") or {}).get("policy_sha256"),
        "gate_as_of": (record.get("gate") or {}).get("as_of"),
        "gate_pins_sha256": (record.get("gate") or {}).get("pins_sha256"),
        "subject_evaluated_signoffs_sha256": (record.get("gate") or {}).get("evaluated_signoffs_sha256"),
    }
    if record.get("reproduce_error"):
        outputs["reproduce_error"] = record["reproduce_error"]
    result = Result(
        capability=REPRODUCTION_CAPABILITY,
        fidelity=Fidelity.SCREENING,            # a re-run record; a reference tier is earned, never declared
        verdict=verdict,
        outputs=outputs,
        caveats=(
            ("this record attests that a reproduction was RUN and what it returned; it does NOT attest that "
             "the subject's result is correct. Re-verify the subject independently by its sealed digest."),
            ("the headline verdict is `reproduced`: pass only when the subject passed verify under the named trust "
             "inputs (gate_policy_sha256, gate_as_of, gate_pins_sha256) AND its result re-derived from its sealed "
             "inputs in a matching environment. It holds only for the subject carrying exactly the sign-offs whose "
             "digest is subject_evaluated_signoffs_sha256; a copy carrying other sign-offs is a different decision."),
        ),
    )
    from proof_core import __version__
    return build_bundle(
        Case(capability=REPRODUCTION_CAPABILITY,
             inputs={"subject_bundle_sha256": subject_seal, "subject_result": consumed_value}),
        result,
        engine="proof-core-reproduce", engine_version=__version__,
        reproduce=("proof-reproduce <subject.json> --runner <the subject's runner> "
                   "(re-run the subject; this record attests that run)"),
        # the chain: a BINDING link (ADR-049). This record CONSUMES the subject's sealed result FOR ITS
        # CAPABILITY (RFC 6901 pointer /result/<subject_cap>) by digest, so the kernel's own reproduction
        # record both verifies AND WALKS to the subject under the kernel's own binding verifier -- the walker
        # cross-checks that pointer's capability against the subject's sealed kind, and the consumed digest
        # binds on both ends (this record's `subject_result` input and the subject's result-map value). It
        # records FACTS only -- no verdict field (the reproduction verdict lives in this record's signed
        # outputs; origin is the walker's call).
        derived_from=[{
            "bundle_sha256": subject_seal,
            "sha256sums": subject_sums,
            "consumed": {"input": "subject_result", "path": f"/result/{subject_cap}", "sha256": consumed_sha},
            "role": role,
        }],
        # mint the record under the SAME dialect the subject was reproduced under, so a branded
        # consumer's reproduction record verifies in its own dialect. profile=None -> neutral.
        profile=profile,
        canon_version=canon_version,
    )
