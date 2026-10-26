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

import copy
import math

from .contract import ReproduceRunner
from .envelope import canon, is_integrity_field, stat_tolerance_problem
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

#: The fresh run's 1-sigma must sit within this factor of the sealed one. The band is
#: `sigmas * hypot(sealed, fresh)`, so a fresh sigma far wider than sealed (a re-run with far fewer
#: samples than the sealed run controls) would widen the band the sealed claim is held to; a fresh
#: sigma far narrower means the re-run did not use the sealed controls either. Same controls -> the
#: two stochastic sigma estimates agree to well within 2x.
_SIGMA_RATIO = 2.0

#: Result-core keys that are PROSE / METADATA, not computed values or integrity: a stat reproduce compares them
#: SEPARATELY and reports a difference as `metadata_drift` (informational) instead of failing the
#: re-derivation. A caveat re-worded, a band tightened, a verdict label or fidelity tier re-declared
#: since the mint does not change whether the NUMBER falls out of the code. Everything else in the core
#: (the outputs' engine, counts, generator/model pins, benchmark id, the provenance stub) stays in the
#: strict byte-for-byte remainder.
METADATA_KEYS = ("caveats", "reproduce_tolerance", "verdict", "fidelity")

#: Of the metadata keys, these two are the MATERIAL claim fields: the result's self-declared `verdict`
#: and `fidelity` tier. A caveat re-wording or an (only-tightening) tolerance change is cosmetic, but if
#: the fresh re-run's result declares a DIFFERENT verdict or fidelity than the sealed one, `certified`
#: must not silently assert the sealed claim -- the drift is surfaced as `metadata_conflict` and blocks
#: certification. It never fails `reproduced`: the NUMBER still re-derives. Domain-neutral (verdict/fidelity
#: are kernel contract fields), so this is unconditional hardening, not a profile knob.
MATERIAL_METADATA_KEYS = ("verdict", "fidelity")


def _material_metadata_conflict(reproduce_detail) -> dict:
    """The subset of a stat reproduce's `metadata_drift` that is MATERIAL to certification
    (verdict/fidelity). Empty for an exact reproduce, a missing detail, or cosmetic-only drift."""
    if not isinstance(reproduce_detail, dict):
        return {}
    drift = reproduce_detail.get("metadata_drift") or {}
    return {k: v for k, v in drift.items() if k in MATERIAL_METADATA_KEYS}


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


class ReproduceError(RuntimeError):
    """Raised when a bundle cannot be reproduced with the open engine."""


def _exact_match(orig_core, fresh_core) -> tuple[bool, dict]:
    try:
        return (orig_core is not None and canon(orig_core) == canon(fresh_core)), {"mode": "exact"}
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


def _stat_match(orig_core: dict, fresh_core: dict, tol: dict) -> tuple[bool, dict]:
    """Statistical (stochastic) reproduce: the declared quantity must agree within `sigmas`
    times the combined 1-sigma, and EVERY other value/integrity byte of the core must be identical
    (except fields the tolerance declares `derived` from the quantity -- see below). Prose/metadata
    keys (METADATA_KEYS) are compared separately and reported as `metadata_drift`, never a failure.

    Falls back to an EXACT match (conservative -- a malformed band can never turn a mismatch into a
    pass), with a named reason, when: the sealed tolerance is unusable (fields missing/non-numeric,
    sigma_key == quantity, a sealed relative sigma >= 5% of the value, `derived` naming an integrity
    field); the band is non-finite/negative/wider than _MAX_SIGMAS; or the fresh sigma is not within
    _SIGMA_RATIO of the sealed one (the re-run did not use the sealed run controls).

    The effective band is the TIGHTER of the sealed tolerance and the fresh (code-declared) one, and
    the effective `derived` set is their intersection: the sealed tolerance is what the reviewer is
    held to, but a re-signed bundle that widened its own band or declared extra `derived` fields can
    never loosen the comparison beyond what the open engine's card actually declares."""
    cap = next(iter(orig_core.get("result", {})), None)
    q, sigma_key = tol.get("quantity"), tol.get("sigma_key")
    o_out = orig_core.get("result", {}).get(cap, {})
    f_out = fresh_core.get("result", {}).get(cap, {})
    problem = stat_tolerance_problem(tol, o_out)
    if problem:
        return _exact_fallback(orig_core, fresh_core, f"sealed tolerance unusable: {problem}")
    try:
        o_val, f_val = float(o_out[q]), float(f_out[q])
        o_sig, f_sig = float(o_out[sigma_key]), float(f_out[sigma_key])
        sigmas = float(tol.get("sigmas"))
    except (KeyError, TypeError, ValueError):
        return _exact_fallback(orig_core, fresh_core, "tolerance fields missing or non-numeric")
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
    fresh_tol = fresh_core.get("reproduce_tolerance")
    fresh_tol = fresh_tol if isinstance(fresh_tol, dict) and fresh_tol.get("kind") == "stat" else {}
    sealed_sigmas = sigmas
    try:
        fs = float(fresh_tol.get("sigmas"))
        if math.isfinite(fs) and 0 <= fs < sigmas:
            sigmas = fs
    except (TypeError, ValueError):
        pass
    # compare two independent estimates: the tolerance band is sigmas * sqrt(sig_a^2 + sig_b^2)
    combined = math.hypot(o_sig, f_sig)
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
    rest_identical = canon(o_rest) == canon(f_rest)
    metadata_drift = {
        k: {"sealed": o_meta.get(k), "fresh": f_meta.get(k)}
        for k in METADATA_KEYS if canon(o_meta.get(k)) != canon(f_meta.get(k))
    }
    return bool(within and rest_identical), {
        "mode": "stat", "quantity": q, "sigmas": sigmas, "sealed_sigmas": sealed_sigmas,
        "delta": delta, "sigma": combined, "n_sigma": delta / combined,
        "within_tolerance": within, "rest_identical": rest_identical,
        # prose/metadata that changed since the mint -- informational, never a failure
        "metadata_drift": metadata_drift,
    }


def _cores_match(orig_core, fresh_core) -> tuple[bool, dict]:
    """Compare the recorded result core against a fresh re-run. Exact by default; a core that
    declares a statistical `reproduce_tolerance` is compared within that tolerance instead."""
    tol = orig_core.get("reproduce_tolerance") if isinstance(orig_core, dict) else None
    if isinstance(tol, dict) and tol.get("kind") == "stat":
        return _stat_match(orig_core, fresh_core, tol)
    return _exact_match(orig_core, fresh_core)


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
            if canon(s_val) != canon(f_val):
                env["notes"].append(
                    f"data.{key} differs (sealed {s_val!r}, fresh {f_val!r}) -- a path-sensitive index "
                    "hash, informational only; the content pin is data_library_sha256")
        elif key.endswith("_sha256") or key in env_run_controls:
            pins[f"data.{key}"] = (s_val, f_val)
    for name, (s_val, f_val) in pins.items():
        if canon(s_val) != canon(f_val):
            env["mismatch"][name] = {"sealed": s_val, "fresh": f_val}
    # toolchain (python / platform / engine image): ADVISORY -- recorded so a reviewer sees whether their
    # runtime matches the minting one below the version string, but NEVER a hard block (a reviewer on a
    # different toolchain is expected; the result core re-derives regardless). Old packs carry none -> skip.
    s_tc = sealed_prov.get("toolchain")
    if isinstance(s_tc, dict):
        f_tc = fresh_prov.get("toolchain") if isinstance(fresh_prov.get("toolchain"), dict) else {}
        if canon(s_tc) != canon(f_tc):
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
    return value


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
    return value


def _sealed_provenance_of(bundle: dict):
    """The sealed provenance value, or None when withheld/absent (an environment gap, not an error)."""
    block = bundle.get("manifest", {}).get("provenance", {})
    return block.get("value") if isinstance(block, dict) else None


def reproduce_bundle(bundle: dict, runner: ReproduceRunner, *, profile=None) -> dict:
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

    Returns a report: {capability, reproduced (result core re-derives), inputs_identical (the re-run
    used the sealed inputs, not substituted ones), reproduce_detail, environment, environment_mismatch,
    environment_unverifiable, bundle_identical, original_bundle_sha256, reproduced_bundle_sha256,
    fresh_bundle, verified, integrity_ok, origin_ok, signer, verify_problems}.
    A bundle whose INTEGRITY fails (hashes inconsistent, or the signature invalid under the bundle's own
    embedded key) is not re-run: the report carries `unverified: True`, `reproduced: False` and the verify
    problems, so `reproduced` can never be read as trustworthy over a tampered bundle. A bundle that is
    intact but signed under a key other than the pinned one IS re-run -- its sealed inputs are exactly
    what the signer sealed -- and reports `origin_ok: False`, `verified: False` alongside the real
    re-derivation result. Raises ReproduceError if the inputs OR the result are withheld, or the
    capability is not registered.
    """
    from proof_verify.verify import classify_bundle  # the independent verifier (no kernel import)

    ver = classify_bundle(bundle, profile=profile)
    verify_fields = {
        "verified": ver["integrity_ok"] and ver["origin_ok"],   # integrity + origin, as verify_bundle
        "integrity_ok": ver["integrity_ok"],
        "origin_ok": ver["origin_ok"],
        # surfaced so a consumer sees WHY origin is unproven: while the pin is the public demo identity
        # origin_ok is False even for a pin-signed bundle, so `verified`/`certified` are never origin.
        "pinned_key_is_demo": ver["pinned_key_is_demo"],
        "signer": ver["signer"],
        "verify_problems": ver["problems"],
    }
    if not ver["integrity_ok"]:
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
            "inputs_identical": False,          # never re-run, so the sealed inputs were not re-derived
            "unverified": True,
            **verify_fields,
            "reproduce_detail": {"mode": "not-attempted",
                                 "reason": "bundle integrity fails (seal/signature/hash problems); "
                                           "an edited or forged record is never re-derived"},
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
    fresh = runner.run(capability, spec["inputs"])
    fresh_core = fresh["manifest"]["result"]["value"]
    result_match, reproduce_detail = _cores_match(orig_core, fresh_core)
    # The re-run must have honored the SEALED inputs, not substituted its own. `reproduce_bundle` hands
    # the runner the sealed inputs, but a runner that ignores a field, drops a sealed threshold, or
    # returns a fixed result would re-derive the number off DIFFERENT inputs than the ones the bundle
    # sealed -- so compare the fresh bundle's own sealed inputs against this bundle's. A mismatch means
    # the reproduction did not actually re-run the sealed case; it must not certify.
    fresh_inputs_blk = fresh.get("manifest", {}).get("inputs", {}) if isinstance(fresh, dict) else {}
    fresh_inputs = fresh_inputs_blk.get("value") if isinstance(fresh_inputs_blk, dict) else None
    try:
        inputs_identical = canon(spec) == canon(fresh_inputs)
    except ValueError:
        inputs_identical = False
    environment = _compare_environment(_sealed_provenance_of(bundle),
                                       fresh["manifest"]["provenance"]["value"], profile=profile)
    return {
        "capability": capability,
        "reproduced": result_match,
        "inputs_identical": inputs_identical,   # the re-run used the sealed inputs, not substituted ones
        "unverified": False,                    # integrity held, so the re-derivation was attempted
        **verify_fields,
        "reproduce_detail": reproduce_detail,   # how it compared: exact, or a stat-tolerance delta
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


def certify_bundle(bundle: dict, runner: ReproduceRunner, *, profile=None) -> dict:
    """VERIFY + REPRODUCE, returning an attestation record (evidence.certification.v1).

    `runner` is the consumer-injected reproduce harness (see `reproduce_bundle`).
    `profile` (optional, duck-typed, additive) selects the on-disk dialect for the integrity/origin check
    and the re-derivation; `profile=None` (the default) is the neutral dialect, byte/behaviour-unchanged.

    `certified` is true iff the bundle verifies under the pinned key (integrity AND origin) AND its
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
        classify_bundle,
        pinned_key_fingerprint,
        pinned_key_is_demo,
    )

    ver = classify_bundle(bundle, profile=profile)
    record = {
        # a dialect brands its own certification-record schema; None/default -> the neutral tag.
        "schema": getattr(profile, "certification_schema", None) or CERTIFICATION_SCHEMA,
        "bundle_sha256": bundle.get("bundle_sha256") if isinstance(bundle, dict) else None,
        "verified": ver["integrity_ok"] and ver["origin_ok"],   # integrity + origin (verify_bundle's ok)
        "verify_problems": ver["problems"],
        # the two halves of `verified`, separately: an intact record signed under a non-pinned key is
        # integrity_ok / not origin_ok -- re-derivable, but never certified (origin is unproven)
        "integrity_ok": ver["integrity_ok"],
        "origin_ok": ver["origin_ok"],
        "signer": ver["signer"],
        # Carry the origin caveat INTO the machine-readable record, not just the CLI print layer: a
        # consumer that renders `verified: true` must be able to see whether that is integrity-only
        # (demo key) or integrity+origin (production key), so "Verified" is never mistaken for origin.
        # When a dialect profile supplies its OWN trust root, these two record fields must reflect the
        # PROFILE's pin (which classify_bundle already resolved), not the verifier's module-global demo
        # pin -- otherwise a branded certify record is self-inconsistent (the record is an unsigned
        # report, so this is a correctness fix, not a sealed-byte change). profile=None keeps the
        # module-global pin, byte/behaviour-unchanged.
        "pinned_key_is_demo": ver["pinned_key_is_demo"] if profile is not None else pinned_key_is_demo(),
        "pinned_key_fingerprint": (ver["pinned_key"] if profile is not None
                                   else pinned_key_fingerprint()),
        # Seed the FULL documented reproduce key set with safe defaults BEFORE the try, so every return
        # path (happy path, ReproduceError, or a re-run that started but could not finish) hands back a
        # record of consistent shape. Without this a consumer reading e.g. `environment_mismatch` or
        # `reproduced_bundle_sha256` off a redacted-inputs / unavailable-capability record would KeyError.
        "capability": None,
        "reproduced": False,
        "inputs_identical": False,
        "reproduce_detail": {},
        "environment": {"ok": False, "mismatch": {}, "notes": [], "unverifiable": None,
                        "ignored": list(ENV_IGNORED)},
        "environment_mismatch": {},
        "environment_unverifiable": None,
        "bundle_identical": False,
        "reproduced_bundle_sha256": None,
    }
    environment_ok = False
    try:
        repro = reproduce_bundle(bundle, runner, profile=profile)
        record.update({
            "capability": repro["capability"],
            "reproduced": repro["reproduced"],
            "inputs_identical": repro["inputs_identical"],
            "reproduce_detail": repro["reproduce_detail"],
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
        record.update({"reproduced": None, "reproduce_error": f"{type(exc).__name__}: {exc}"})

    # A MATERIAL metadata drift (the fresh re-run's result self-declares a different verdict or fidelity
    # tier than the sealed core) must not ride under certified:True -- a downgrade would otherwise sit in a
    # note next to a green verdict. Surfaced as `metadata_conflict` and blocks certification; it never fails
    # `reproduced` (the number still re-derives). Cosmetic drift (caveats, a tightened tolerance) stays
    # informational. Unconditional (verdict/fidelity are kernel contract fields), so it is byte-neutral
    # hardening of the unsigned report, not a profile knob.
    metadata_conflict = _material_metadata_conflict(record.get("reproduce_detail"))
    record["metadata_conflict"] = metadata_conflict
    record["certified"] = bool(
        record["verified"] and record.get("reproduced")
        and record.get("inputs_identical") and environment_ok and not metadata_conflict
    )
    return record


def seal_certification(bundle: dict, runner: ReproduceRunner, *, role: str = "reproduced",
                       profile=None) -> dict:
    """Run certify over `bundle` and SEAL the reproduction verdict into its OWN signed evidence bundle,
    cryptographically CHAINED to the subject via the existing `derived_from` mechanism.

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
    from .envelope import build_bundle, sha

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
    record = certify_bundle(bundle, runner, profile=profile)
    reproduced = record.get("reproduced")
    # the subject's capability scopes the binding pointer /result/<cap>; the walker cross-checks it against
    # the upstream's sealed kind, so take it from the reproduce record and confirm it keys the result map.
    subject_cap = record.get("capability")
    if not isinstance(subject_cap, str) or subject_cap not in res_map:
        raise ValueError("cannot seal a reproduction record: the subject's result core is not single-capability "
                         f"(capability {subject_cap!r} does not key its result map) -- no scoped value to bind to")
    consumed_value = res_map[subject_cap]
    consumed_sha = sha(canon(consumed_value))
    verdict = (Verdict.PASS if reproduced is True
               else Verdict.FAIL if reproduced is False else Verdict.ADVISORY)
    outputs = {
        "subject_bundle_sha256": subject_seal,
        "subject_capability": record.get("capability"),
        "reproduced": reproduced,                       # True / False / None (could not be attempted)
        "inputs_identical": record.get("inputs_identical"),
        "environment_ok": bool((record.get("environment") or {}).get("ok")),
        "certified": record.get("certified"),
        "mode": (record.get("reproduce_detail") or {}).get("mode"),
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
            ("the headline verdict reflects the RESULT-CORE match only (reproduced); inputs_identical, "
             "environment_ok and certified are SEPARATE axes carried in this record's outputs -- read them, "
             "not the verdict alone, to judge whether the re-run matched the sealed case and environment."),
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
    )
