"""The evidence envelope: embeds the evidence.result.v1 core UNCHANGED and adds a canonical-JSON
SHA-256 manifest of (inputs, result, provenance), then SIGNS the manifest digest. The bundle is the
unit of evidence; the producer's computed result -- a simulation output, a model score, an AI
pipeline's answer, any number a decision rests on -- is its input.

Three tamper-evidence layers, strongest last:
  hashes      -- the bundle wasn't edited
  provenance  -- WHAT produced it (code + data + seed), folded into the signed manifest
  signature   -- it came from the pinned signer's key (non-repudiation; a reviewer trusts the key)
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from decimal import Decimal
from json.encoder import encode_basestring as _json_escape  # stdlib C escaper, ensure_ascii=False
from typing import Any

from . import provenance as prov
from . import signing
from .contract import Case, Result
from .result import build_result_core

#: A well-formed content digest, the only shape a sealed `data_library_sha256` may take (mirrors the
#: verifier's S6 rule; restated here so the MINT refuses what the verifier would reject).
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")

#: ADR-050: the REFERENCE canon's output-definition version, stamped INSIDE `sha256sums` (a 4th key, under
#: the seal) so a retained bundle self-describes which canon produced its hashes, and a stale verifier can
#: fail FORWARD ("use a newer verifier") rather than mistake a newer format for tampering. The single source
#: of truth -- NOT a `Profile` field: the canon is profile-invariant (ADR-047), so no dialect may brand or
#: omit it. A future change to what `canon` EMITS becomes version 2 with v1 frozen verbatim; a verifier-port
#: bug is fixed in place with NO bump (the format did not move).
CANON_VERSION = 1


def normalize_floats(obj: Any) -> Any:
    """Return `obj` with every float ``-0.0`` replaced by ``0.0`` (recursively; dicts/lists copied).

    ``-0.0 == 0.0`` in Python and IEEE-754, but ``json.dumps`` writes them as different bytes
    (``-0.0`` vs ``0.0``), so a sealed delta that happened to round to ``-0.0`` would fail an exact
    re-derivation that landed on ``0.0`` -- a false-fail on a value that is numerically identical.
    Applied to the sealed sections at MINT (so the bundle carries ``0.0`` and any strict verifier's
    plain canonical JSON agrees) and inside `canon` (so comparisons see one spelling). No shipped
    pack contains ``-0.0``, so no existing seal moves."""
    if isinstance(obj, float):
        return 0.0 if obj == 0.0 else obj          # -0.0 == 0.0 -> the positive spelling; NaN != NaN untouched
    if isinstance(obj, dict):
        return {k: normalize_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [normalize_floats(v) for v in obj]
    return obj


def canon(obj: Any) -> bytes:
    """Canonical JSON bytes (sorted keys, no whitespace) -- the bytes every digest is taken over.

    RFC 8259 strict: ``allow_nan=False`` so a NaN/Infinity raises ``ValueError`` at MINT instead of
    sealing ``NaN`` tokens that strict and browser JSON parsers reject (a bundle that verifies in
    Python but not in the in-browser checker is a false-fail off-Python). A card with an undefined
    value emits ``None`` (JSON ``null``) instead. ``-0.0`` is normalized to ``0.0`` (see
    `normalize_floats`)."""
    return json.dumps(normalize_floats(obj), sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


# --- canon_version 2: strict RFC 8785 (JCS) + string-encoded big ints (ADR-053) ----------------------
# v2 removes v1's three CPython deviations: strings are raw UTF-8 with JCS-minimal escaping (NOT
# ensure_ascii), numbers follow ECMAScript Number::toString (a whole float collapses: 2.0 -> "2"), and
# object keys sort by UTF-16 code unit (NOT code point). Integers outside +-(2^53-1) cannot be bare numbers
# (JCS numbers are IEEE-754 doubles): the mint GUARDS and refuses one (fail-loud -- encode it as a string),
# and refuses a lone surrogate (no UTF-8 encoding). The ES number rule reuses Python's shortest-round-trip
# repr() for digit selection, then reformats per ECMA-262 6.1.6.1.20. Kept byte-identical to the independent
# verifier's `_canon_v2` (proof_verify.verify); the conformance battery + a cross-language fuzz locks parity.
_SAFE_INT = 2**53 - 1   # Number.MAX_SAFE_INTEGER -- the largest bare integer canon v2 may carry
_V2_SHORT_ESCAPE = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


_V2_SURROGATE = re.compile("[\ud800-\udfff]")


def _v2_surrogate_escape(m: re.Match) -> str:
    return f"\\u{ord(m.group()):04x}"


def _v2_guard(obj: Any) -> None:
    t = type(obj)
    if t is str or t is bool or obj is None:          # exact-type fast paths; subclasses take the generic path
        return
    if t is dict:
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"canon v2: object key must be a string, got {type(k).__name__}")
            if type(v) is not str:                    # a str value is always representable
                _v2_guard(v)
        return
    if t is list:
        for v in obj:
            if type(v) is not str:
                _v2_guard(v)
        return
    if isinstance(obj, bool):
        return
    if isinstance(obj, int):
        if not (-_SAFE_INT <= obj <= _SAFE_INT):
            raise ValueError(f"canon v2: bare integer {obj} is outside +-(2^53-1); encode it as a JSON string "
                             "(RFC 8785 cannot represent it as a number)")
    elif isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("canon v2: NaN/Infinity are not valid JSON")
    elif isinstance(obj, str):
        return   # always representable: a lone surrogate is escaped to \uXXXX by canon_v2 (JCS), not raw UTF-8
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"canon v2: object key must be a string, got {type(k).__name__}")
            _v2_guard(k)
            _v2_guard(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _v2_guard(v)
    elif obj is not None:
        raise ValueError(f"canon v2: not a JSON value: {type(obj).__name__}")


def _v2_string(s: str) -> str:
    # The stdlib's C JSON escaper with ensure_ascii=False already writes the RFC 8785 form for every scalar value:
    # the short escapes \b \t \n \f \r \" \\, every other C0 control as lowercase \u00xx, and everything else raw
    # (DEL, U+2028/U+2029, all other non-ASCII, astral characters). The one difference: it passes a lone surrogate
    # through raw, where JCS / JSON.stringify write lowercase \uXXXX. That is fixed up here; an escape the C
    # escaper wrote is pure ASCII, so the fix-up can never touch one.
    out = _json_escape(s)
    if _V2_SURROGATE.search(out) is None:
        return out
    return _V2_SURROGATE.sub(_v2_surrogate_escape, out)


def _v2_number(n: Any) -> str:
    if isinstance(n, int):
        return str(n)
    if not math.isfinite(n):
        raise ValueError("canon v2: NaN/Infinity are not valid JSON")
    if n == 0:
        return "0"
    if type(n) is float:
        # Fast path. repr() picks the shortest round-trip digits (the digits the general path below starts from)
        # and writes positional notation exactly when the decimal exponent is in [-4, 16), inside ECMAScript's
        # positional range (-7, 21). There the two agree except that repr() writes a whole value as "2.0" where
        # ES writes "2". A value repr() writes in exponent form takes the general path.
        r = repr(n)
        if "e" not in r:
            return r.removesuffix(".0")
    neg = n < 0
    _, digs, exp = Decimal(repr(abs(n))).as_tuple()
    digs = list(digs)
    while len(digs) > 1 and digs[-1] == 0:
        digs.pop()
        exp += 1
    s = "".join(map(str, digs))
    k = len(s)
    m = k + exp
    if k <= m <= 21:
        out = s + "0" * (m - k)
    elif 0 < m <= 21:
        out = s[:m] + "." + s[m:]
    elif -6 < m <= 0:
        out = "0." + "0" * (-m) + s
    else:
        mant = s[0] + ("." + s[1:] if k > 1 else "")
        e = m - 1
        out = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return "-" + out if neg else out


def _v2_utf16_key(kv: tuple) -> bytes:
    return kv[0].encode("utf-16-be", "surrogatepass")


def _v2_write(obj: Any, w) -> None:
    """Append the JCS text of `obj` to the output through `w` (a list's append): one join at the end, instead of
    re-copying every nested container's text into its parent's string at each level."""
    t = type(obj)                                     # exact-type dispatch first: the shapes json.loads produces
    if t is str:
        w(_v2_string(obj))
        return
    if t is dict:
        keys = list(obj)
        if all(type(k) is str and k.isascii() for k in keys):
            # all-ASCII keys: code-point order IS UTF-16 code-unit order, and dict keys are distinct, so a plain
            # sort gives exactly the order of the UTF-16 sort below
            keys.sort()
            items = [(k, obj[k]) for k in keys]
        else:
            items = sorted(obj.items(), key=_v2_utf16_key)
    elif t is list:
        items = None
    elif t is int:
        w(str(obj))
        return
    elif t is float:
        w(_v2_number(obj))
        return
    elif obj is None:
        w("null")
        return
    elif obj is True:
        w("true")
        return
    elif obj is False:
        w("false")
        return
    elif isinstance(obj, str):
        w(_v2_string(obj))
        return
    elif isinstance(obj, (int, float)):
        w(_v2_number(obj))
        return
    elif isinstance(obj, (list, tuple)):
        items = None
    elif isinstance(obj, dict):
        items = sorted(obj.items(), key=_v2_utf16_key)
    else:
        raise TypeError(f"not a JSON value: {type(obj).__name__}")
    if items is None:                                 # an array
        sep = "["
        for v in obj:
            w(sep)
            sep = ","
            _v2_write(v, w)
        w("]" if sep == "," else "[]")
    else:                                             # an object, members in JCS order
        sep = "{"
        for k, v in items:
            w(sep)
            sep = ","
            w(_v2_string(k) + ":")
            _v2_write(v, w)
        w("}" if sep == "," else "{}")


def _v2_emit(obj: Any) -> str:
    parts: list[str] = []
    _v2_write(obj, parts.append)
    return "".join(parts)


def canon_v2(obj: Any) -> bytes:
    """canon_version 2 bytes: guard (reject unrepresentable values, fail-loud) then emit JCS (UTF-8)."""
    _v2_guard(obj)
    return _v2_emit(obj).encode("utf-8")


def canon_v3(obj: Any) -> bytes:
    """canon_version 3 bytes (SPEC v4 draft 5.6.1): ``canon_2(T(x))``, T the committed-item projection. T is the
    verifier's own (``proof_verify.verify.project``), so a minted digest is the one every verifier recomputes."""
    from proof_verify.verify import project
    return canon_v2(project(obj))


#: version -> mint canon (mirrors proof_verify.verify._CANON). APPEND-ONLY and FROZEN: v1 stays verbatim.
_CANON = {1: canon, 2: canon_v2, 3: canon_v3}


def _assert_sealed_provenance_honest(capability: str, core: dict, repro: dict, *, profile=None,
                                     inputs_value: dict | None = None, canon_version: int = 1) -> None:
    """BELT: refuse to MINT a bundle whose sealed provenance contradicts its own signed result -- the
    "seal what actually ran" invariant, enforced at build time so a regressing producer FAILS to produce
    a bundle instead of silently shipping a false attestation. Mechanical checks only (no domain
    knowledge): a placeholder that slips back in stops the mint here rather than reaching a reviewer.

    `profile` (domain-neutral, additive) supplies the dialect's own open-engine sentinel, accepted
    `reproduce` prefixes and placeholder seed, so the belt reads the SAME constants the mint sealed with;
    None resolves to the neutral profile, whose values equal the module constants, leaving behaviour
    identical to the pre-seam belt.

    `inputs_value` is the sealed inputs section (`{"capability", "inputs"}`); it is consulted whenever the
    provenance carries a `derived_from` chain claim, to enforce the BINDING belt (a link must cite a value
    this run actually took as input). ADR-049: binding is the one chain shape, so this always runs for a
    bundle that seals a `derived_from`; a bundle that seals none is unaffected."""
    from .profile import NEUTRAL
    p = profile or NEUTRAL
    outputs = (core.get("result") or {}).get(capability) or {}
    tol = core.get("reproduce_tolerance") or {}
    seed = outputs.get("seed") if isinstance(outputs, dict) else None
    rng_seed = repro.get("rng_seed")
    if seed is not None and rng_seed != seed:
        raise ValueError(
            f"{capability}: sealed rng_seed {rng_seed!r} != the seed in the signed result ({seed!r}); "
            "a bundle must not attest a seed it did not run")
    if tol.get("kind") == "stat" and rng_seed == p.rng_seed_placeholder:
        raise ValueError(
            f"{capability}: a stochastic result (stat reproduce_tolerance) sealed rng_seed={p.rng_seed_placeholder} "
            "(the placeholder); record the seed actually used")
    # DATA-LIBRARY pin honesty (the producer-side twin of the verifier's S6 rule): a NAMED data library --
    # any non-empty string, INCLUDING the honest `unpinned` marker -- must carry a well-formed
    # `sha256:<64 hex>` digest. A name with a null/malformed digest is a claim with nothing committing to
    # the bytes; the verifier rejects it, so the mint refuses it first.
    dl, dls = repro.get("data_library"), repro.get("data_library_sha256")
    if dl is not None and not (isinstance(dl, str) and dl):
        raise ValueError(f"{capability}: data_library must be a non-empty string, got {dl!r}")
    if isinstance(dl, str) and dl and not (isinstance(dls, str) and _SHA256_RE.fullmatch(dls)):
        raise ValueError(
            f"{capability}: data_library {dl!r} is named but data_library_sha256 is not a well-formed "
            f"sha256:<64 hex> digest ({dls!r}); a named library must be pinned by content digest")
    # ORIGIN honesty (the false-attestation belt): a bundle claiming the OPEN engine produced it must be
    # OPEN-reproducible, i.e. its sealed `reproduce` path starts with `reproduce`. If `reproduce` instead
    # names an EXTERNAL engine (a run of some out-of-tree code whose output was merely recorded), the number
    # was NOT produced by the open engine -- refuse to seal the open-engine claim over it. The fix at the
    # call site is to set provenance["produced_by"]="external:<code>", which names the real producer and
    # clears this belt. Mechanical + domain-agnostic: it reads only the two fields already in the signed
    # manifest.
    produced_by = repro.get("produced_by")
    reproduce = repro.get("reproduce") or ""
    # the open-engine reproduce path names the re-run of the open engine: the `proof-reproduce` CLI, or a
    # bare `reproduce ...` phrasing. An EXTERNAL command (a vendor tool, an out-of-tree run) must not ride
    # under the open-engine label.
    if produced_by == p.produced_by_open and not reproduce.startswith(p.reproduce_open_prefixes):
        raise ValueError(
            f"{capability}: produced_by claims the open engine ({p.produced_by_open!r}) but the sealed "
            f"reproduce path is external ({reproduce!r}); an externally-produced result must set "
            f"provenance['produced_by']='{p.produced_by_external_prefix}<code>' -- do not seal it as open-engine-derived")
    # produced_by must be UNAMBIGUOUS: either the exact open sentinel or an explicit `external:<code>`.
    # A near-miss ("open", "open-engin") would slip past the check above (it is not
    # the exact sentinel) yet read to a human as open-engine-derived, letting an external number be
    # sealed under an open-looking label. `verify` never inspects produced_by, so this mint-time belt
    # is the only guard.
    if produced_by != p.produced_by_open and not str(produced_by).startswith(p.produced_by_external_prefix):
        raise ValueError(
            f"{capability}: produced_by {produced_by!r} is neither the open sentinel "
            f"({p.produced_by_open!r}) nor an explicit '{p.produced_by_external_prefix}<code>'; set one so the "
            "sealed origin cannot read as open-engine-derived when it is not")
    # STAT-TOLERANCE honesty: a sealed statistical band is only as honest as the sigma it is built on.
    # `reproduce` bounds the re-run by `sigmas * hypot(min(sealed_sigma, fresh_sigma), fresh_sigma)`, so a sealed sigma that
    # is absurd (sigma == the value; sigma_key pointing at the quantity or at an unrelated count) would
    # make ANY fresh value "reproduce". The consumer side falls back to an exact match on such a band
    # (certify._stat_match); this belt refuses to MINT one in the first place. Same bounds both sides, and the same
    # strict number rule (stat_number_problem): a string or boolean band, quantity or sigma is refused, not coerced.
    if tol.get("kind") == "stat":
        problem = stat_number_problem(tol, outputs) or stat_tolerance_problem(tol, outputs)
        if problem:
            raise ValueError(f"{capability}: refusing to seal a stat reproduce_tolerance: {problem}")
    # PROVENANCE-SHAPE belt: the verifier's own required/optional provenance rules (not a second copy), so the
    # producer never signs a bundle its verifier rejects -- e.g. a Result.provenance override of rng_seed=None.
    from proof_verify.verify import (
        _check_frontier_slots,
        _check_optional_provenance,
        _check_required_provenance,
    )
    shape_problems: list[str] = []
    _check_required_provenance(repro, shape_problems)
    _check_optional_provenance(repro, shape_problems)
    # the frontier slots (applicability / completeness / derived_from shape): the same rule the verifier applies,
    # with no own-seal yet (the self-reference check needs the final seal; the verifier still applies it).
    # derived_from is held to its own CHAIN belt below (the verifier's shape rule + the binding check), so it is
    # left out here rather than reported twice.
    _check_frontier_slots({k: v for k, v in repro.items() if k != "derived_from"}, shape_problems, p,
                          own_seal=None)
    if repro.get("data_library", "") is None:
        shape_problems.append("provenance data_library is null")
    if shape_problems:
        raise ValueError(f"{capability}: refusing to seal a provenance the verifier would reject: {shape_problems}")
    # CHAIN belt (ADR-049: binding is the one chain shape): a sealed `derived_from` link must be BINDING,
    # not decoration -- the producer-end twin of the verifier's shape rule. Two refusals, mechanical +
    # domain-agnostic: (1) the link must pass the verifier's OWN closed shape rule (no second copy), so the
    # producer can never seal a link the verifier would reject; (2) `consumed.sha256` MUST equal the digest
    # of this bundle's OWN sealed input named by `consumed.input` -- i.e. the run actually TOOK that value.
    # Binding only against own inputs; the UPSTREAM end is the chain walker's job.
    if "derived_from" in repro:
        from proof_verify.verify import derived_from_problems  # the verifier's rule, not a second copy
        links = repro["derived_from"]
        problems = derived_from_problems(links, p.derived_from_keys)
        if problems:
            raise ValueError(f"{capability}: refusing to seal a malformed derived_from chain claim: {problems}")
        own_inputs = inputs_value.get("inputs") if isinstance(inputs_value, dict) else None
        if not isinstance(own_inputs, dict):
            raise ValueError(f"{capability}: derived_from needs the sealed inputs to bind against; none were given")
        canon_fn = _CANON[canon_version]
        for i, link in enumerate(links):
            link_fn = canon_fn
            # ADR-054: the citing canon must be at least the upstream's. A v1 digest is spelling-sensitive
            # (`2.0` != `2`) while a v2 upstream's seal is not, so a v1 link to a v2 upstream would bind or not
            # depending on how the upstream's JSON is spelled. The verifier's walker refuses it; so does the mint.
            up_cv = link["sha256sums"].get("canon_version")
            if up_cv > canon_version:
                raise ValueError(
                    f"{capability}: derived_from[{i}] cites a canon_version {up_cv} upstream from a canon_version "
                    f"{canon_version} bundle; the citing canon must be at least the upstream's (mint this bundle "
                    f"under canon_version {up_cv})")
            key = link["consumed"]["input"]
            if key not in own_inputs:
                raise ValueError(
                    f"{capability}: derived_from[{i}] says it consumed input {key!r}, but the sealed inputs carry "
                    "no such key -- a chain link must name a value this run actually took as input")
            if canon_version == 3 and up_cv != 3:
                # SPEC v4 draft 9.4 rule 2: to a canon-1/2 upstream both ends digest under canon_2 with NO
                # projection, and the citing input "MUST NOT contain an object member named `$committed`". Rule 5
                # asks producers to meet rules 2 and 3 at mint; this mint enforces rule 2 only. Rule 3 (a
                # consumed.path that resolves to, or passes through, an item in the upstream) is NOT checked here:
                # the verifier's chain walk reports such a link as `consumed-mismatch`.
                from proof_verify.verify import _has_committed_member
                if _has_committed_member(own_inputs[key]):
                    raise ValueError(
                        f"{capability}: derived_from[{i}] binds a canon_version {up_cv} upstream through input "
                        f"{key!r}, which holds a committed item; a link to a canon-1/2 upstream cannot bind an item "
                        "(SPEC 9.4 rule 2)")
                link_fn = canon_v2
            # under the canon THIS bundle seals with (ADR-054): the walker re-derives it the same way.
            got = sha(link_fn(own_inputs[key]))
            if got != link["consumed"]["sha256"]:
                raise ValueError(
                    f"{capability}: derived_from[{i}] consumed.sha256 {link['consumed']['sha256']} != the digest of "
                    f"the sealed input {key!r} ({got}); the link cites an upstream value this run did not consume -- "
                    "decoration, not binding; refusing to mint")


#: Fields a stat tolerance may NEVER declare `derived` (excluded from the bit-identical remainder):
#: the integrity pins a reviewer relies on to know the SAME model/generator/engine ran. Blanking them
#: would let a re-run of a different model "reproduce" a sealed number (see result.stat_tolerance).
INTEGRITY_FIELDS = frozenset({"engine", "benchmark_id", "generator_sha256", "model_sha256"})

#: Upper bound on the sealed RELATIVE 1-sigma of a stat-tolerance quantity. A converged stochastic
#: estimate (a sampling-based tally, a bootstrapped model score) carries a sigma of order 1e-4..1e-2 of its
#: value; a sealed sigma of 5% or more of the value is not a statistical band, it is a hole (a score of
#: 1.0 +/- 1.0 "reproduces" anything).
MAX_RELATIVE_SIGMA = 0.05


def is_integrity_field(name: str) -> bool:
    return name in INTEGRITY_FIELDS or name.endswith("_sha256")


def _json_number(value):
    """``value`` as a float when it is a finite JSON number (an int or a float, never a bool), else None. A
    statistical comparison never coerces a string such as "20.0" or a boolean with float(): either is a mismatch.
    One definition for the mint belt (``stat_number_problem``) and reproduce (``certify._stat_match``)."""
    if type(value) not in (int, float):
        return None
    try:
        out = float(value)
    except OverflowError:
        return None
    return out if math.isfinite(out) else None


def stat_number_problem(tol: dict, outputs: dict) -> str | None:
    """Why a stat tolerance's numbers would not survive reproduce's strict number rule (None = they do): the band
    width ``sigmas``, the quantity and its 1-sigma must each be a finite JSON number, never a string or a boolean.
    Reproduce treats a string or a boolean there as a mismatch (``certify._stat_match``), so the mint refuses to seal
    one: the record would carry a band no honest re-run can ever be compared under. Names absent from ``outputs``
    (and a malformed ``quantity`` / ``sigma_key``) are left to ``stat_tolerance_problem``."""
    if _json_number(tol.get("sigmas")) is None:
        return f"sigmas {tol.get('sigmas')!r} must be a finite JSON number (not a string or a boolean)"
    if isinstance(outputs, dict):
        for key in (tol.get("quantity"), tol.get("sigma_key")):
            if isinstance(key, str) and key in outputs and _json_number(outputs[key]) is None:
                return (f"{key!r} = {outputs[key]!r} must be a finite JSON number (not a string or a boolean); "
                        "reproduce compares it as one")
    return None


def stat_tolerance_problem(tol: dict, outputs: dict) -> str | None:
    """Why a sealed stat tolerance is unusable against `outputs` (None = it is sound). Shared by the
    mint-time belt (refuse to seal) and the reproduce side (fall back to an exact match), so the two
    can never disagree about what a plausible band is."""
    q, sigma_key = tol.get("quantity"), tol.get("sigma_key")
    if not isinstance(q, str) or not isinstance(sigma_key, str):
        return "quantity/sigma_key must be output-key strings"
    if sigma_key == q:
        return f"sigma_key {sigma_key!r} names the quantity itself (a self-referential band)"
    derived = tol.get("derived", [])
    if not isinstance(derived, (list, tuple)):
        return "derived must be a list of output keys"
    bad = sorted(d for d in derived if not isinstance(d, str) or is_integrity_field(d))
    if bad:
        return f"derived names integrity fields {bad} (never excluded from the remainder check)"
    if not isinstance(outputs, dict) or q not in outputs or sigma_key not in outputs:
        return f"outputs lack {q!r} and/or {sigma_key!r}"
    try:
        val, sig = float(outputs[q]), float(outputs[sigma_key])
    except (TypeError, ValueError):
        return f"{q!r}/{sigma_key!r} are not numeric"
    if not (math.isfinite(val) and math.isfinite(sig)) or sig <= 0 or val == 0:
        return f"sigma {sig!r} must be finite and > 0 over a finite, non-zero value {val!r}"
    rel = sig / abs(val)
    if rel >= MAX_RELATIVE_SIGMA:
        return (f"relative sigma {rel:.3g} >= {MAX_RELATIVE_SIGMA:g} ({sigma_key}={sig!r} over {q}={val!r}) "
                "is not a statistical band")
    return None


#: SPEC 7.8 SIG-16 / 7.9 SIG-19: at most 7 co-signatures, so at most 8 declared seal signers.
_MAX_COSIGNERS = 7


def _seal_signer_set(canon_version: int, cosigners) -> list[dict]:
    """The declared seal signer set `provenance.seal_signers` (SPEC 7.9) the mint will write: entry 0 is the primary,
    entries 1 onward the co-signers in order. Refuses (ValueError) whatever the verifier would fail: co-signers on a
    v3 bundle (SIG-17), a non-Ed25519 primary on a v3 bundle (7.1: `alg` is "ed25519"), more than 7 co-signers,
    a key that does not fit its suite, or a repeated (alg, public_key) pair (SIG-19)."""
    cosigners = list(cosigners or [])
    if canon_version != 3:
        if cosigners:
            raise ValueError("co-signatures (SPEC 7.8 `signatures`) exist only in evidence.envelope.v4 "
                             "(canon_version=3); a v3 bundle carries one Ed25519 signature")
        if signing.active_alg() != "ed25519":
            raise ValueError(f"a v3 bundle is signed with Ed25519 only (SPEC 7.1); the active signer is "
                             f"{signing.active_alg()!r}; mint with canon_version=3 instead")
        return []
    if len(cosigners) > _MAX_COSIGNERS:
        raise ValueError(f"at most {_MAX_COSIGNERS} co-signers (SPEC 7.8 SIG-16), got {len(cosigners)}")
    for i, c in enumerate(cosigners):
        signing.signer_key_problems(c, where=f"cosigners[{i}]")
    out = [{"alg": signing.active_alg(), "public_key": signing.public_key_hex()}]
    out += [{"alg": signing.signer_alg(c), "public_key": bytes(c.public_key()).hex()} for c in cosigners]
    pairs = [(e["alg"], e["public_key"]) for e in out]
    if len(set(pairs)) != len(pairs):
        raise ValueError("the seal signer set repeats an (alg, public_key) pair (SPEC 7.9 SIG-19): a key signs a "
                         "seal at most once")
    return out


def _self_verify_seal_signatures(capability: str, bundle: dict, seal_signers: list[dict], cosigners: list) -> None:
    """SPEC 7.16 SIG-36 / SIG-37, at mint: E = [signature] + signatures equals `seal_signers` (G2), and every
    co-signature (and a primary of any suite other than the built-in Ed25519 path) verifies over the seal. A suite
    this kernel implements is checked with its own code; any other suite needs the signer's own ``verify(msg, sig)``
    (the signing library's verify), so an honest hybrid keeps its verdict when the suite is activated (7.18)."""
    if not seal_signers:
        return
    blocks = [bundle["signature"]] + bundle.get("signatures", [])
    if [(b["alg"], b["public_key"]) for b in blocks] != [(e["alg"], e["public_key"]) for e in seal_signers]:
        raise ValueError(f"{capability}: refusing to mint: the seal signatures do not equal seal_signers (SIG-36)")
    msg = bundle["bundle_sha256"].encode()
    checks = [(bundle["signature"], signing._ACTIVE_SIGNER)] if signing.active_alg() != "ed25519" else []
    checks += list(zip(bundle.get("signatures", []), cosigners))
    for blk, signer in checks:
        sig = bytes.fromhex(blk["signature"])
        ok = signing.verify_suite(blk["alg"], bytes.fromhex(blk["public_key"]), msg, sig)
        if ok is None:
            own = getattr(signer, "verify", None)
            if own is None:
                raise ValueError(f"{capability}: refusing to mint: a {blk['alg']!r} co-signer must provide "
                                 "verify(msg, sig) so the mint can self-verify it (SPEC 7.16 SIG-37)")
            ok = own(msg, sig) is True
        if not ok:
            raise ValueError(f"{capability}: refusing to mint: the {blk['alg']!r} seal signature by "
                             f"{blk['public_key'][:16]}... does not verify over the seal (SPEC 7.16 SIG-37)")


def build_bundle(case: Case, result: Result, *, engine: str, engine_version: str,
                 reproduce: str | None = None,
                 data_library: tuple[str, str] | None = None,
                 lineage: list | None = None,
                 applicability: dict | None = None,
                 completeness: dict | None = None,
                 derived_from: list | None = None,
                 solver: dict | None = None,
                 canon_version: int = 1,
                 profile=None,
                 cosigners: list | None = None) -> dict:
    # `profile` (domain-neutral, ADDITIVE) brands the on-disk dialect -- schema tags, the open-engine
    # sentinel, the default `reproduce` phrasing, the unpinned-data marker, the attestation scope, and
    # whether a `host` block is emitted. None resolves to the neutral profile, whose values ARE the
    # constants this function read before the seam, so the default path's bytes are byte-identical.
    # EVERYTHING profile-invariant (canon, sha, signing, the manifest/sha256sums/bundle_sha256 math)
    # stays below, untouched by the profile -- a profile can never weaken the seal.
    from .profile import NEUTRAL
    p = profile or NEUTRAL
    # canon_version selects the canonicalization (ADR-053): v1 (default, FROZEN) or v2 (strict JCS). All
    # digests below use `_c`, INCLUDING a derived_from link's `consumed.sha256` (ADR-054: a link's consumed
    # digest is taken under the canon of the bundle that SEALS the link, so the chain walker re-derives it
    # under the citing bundle's sealed canon_version). Everything else is version-agnostic (signing, the
    # manifest/seal math, the ASCII header).
    # strict int (a bool or 2.0 compares equal to 1/2 but would seal a header no verifier accepts)
    if type(canon_version) is not int or canon_version not in _CANON:
        raise ValueError(f"unsupported canon_version {canon_version!r}; supported: {sorted(_CANON)}")
    _c = _CANON[canon_version]
    # SPEC v4 7.8 / 7.9 / 7.16: the seal signer set is the primary (the active signer: the built-in seed or the
    # `use_signer` hook) plus `cosigners`, every one known BEFORE minting (SIG-36). Co-signatures exist only in v4.
    seal_signers = _seal_signer_set(canon_version, cosigners)
    # the sealed sections carry the NORMALIZED spelling (-0.0 -> 0.0), so the digest a strict, plain
    # canonical-JSON verifier recomputes over the stored value equals the one taken here.
    core = normalize_floats(build_result_core(case, result, profile=p))
    inputs_value = normalize_floats({"capability": case.capability, "inputs": case.inputs})
    # run-scoped provenance (e.g. a data-snapshot or reference-library digest) OVERRIDES the module
    # placeholders and lands in the signed manifest, so a bundle claiming one data set that actually ran
    # on another cannot exist without breaking the signature. Only OS-independent facts belong here.
    run_prov = dict(result.provenance or {})
    # the data library is passed in by the caller (the data set THIS run actually read); a direct
    # caller that passes nothing gets the honest `unpinned` default -- the envelope never reads a
    # process-global, so a stray recording elsewhere cannot leak into this bundle's signed claim.
    _run_data_id, _run_data_sha = data_library or (p.data_library_unpinned_id, p.data_library_unpinned_sha256)
    repro = {
        "engine": engine,
        "engine_version": engine_version,
        # git HEAD by default; PINNABLE via provenance so an evidence bundle assembled from RECORDED data
        # (not a live git-tracked run) stays bit-reproducible regardless of the working tree's commit
        "code_version": run_prov.pop("code_version", prov.code_version()),          # what code
        # what data: the run records what it actually read (an in-tree table, a staged reference
        # library, a plant data snapshot); a producer can still override via its Result.provenance; a
        # producer that touched no data falls back to the honest `unpinned` marker -- never a fake claim.
        "data_library": run_prov.pop("data_library", _run_data_id),
        "data_library_sha256": run_prov.pop("data_library_sha256", _run_data_sha),
        "rng_seed": run_prov.pop("rng_seed", p.rng_seed_placeholder),                 # what seed
        # WHO produced/reproduced this number: the open engine by DEFAULT (so `reproduce`
        # re-derives it from the recorded inputs). A producer that PACKAGES an externally-computed result
        # (a simulation run out of tree, a vendor model's output, a third-party service's answer)
        # sets Result.provenance["produced_by"]="external:<code>", so the seal names the true producer
        # instead of letting an as-received number read as open-engine-derived. Folded into the SIGNED
        # manifest -> the origin claim is tamper-evident, not decorative.
        "produced_by": run_prov.pop("produced_by", p.produced_by_open),              # who produced it
        # what TOOLCHAIN produced it (python / platform / engine-image digest). Signed so `reproduced-exact`
        # is honest below the version string; ADVISORY (certify surfaces a diff, never blocks -- a reviewer on
        # a different toolchain is expected and the result CORE re-derives regardless). This IS environment-
        # specific by design (unlike the OS-independent pins above): it records the minting toolchain so a
        # reproduction mismatch is visible, not mysterious -- the signed twin of the diagnostic `host` block.
        # Cross-OS determinism is unaffected: that guarantee is on the RESULT CORE, not the provenance digest.
        # `solver` (default None) threads an EXTERNAL solver record into the signed toolchain (see
        # provenance.toolchain / solver_record); solver=None emits the same toolchain dict as before, so the
        # neutral golden/packs are byte-identical. An explicit Result.provenance["toolchain"] still wins via
        # the run_prov.pop precedence below.
        "toolchain": run_prov.pop("toolchain", prov.toolchain(solver=solver)),
        # reproducible GIVEN these pinned facts, ACROSS operating systems. The RESULT CORE is
        # OS-independent (that is what reproduce compares); the signed PROVENANCE deliberately is not --
        # code_version and the `toolchain` axis above name the minting environment on purpose -- so
        # full-BUNDLE byte identity is NOT cross-OS (code_version/toolchain/host differ -> bundle_sha
        # differs by design), only the result core is. A consumer that ships committed packs should keep
        # a cross-OS canary (re-derive a pack sealed on one OS on another and assert a bit-exact result
        # core). The host block below stays diagnostic-only (unsigned) so any divergence is findable.
        # Reflect what the producer actually delivers: a stochastic result (a `stat` reproduce_tolerance
        # in the signed core) is reproducible only within that sealed band, NOT bit-for-bit -- claiming
        # bit-determinism there would contradict the producer's own tolerance.
        "deterministic": (
            "reproducible within the sealed reproduce_tolerance given (data_library_sha256, rng_seed, code_version)"
            if (result.reproduce_tolerance or {}).get("kind") == "stat"
            else "bit-identical given (data_library_sha256, rng_seed, code_version)"),
        # how a reviewer re-derives this number: `reproduce` re-runs the open engine on the
        # bundle's OWN recorded inputs (no args to retype -- they are in the sealed manifest) and checks
        # the result core re-derives. Override for evidence whose value came from an EXTERNAL engine (an
        # out-of-tree simulation run, a vendor model) so the string names that path instead of a command
        # that can't reproduce it.
        "reproduce": reproduce if reproduce is not None else p.reproduce_default,
        # the signed CLAIM BOUNDARY: what this seal does and does NOT attest, in the signed manifest so it is
        # tamper-evident, not implied. Makes "seal what ran" cryptographic -- an integrity+origin seal can
        # never be mistaken for proof the run happened (that is `reproduce`) or that the number is correct
        # (that is the benchmark/closure evidence). Static + general by design (see prov.ATTESTATION_SCOPE).
        # Coerced to a plain dict so a read-only MappingProxyType profile view seals to identical bytes.
        "attestation_scope": dict(p.attestation_scope),
    }
    # OPTIONAL frontier assertion slots, sealed into provenance (the signed manifest) so they are
    # tamper-evident PRODUCER claims the verifier carries and shape-checks, never evaluates. Absent is the
    # honest default (not asserted). `applicability` is a domain adapter's in-distribution verdict (never a
    # correctness claim the seal makes); `completeness` is an honest declaration of what the record
    # captured; `derived_from` binds this record to the exact seal(s) of prior ones (the transitive chain).
    # See proof_verify.verify._check_frontier_slots for the shape the verifier enforces.
    if applicability is not None:
        repro["applicability"] = applicability
    if completeness is not None:
        repro["completeness"] = completeness
    if derived_from is not None:
        repro["derived_from"] = derived_from
    if run_prov:                                       # remaining run-scoped facts (pack_id, temperature, ...)
        repro["data"] = run_prov
    if lineage:                                        # composed-derivation lineage: the ordered sub-cards
        # this result was built from (run_step), each with its input/output digests. In the SIGNED
        # provenance, so the derivation is tamper-evident; a leaf card composes nothing -> no lineage.
        repro["lineage"] = {"count": len(lineage), "steps": lineage}
    if canon_version == 3:
        # SPEC v4 draft 7.9 SIG-18: "In v4, `manifest.provenance.value` MUST contain `seal_signers`". This release
        # seals with the one primary signature, so the declared list is that signer alone (7.10 G2).
        repro["seal_signers"] = seal_signers
    repro = normalize_floats(repro)
    withheld_at_mint: list[str] = []
    if canon_version == 3:
        # Producer side of SPEC 6.6: refuse any `$committed` object that is not a well-formed, well-placed item --
        # 6.6.1 "A producer MUST refuse domain data that uses the key `$committed` outside an item" -- and items in
        # provenance (P2). The rules are the VERIFIER's item walk, so the mint can never seal what it rejects.
        from proof_verify.verify import _v4_item_walk
        walk_problems: list[str] = []
        walk = _v4_item_walk({"inputs": {"value": inputs_value}, "result": {"value": core},
                              "provenance": {"value": repro}}, {"inputs", "result", "provenance"}, walk_problems)
        if walk_problems:
            raise ValueError(f"{case.capability}: refusing to mint a canon-3 bundle: {walk_problems[:5]}")
        withheld_at_mint = sorted(walk["W"])
    manifest = {
        "inputs": {"sha256": sha(_c(inputs_value)), "value": inputs_value},
        "result": {"sha256": sha(_c(core)), "value": core},   # the result.v1 core, unchanged
        "provenance": {"sha256": sha(_c(repro)), "value": repro},  # signed, not just informational
    }
    # The signed seal commits to the LIST of section digests, NOT their contents. Each value is
    # still pinned (manifest[s].sha256 == sha(canon(value)) and equals its entry here), so the
    # seal transitively covers everything -- but a section's value can be WITHHELD (redacted)
    # while its digest keeps the commitment intact and the signature stays valid. See
    # proof_core.redaction.
    # ADR-050: `canon_version` is a 4th key INSIDE `sha256sums` (NOT a new top-level key), so it is covered
    # by the existing seal equation `bundle_sha256 == sha(canon(sha256sums))` -- editing or stripping it
    # breaks the seal + signature (integrity FAIL, never fail-forward). canon sorts keys, so the emitted
    # bytes carry it first regardless of insertion order; the seal equation below is textually UNCHANGED.
    sha256sums = {"canon_version": canon_version}
    sha256sums.update({s: manifest[s]["sha256"] for s in ("inputs", "result", "provenance")})
    # Belt (the mint never ships a sha256sums without the version): the golden-bytes gate pins the shape too.
    assert "canon_version" in sha256sums, "mint invariant: sha256sums must carry canon_version"
    # BELT (don't mint a self-contradicting bundle): runs BEFORE signing, so the signing key is never
    # invoked on a bundle that would then be discarded when the belt raises. It reads only core/repro/
    # profile/inputs_value (all finalized above), never the signature, so the ordering is clean. Belts run
    # before signing; emitted bytes and verdicts are identical to the old belt-last order: a passing bundle
    # signs exactly as before; a failing one raises and emits NOTHING either way -- the only difference is
    # that the key is never touched on a refused mint.
    _assert_sealed_provenance_honest(case.capability, core, repro, profile=p, inputs_value=inputs_value,
                                     canon_version=canon_version)
    bundle = {
        "schema": p.envelope_schema_v4 if canon_version == 3 else p.envelope_schema,
        "result": core,                       # the envelope is a superset that embeds the result core shape
        "reproducibility": repro,             # readable copy of the signed provenance block
        "manifest": manifest,
        "sha256sums": sha256sums,             # the sealed digest-list (redaction-safe)
    }
    # the seal recomputes over the ALL-ASCII sha256sums header, which canonicalizes identically under every
    # canon version (the ADR-050 header invariant); use the fixed v1 `canon` so the mint matches both
    # verifiers' header recompute explicitly (not just coincidentally for ASCII).
    bundle["bundle_sha256"] = sha(canon(sha256sums))
    bundle["signature"] = signing.sign_bundle_digest(bundle["bundle_sha256"])
    if cosigners:
        # SPEC 7.8: "No co-signatures" has exactly one encoding, the key absent; so `signatures` is written only
        # when there is at least one. Every block signs the same 71 bytes (SIG-3).
        bundle["signatures"] = [signing.sign_block(c, bundle["bundle_sha256"]) for c in cosigners]
    _self_verify_seal_signatures(case.capability, bundle, seal_signers, cosigners or [])
    if withheld_at_mint:
        # SPEC 10.4 R5: "A record MUST be present whenever W is non-empty ... That includes items withheld at mint."
        bundle["redaction"] = {"schema": p.redaction_schema_v2, "parent_bundle_sha256": bundle["bundle_sha256"],
                               "withheld_sections": [], "withheld_items": withheld_at_mint}
    # BELT (S1/S2, producer side): the block just minted is exactly {alg, public_key, signature, message}
    # with message == "bundle_sha256". Anything else rides UNSIGNED and every conforming verifier rejects
    # it, so a producer whose signing backend drifted must fail HERE, not at a reviewer's desk.
    sig_problems = signing.signature_block_problems(bundle["signature"])
    if sig_problems:
        raise ValueError(f"{case.capability}: refusing to mint a non-conforming signature block: "
                         + "; ".join(sig_problems))
    # ADR-049 (one strict dialect): the diagnostic (unsigned) `host` block is RETIRED. Its structured
    # replacement is the SIGNED `toolchain` axis above (which always carries `machine`), and a stapled
    # `host` now FAILs the verifier's top-level allowlist. The spine never emits host -- host was unsigned,
    # so dropping it leaves the seal (`bundle_sha256`) unchanged; only the on-disk bundle shape loses the key.
    return bundle
