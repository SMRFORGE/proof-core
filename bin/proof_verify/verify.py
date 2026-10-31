"""Standalone evidence-bundle verifier.

Imports ONLY the standard library -- NOTHING from proof_core or any producer. Its packaged
independence is the "verify without the tool that produced it" claim: it is a genuine second
implementation of the canonicalization, the hashing, AND the Ed25519 signature check, so a
passing verify is not the producer marking its own homework. Ships as its own package.

It checks, strongest last:
  - the envelope schema and the embedded evidence.result.v1 required fields
  - every manifest hash (inputs, result, provenance), recomputed independently, each equal to
    its entry in the SEALED digest-list; a section whose value is lawfully withheld (redacted)
    is still pinned by that digest
  - the embedded result/reproducibility copies match their hashed manifest values
  - the bundle digest over the sealed digest-list (sha256sums) -- so withholding a value never
    disturbs the seal or the signature (that is what makes a redaction verifiable)
  - the Ed25519 signature over that digest, under the public key the bundle itself carries
    (INTEGRITY: the sealed record is exactly what its signer signed)
  - that this signing key IS the PINNED key (ORIGIN: it came from the pinned signer)

Those last two are deliberately separate questions, so the verdict is THREE-state
(`classify_bundle`): integrity + origin (a record from the pinned signer), integrity only (a record signed
under some other key -- the public demo key on a dev machine, say -- whose sealed inputs and result
are nonetheless untampered), or an integrity FAILURE (edited, forged, malformed). `verify_bundle`'s
boolean keeps its original meaning, integrity AND origin.

While proof-core pins the PUBLIC demo identity (`pinned_key_is_demo()` is True), origin can NEVER be
established -- anyone can reproduce a signature under the demo seed -- so even a bundle signed under the
pin is integrity-only, and `verify_bundle` returns False for it. Origin becomes reachable only once a
real production trust root is pinned. Callers that only need integrity use `integrity_ok`.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from decimal import Decimal
from typing import Any

_RESULT_REQUIRED = ("schema", "schema_version", "result", "fidelity", "verdict")
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
#: The two hex fields of the signature block held to EXACTLY the schema's lowercase `[0-9a-f]{64}` /
#: `[0-9a-f]{128}` (no whitespace) BEFORE `bytes.fromhex`, which is case-insensitive and skips ASCII
#: whitespace. Used by the signature-hex check (and by `pin_key`); the strict lowercase-hex match
#: keeps the lenient `bytes.fromhex` path, so these change nothing unless a profile opts in.
_PUBKEY_HEX_RE = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_HEX_RE = re.compile(r"[0-9a-f]{128}")
_SECTIONS = ("inputs", "result", "provenance")
#: ADR-050: `sha256sums` carries the three section digests PLUS the integer `canon_version` (a 4th key under
#: the seal). The valid key set a well-formed `sha256sums` (bundle-level and in a derived_from link) must
#: have -- exactly the three sections plus `canon_version`.
_SHA256SUMS_KEYS = set(_SECTIONS) | {"canon_version"}
#: The signature block is UNSIGNED apart from the `signature` bytes themselves (the seal binds only
#: `bundle_sha256`), so any key beyond these four rides unsigned: an intermediary who cannot re-sign
#: could staple `"attestation": "APPROVED"` into the block of a genuinely-signed bundle and the Ed25519
#: check would still pass. Exactly these keys, nothing else; `message` MUST name what was signed.
#: (Parity checks S1/S2, 2026-10-04: identical across every conforming verifier.)
_SIGNATURE_KEYS = {"alg", "public_key", "signature", "message"}
_SIGNATURE_REQUIRED = ("alg", "public_key", "signature")
_SIGNATURE_MESSAGE = "bundle_sha256"
#: The UNSIGNED sub-objects the envelope allows, and exactly which keys each may carry. Nothing in
#: `redaction` or `host` is covered by the seal, so any key outside these allowlists is free-riding
#: prose an intermediary could add to a bundle that still "verifies" (the same hole the top-level
#: allowlist closes). `redaction` is a machine record of WHICH sections are withheld; `host` is a
#: diagnostic triple. Neither may carry a conclusion, a note, or any other unsigned claim.
_REDACTION_SCHEMA = "evidence.envelope.redaction.v1"
_HOST_KEYS = {"python_version", "python_impl", "platform"}
#: `timestamp` is an OPTIONAL unsigned RFC 3161 trusted-timestamp token embedded in the bundle (added AFTER
#: signing, by a Timestamp Authority -- so it cannot live inside the signed manifest). It is self-
#: authenticating (the TSA signs it, and it binds `bundle_sha256`, which IS signed), and its cryptographic
#: validity would be checked SEPARATELY by a dedicated RFC 3161 tool (ASN.1/CMS/X.509, which this
#: stdlib-only verifier cannot parse); no such tool ships here yet. Here we only constrain its SHAPE so
#: nothing else rides unsigned.
_TIMESTAMP_TOKEN_MAX = 200_000        # a base64 RFC 3161 token is a few KB; cap to reject a stapled blob
#: The timestamp shape (ADR-049: always strict). A timestamp is a bare RFC 3161 token with no free-text
#: label: the record is held to the CLOSED, REQUIRED {format, token} set (`_TIMESTAMP_KEYS_STRICT`), and the
#: token to strict base64 that decodes to a DER SEQUENCE (starts 'MI', correct padding, no other characters,
#: no trailing whitespace -- `fullmatch` rejects a trailing newline).
_TIMESTAMP_TOKEN_RE = re.compile(r"^MI[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_TIMESTAMP_KEYS_STRICT = {"format", "token"}                              # closed+required set when strict
#: The redaction REQUIRED key set (ADR-049: the record is always prose-free + strict): every one must be present.
#: Paired with `prose_free_redaction`, which narrows the verify-side ALLOWLIST to the same closed set.
_REDACTION_KEYS_STRICT = {"schema", "withheld", "parent_bundle_sha256"}
_MAX_JSON_DEPTH = 100                  # evidence envelopes nest a few levels; deeper is pathological -> fail closed
#: Length cap on the UNSIGNED free-text fields (redaction.reason, each redaction.caveats entry,
#: timestamp.tsa, host.*). None of these is covered by the seal, so without a cap an intermediary could
#: staple a whole paragraph of unsigned prose onto a bundle that still "verifies". A sane per-value cap
#: keeps them to short labels/notes; a stapled blob is rejected with a verdict. (They are NOT forbidden
#: -- forbidding them would need a re-mint -- only bounded.)
_FREE_TEXT_MAX = 256
#: Upper bound on the raw bundle TEXT the CLI/loader will parse. An evidence bundle is at most a few KB
#: of sealed digests plus (optionally) a small result core; a multi-megabyte field is pathological. Cap
#: the input so a 60 MB string is rejected with a verdict instead of exhausting memory in the parser.
_MAX_BUNDLE_BYTES = 8_000_000

# The signing public key PINNED here. A signature under any other key is rejected.
#
# proof-core has no production trust root yet, so the pin IS the well-known PUBLIC DEMO identity (its
# private seed ships in signing.py). A demo-key signature is reproducible by anyone, so a passing verify
# attests INTEGRITY (not edited) but NOT a meaningful ORIGIN -- `pinned_key_is_demo()` is True, and every
# verdict path words a pass as integrity-only. When proof-core earns its own production key (a hardware-token
# ceremony), set `_PINNED_PUBKEY` to that key here; a passing verify then attests origin too. A CONSUMER with
# its own production trust root does not edit this file: it calls `pin_key(pubkey_hex)` (process-wide) or
# supplies `Profile.pinned_pubkey` (per call) -- proof-core embeds no production key value.
_DEMO_PUBKEY = "069aba87747dd9c1f46f24004eb79e05eb8f2e0f2c3adfdde60c1e2e00bac838"
_PINNED_PUBKEY = _DEMO_PUBKEY

#: The verdicts of `classify_bundle`.
STATE_VERIFIED = "integrity+origin"     # every hash recomputes; valid signature under the PINNED production key
STATE_INTEGRITY_ONLY = "integrity-only"  # every hash recomputes; valid signature under some OTHER key
#: every hash recomputes and the signature is valid under the pinned key, but that pin is the public DEMO
#: identity, so origin cannot be established (anyone can sign under the demo seed). Distinct from the
#: other-key integrity-only state so a consumer can tell "ours, but a demo pin" from "signed by someone else".
STATE_INTEGRITY_ONLY_DEMO = "integrity-only (demo pin)"
STATE_FAIL = "fail"                      # a hash/seal/schema problem, or the signature is invalid
#: ADR-050 fail-FORWARD: the bundle is sealed under a `canon_version` NEWER than this verifier supports, and
#: its header seal + signature are valid -- a signed record this verifier simply cannot check the sections
#: of. A DISTINCT, NAMED verdict, never `fail`/"tampered": the honest answer is "use a newer verifier", not
#: "this is corrupt". `integrity_ok` is still False and `verify_bundle` still returns False (integrity
#: cannot be established, so a boolean consumer stays fail-closed); only the state + message distinguish it.
STATE_UNSUPPORTED_CANON = "unsupported-canon"
STATE_UNSUPPORTED_ALG = "unsupported-alg"
_ALG_SUPPORTED = frozenset({"ed25519"})
_ALG_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9.+\-]{0,31}")


def _profile_value(profile, name, default):
    """Read a dialect-shape field off an OPTIONAL, DUCK-TYPED profile object, else the neutral default.

    The profile is read ATTRIBUTE-ONLY -- this verifier never imports proof_core (nor any producer), so its
    stdlib-only, "verify without the tool that produced it" packaging is preserved. A caller may pass a
    ``proof_core.profile.Profile`` or any object carrying the same attribute names. ``profile is None`` (the
    default on every entry point) selects the spine's own neutral ``evidence.*`` behaviour, unchanged, so a
    bundle verified without a profile is checked exactly as before this seam. A profile NEVER relaxes the
    canonicalization, the hashing or the Ed25519 math -- only which schema strings and pinned key apply."""
    if profile is None:
        return default
    return getattr(profile, name, default)


def pinned_key_is_demo() -> bool:
    """True while the verifier pins the public demo identity -- a passing verify then proves integrity
    (not edited), not origin. proof-core pins the demo key until it earns its own production trust root,
    so callers word a pass honestly as integrity-only."""
    return _PINNED_PUBKEY == _DEMO_PUBKEY


def pin_demo_key() -> None:
    """DEMO / TEST: pin THIS process's verifier to the well-known PUBLIC demo identity (the current
    default). After this `pinned_key_is_demo()` is True and every verdict path words a pass as
    INTEGRITY ONLY -- anyone can sign under the demo seed, so it never proves origin."""
    global _PINNED_PUBKEY
    _PINNED_PUBKEY = _DEMO_PUBKEY


def pin_production_key() -> None:
    """Legacy no-op kept for API compatibility: proof-core holds no production key of its own, so this pins
    the PUBLIC DEMO key (identical to `pin_demo_key()`) and does NOT pin a production key. A consumer that
    holds its own production trust root pins it with `pin_key(pubkey_hex)` below (process-wide) or supplies
    it per call via `Profile.pinned_pubkey`."""
    global _PINNED_PUBKEY
    _PINNED_PUBKEY = _DEMO_PUBKEY


def pin_key(pubkey_hex: str | None) -> None:
    """Pin THIS process's ORIGIN check to a CONSUMER's own production trust root.

    `pubkey_hex` is an Ed25519 public key as 64 lowercase hex (no ``ed25519:`` prefix), matching the shape a
    bundle's ``signature.public_key`` and a ``Profile.pinned_pubkey`` carry. ``pin_key(None)`` resets to the
    built-in PUBLIC demo identity (today's default; identical to ``pin_demo_key()``). This is the symmetric
    verify-side twin of the mint-side ``provenance.configure()``: a consumer that earns its OWN production key
    pins it here, in its own tree -- proof-core embeds no production key value. Composition is automatic:
    ``pinned_key_is_demo()``, ``pinned_key_fingerprint()`` and the origin/demo-ness logic all read
    ``_PINNED_PUBKEY``, so no verdict code changes."""
    global _PINNED_PUBKEY
    if pubkey_hex is None:
        _PINNED_PUBKEY = _DEMO_PUBKEY
        return
    if not (isinstance(pubkey_hex, str) and _PUBKEY_HEX_RE.fullmatch(pubkey_hex)):
        raise ValueError("pin_key expects 64 lowercase hex (an Ed25519 public key, no "
                         f"'ed25519:' prefix) or None; got {pubkey_hex!r}")
    _PINNED_PUBKEY = pubkey_hex


def pinned_key_fingerprint() -> str:
    """The verifier's pinned Ed25519 public key, as an ``ed25519:<64 hex>`` fingerprint. A reviewer
    cross-checks THIS against the published trust root before relying on an origin verdict -- so a
    swapped verifier that pinned a different key cannot pass off a forged 'origin'."""
    return "ed25519:" + _PINNED_PUBKEY


def key_label(pubkey_hex: str | None) -> str:
    """A human label for a signing key: names the public demo key; anything else is an unrecognised key,
    shown by fingerprint."""
    if pubkey_hex == _DEMO_PUBKEY:
        return f"the PUBLIC DEMO key (ed25519:{pubkey_hex[:16]}...)"
    if isinstance(pubkey_hex, str) and pubkey_hex:
        return f"an unrecognised key (ed25519:{pubkey_hex[:16]}...)"
    return "no readable key"


def _normalize_floats(obj: Any) -> Any:
    """Return `obj` with every float ``-0.0`` replaced by ``0.0`` (recursively). ``-0.0 == 0.0`` in
    IEEE-754 but ``json.dumps`` writes them as different bytes, so the producer normalizes ``-0.0`` to
    ``0.0`` at MINT (proof_core.envelope.normalize_floats); this independent verifier does the SAME inside
    its canon so the two canonical forms agree on negative zero. No shipped bundle contains ``-0.0`` (the
    conformance vectors are a no-op here), so no existing seal moves. NaN/Infinity are left to the strict
    ``allow_nan=False`` below / the up-front finite check."""
    if isinstance(obj, float):
        return 0.0 if obj == 0.0 else obj          # -0.0 == 0.0 -> the positive spelling; NaN != NaN untouched
    if isinstance(obj, dict):
        return {k: _normalize_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize_floats(v) for v in obj]
    return obj


def _canon(obj: Any) -> bytes:
    # independent re-implementation of the producer's canonicalization (on purpose). RFC 8259 strict:
    # NaN/Infinity are not JSON, so they are rejected up front by `_non_finite_paths` (a verdict, not
    # a crash) and would raise here otherwise. `-0.0` is normalized to `0.0` to match the producer.
    return json.dumps(_normalize_floats(obj), sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


# --- canon_version 2: strict RFC 8785 (JCS) + string-encoded big ints (ADR-053) ----------------------
# An independent re-implementation of the producer's v2 canonicalization, on purpose. v2 removes v1's three
# CPython deviations: strings are raw UTF-8 with JCS-minimal escaping (NOT ensure_ascii), numbers follow
# ECMAScript Number::toString (a whole float collapses: 2.0 -> "2"; 1e-7 -> "1e-7"), and object keys sort by
# UTF-16 code unit (NOT code point). Integers outside +-(2^53-1) are not representable as bare numbers under
# v2 (the mint refuses one; encode it as a JSON string) and `_v2_number` REFUSES one, so a v2 bundle sealing one is a
# canonicalization FAIL here and in the JS verifier. The ES number rule reuses Python's shortest-round-trip repr() for digit SELECTION, then
# reformats per ECMA-262 6.1.6.1.20 -- no dtoa reimplementation. See the ADR-053 canon spec + conformance.
_V2_SHORT_ESCAPE = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


def _v2_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c in _V2_SHORT_ESCAPE:
            out.append(_V2_SHORT_ESCAPE[c])
        elif c < 0x20 or 0xD800 <= c <= 0xDFFF:  # C0 controls AND lone surrogates -> \uXXXX (lowercase),
            out.append(f"\\u{c:04x}")            # exactly as ECMAScript JSON.stringify / RFC 8785 escapes them
        else:
            out.append(ch)                       # raw (all other non-ASCII, incl. valid astral scalars)
    out.append('"')
    return "".join(out)


#: The largest integer magnitude a canon-v2 (JCS / IEEE-754 double) number represents exactly.
_JS_SAFE_INT = 2 ** 53 - 1


def _v2_number(n: Any) -> str:
    if isinstance(n, int):                        # bool is handled by _v2_emit before reaching here
        # JCS numbers are IEEE-754 doubles: an integer outside +/-(2^53-1) has no exact v2 encoding (the producer
        # refuses to mint one -- encode it as a JSON string, ADR-053). A verifier must refuse it too, or a v2
        # bundle the producer could never mint would verify (and a v2 link could bind a float to a nearby big
        # int). Raising here makes every v2 section with one a canonicalization FAIL, in both verifiers.
        if abs(n) > _JS_SAFE_INT:
            raise ValueError(f"canon v2: integer {n} is outside +/-(2^53-1) and not representable; "
                             "encode it as a JSON string")
        return str(n)
    if not math.isfinite(n):
        raise ValueError("NaN/Infinity are not valid JSON")
    if n == 0:
        return "0"                                # -0.0 -> "0"
    neg = n < 0
    _, digs, exp = Decimal(repr(abs(n))).as_tuple()
    digs = list(digs)
    while len(digs) > 1 and digs[-1] == 0:        # strip trailing zeros; value = int(digs) * 10**exp
        digs.pop()
        exp += 1
    s = "".join(map(str, digs))
    k = len(s)
    m = k + exp                                   # ES: value = s * 10**(m-k); point goes after m digits
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


def _v2_emit(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _v2_string(obj)
    if isinstance(obj, (int, float)):
        return _v2_number(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_v2_emit(v) for v in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_v2_string(k) + ":" + _v2_emit(v) for k, v in items) + "}"
    raise TypeError(f"not a JSON value: {type(obj).__name__}")


def _canon_v2(obj: Any) -> bytes:
    # canon_version 2 = strict RFC 8785 (JCS) + string-encoded big ints. Output is UTF-8 (raw non-ASCII).
    return _v2_emit(obj).encode("utf-8")


def _try_canon(obj: Any, label: str, problems: list[str], canon_fn=_canon) -> bytes | None:
    """`_canon` that turns a serialization failure into a FAIL problem, never an uncaught traceback.

    `_canon` can raise on a hand-built object handed straight to the Python API (a value json cannot
    serialize -- a set, bytes, a custom object -- raises TypeError; a NaN/Infinity that slipped past the
    up-front finite check raises ValueError). A verifier a reviewer points at arbitrary objects must
    answer with a verdict, so a canon failure becomes a problem here and returns None (which never
    compares equal to real canonical bytes, so a failed canon reads as a mismatch -- closed)."""
    try:
        return canon_fn(obj)
    except (TypeError, ValueError, AttributeError, RecursionError) as exc:
        problems.append(f"{label}: value cannot be canonicalized ({type(exc).__name__}: {exc})")
        return None


# --- ADR-050: the version -> canon map (append-only, frozen) ------------------------------------------
#: The REFERENCE canon's output-definition version -> the canon function that produces it. APPEND-ONLY and
#: FROZEN: a future change to what the reference canon EMITS becomes `canon_version = 2` with a NEW `_canon_v2`
#: entry while `1: _canon` is preserved VERBATIM, so every v1 bundle verifies forever. A VERIFIER-port bug
#: (a port disagreeing with the reference for version N) is fixed IN PLACE with NO bump -- that verifier was
#: non-conformant; the format did not move. For v1 the map's canon IS this module's `_canon`.
_CANON = {1: _canon, 2: _canon_v2}
#: The highest `canon_version` this verifier can apply. A bundle sealed under anything higher is a
#: fail-FORWARD (`STATE_UNSUPPORTED_CANON`), never an integrity failure.
_CANON_SUPPORTED_MAX = max(_CANON)

#: The exact set of top-level keys the envelope allows. Anything else rides UNSIGNED (the seal commits
#: only to `sha256sums`), so a rendering UI must never show it. This membership test is canon-INDEPENDENT
#: (pure key-set), so the fail-FORWARD branch applies it too, even though it leaves the newer bundle's
#: sections to a newer verifier. ADR-049: `host` is RETIRED -- a stapled host block fails this allowlist.
_ALLOWED_TOP = frozenset({"schema", "result", "reproducibility", "manifest", "sha256sums",
                          "bundle_sha256", "signature", "redaction", "timestamp", "attestations"})


def _read_canon_version(sha256sums: Any) -> tuple[str | None, int | None, bool]:
    """Read the sealed `canon_version` from `sha256sums` (ADR-050). Returns
    `(problem_or_None, version_or_None, newer_than_supported)`:

    - `(None, N, False)` -- a KNOWN version (`1 <= N <= _CANON_SUPPORTED_MAX`): apply that canon.
    - `(None, N, True)`  -- NEWER than this verifier supports: the caller fails FORWARD.
    - `(problem, None, False)` -- MISSING, non-int, `< 1`, or a float/bool: a MALFORMED header. There is no
      implicit default -- a bundle without the field is not a "v0 bundle", it is not a bundle this format
      defines -- so the caller treats it as an integrity FAIL.

    Reading the version is a plain parse: the header canonicalizes identically under every canon version
    (the ADR-050 header invariant), so no canon is needed to read it, and there is no bootstrapping circularity.
    """
    if not isinstance(sha256sums, dict) or "canon_version" not in sha256sums:
        return (("sha256sums is missing the required integer canon_version (ADR-050): a bundle without it "
                 "is not a bundle this format defines"), None, False)
    v = sha256sums["canon_version"]
    # NB: bool is a subclass of int -- reject it explicitly (a JSON `true`/`false` is not a version).
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        return (f"canon_version must be an integer >= 1, got {v!r}", None, False)
    if v > _CANON_SUPPORTED_MAX:
        return (None, v, True)
    return (None, v, False)


def _non_finite_paths(obj: Any, path: str = "$") -> list[str]:
    """JSON paths of every NaN / +-Infinity float in `obj` -- values RFC 8259 has no encoding for.
    Python's json module writes and reads them as bare `NaN`/`Infinity` tokens, which strict and
    browser parsers reject, so a bundle carrying one would verify here and fail everywhere else."""
    if isinstance(obj, float):
        return [] if math.isfinite(obj) else [path]
    if isinstance(obj, dict):
        return [p for k, v in obj.items() for p in _non_finite_paths(v, f"{path}.{k}")]
    if isinstance(obj, (list, tuple)):
        return [p for i, v in enumerate(obj) for p in _non_finite_paths(v, f"{path}[{i}]")]
    return []


def _check_redaction(bundle: dict, problems: list[str], profile=None) -> set[str]:
    """Validate the (unsigned) redaction record; return the set of lawfully withheld sections. A malformed
    record withholds NOTHING (fail closed: a missing value then reads as an undeclared strip, which the
    section checks reject).

    ADR-049 (one strict dialect): the record is always the CLOSED, PROSE-FREE machine key set
    {schema, withheld, parent_bundle_sha256}. PRESENT means an object (a `null`/non-object is MALFORMED, not
    absent), the closed key set is REQUIRED, `parent_bundle_sha256` must be a well-formed sha256:<64 hex>
    digest, and `reason`/`caveats` are not allowed -- an unsigned sentence riding on a verifying bundle."""
    if "redaction" not in bundle:
        return set()
    red = bundle["redaction"]
    if not isinstance(red, dict):
        problems.append(f"redaction is not a JSON object (got {type(red).__name__})")
        return set()
    extra = sorted(set(red) - _REDACTION_KEYS_STRICT)
    if extra:
        problems.append(f"redaction has unexpected keys (unsigned): {extra}")
    missing = sorted(_REDACTION_KEYS_STRICT - set(red))
    if missing:
        problems.append(f"redaction is missing required keys: {missing}")
    redaction_schema = _profile_value(profile, "redaction_schema", _REDACTION_SCHEMA)
    if red.get("schema") != redaction_schema:
        problems.append(f"redaction schema is not {redaction_schema!r}: {red.get('schema')!r}")
    withheld = red.get("withheld")
    if not isinstance(withheld, list) or not withheld \
            or not all(isinstance(w, str) and w in _SECTIONS for w in withheld):
        problems.append(f"redaction.withheld must be a non-empty list of sections {list(_SECTIONS)}: {withheld!r}")
        withheld = []
    elif len(set(withheld)) != len(withheld):
        # the schema declares `withheld` uniqueItems; reject duplicates here too so a JSON-Schema validator
        # and this verifier never disagree on whether a redacted bundle is well-formed.
        problems.append(f"redaction.withheld has duplicate sections (must be unique): {sorted(withheld)}")
        withheld = []
    parent = red.get("parent_bundle_sha256")
    if "parent_bundle_sha256" in red and not (isinstance(parent, str) and _SHA256_RE.fullmatch(parent)):
        problems.append(f"redaction.parent_bundle_sha256 is not a well-formed sha256:<64 hex> digest: {parent!r}")
    return set(withheld)


def _check_host(bundle: dict, problems: list[str]) -> None:
    """`host` is a diagnostic triple of strings and nothing else -- it is unsigned, so any other key
    would be an unsigned claim riding on a verifying bundle."""
    host = bundle.get("host")
    if host is None:
        return
    if not isinstance(host, dict):
        problems.append(f"host is not a JSON object (got {type(host).__name__})")
        return
    extra = sorted(set(host) - _HOST_KEYS)
    if extra:
        problems.append(f"host has unexpected keys (unsigned): {extra}")
    bad = sorted(k for k in _HOST_KEYS if k in host and not isinstance(host[k], str))
    if bad:
        problems.append(f"host values must be strings: {bad}")
    # UNSIGNED diagnostic triple: bound each value so it cannot carry a stapled paragraph.
    long = sorted(k for k in _HOST_KEYS if isinstance(host.get(k), str) and len(host[k]) > _FREE_TEXT_MAX)
    if long:
        problems.append(f"host values exceed {_FREE_TEXT_MAX} chars (unsigned free text; rejected): {long}")


def _check_timestamp(bundle: dict, problems: list[str], profile=None) -> None:
    """`timestamp` (optional) is an embedded RFC 3161 token: a constrained object of strings, unsigned. It
    is self-authenticating and would be verified separately by a dedicated RFC 3161 tool (none ships here
    yet); this only holds it to a strict shape so it cannot carry an unsigned claim or a stapled blob on a
    bundle that still verifies.

    ADR-049 (one strict dialect): the timestamp is a bare RFC 3161 token held to the CLOSED+REQUIRED
    {format, token} key set -- a null/non-object is MALFORMED (not absent), and `token` is a strict-base64
    DER value (starts 'MI', correct padding, no trailing whitespace). There is no free-text `tsa` label."""
    if "timestamp" not in bundle:
        return
    # PRESENT means it must be an object: `"timestamp": null` is a MALFORMED record, not an absent one.
    ts = bundle["timestamp"]
    if not isinstance(ts, dict):
        problems.append(f"timestamp is not a JSON object (got {type(ts).__name__})")
        return
    extra = sorted(set(ts) - _TIMESTAMP_KEYS_STRICT)
    if extra:
        problems.append(f"timestamp has unexpected keys (unsigned): {extra}")
    missing = sorted(_TIMESTAMP_KEYS_STRICT - set(ts))
    if missing:
        problems.append(f"timestamp is missing required keys: {missing}")
    bad = sorted(k for k in _TIMESTAMP_KEYS_STRICT if k in ts and not isinstance(ts[k], str))
    if bad:
        problems.append(f"timestamp values must be strings: {bad}")
    if "format" in ts and ts.get("format") != "rfc3161":
        problems.append(f"timestamp.format must be 'rfc3161' (got {ts.get('format')!r})")
    tok = ts.get("token")
    if isinstance(tok, str):
        if len(tok) > _TIMESTAMP_TOKEN_MAX:
            problems.append(f"timestamp.token is too large ({len(tok)} > {_TIMESTAMP_TOKEN_MAX})")
        elif not _TIMESTAMP_TOKEN_RE.fullmatch(tok):
            problems.append("timestamp.token is not a strict-base64 DER token (must decode to an RFC 3161 "
                            "SEQUENCE: base64 starting 'MI', correct padding, no other characters)")


def _exceeds_depth(obj: Any, limit: int = _MAX_JSON_DEPTH) -> bool:
    """True if ``obj`` nests deeper than ``limit``. ITERATIVE (no recursion), so it can guard the recursive
    ``_non_finite_paths`` / ``_canon`` against a RecursionError on a hand-built deep structure handed to the
    Python API. The CLI (``proof_verify.__main__``) rejects deeply nested TEXT before it is ever parsed."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(cur, dict):
            stack.extend((v, depth + 1) for v in cur.values())
        elif isinstance(cur, (list, tuple)):
            stack.extend((v, depth + 1) for v in cur)
    return False


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """object_pairs_hook that rejects duplicate object keys. Python's json keeps the LAST of any
    duplicate silently, so a bundle with two ``score`` keys would let this verifier attest one value
    while another JSON parser (first-wins, or the in-browser check) shows a different one -- both
    "verifying". A "check us with any tool" verifier must reject the ambiguity outright."""
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r} in bundle JSON (ambiguous; rejected)")
        seen[key] = value
    return seen


def _reject_non_finite(token: str):
    raise ValueError(f"non-JSON token {token!r} in bundle (NaN/Infinity are not RFC 8259 JSON; rejected)")


def _text_depth_ok(text: str) -> bool:
    """True when the maximum bracket-nesting depth of ``text`` is within ``_MAX_JSON_DEPTH``. Scans
    string-aware (braces inside strings do not count). A fail-closed guard against input that would
    otherwise overflow the recursive JSON parser with a RecursionError instead of a verdict."""
    depth = max_depth = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
            max_depth = max(max_depth, depth)
            if max_depth > _MAX_JSON_DEPTH:
                return False
        elif ch in "}]":
            depth -= 1
    return True


def loads(text: str) -> dict:
    """The ONE guarded JSON loader every bundle reader shares. Rejects, at parse time: a bundle larger
    than ``_MAX_BUNDLE_BYTES`` (a pathological input that would exhaust memory), pathological bracket
    nesting (a RecursionError in the parser), duplicate object keys (last-wins ambiguity across parsers),
    and NaN/Infinity (not RFC 8259 JSON). Any reader that bypasses this -- a plain ``json.loads`` in
    conformance, the lineage index, reproduce/certify -- could attest or re-derive a bundle this
    authoritative verifier would refuse to even parse, so they all route through here."""
    nbytes = len(text) if len(text) > _MAX_BUNDLE_BYTES else len(text.encode("utf-8", "surrogatepass"))
    if nbytes > _MAX_BUNDLE_BYTES:
        raise ValueError(f"bundle text is {nbytes} UTF-8 bytes (> {_MAX_BUNDLE_BYTES} cap; rejected)")
    if not _text_depth_ok(text):
        raise ValueError(f"JSON nesting exceeds {_MAX_JSON_DEPTH} levels (rejected fail-closed)")
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_non_finite,
                      parse_int=_parse_bounded_int)


#: Integer literals longer than this many digits are refused, independent of PYTHONINTMAXSTRDIGITS (CPython's
#: default limit), so the verdict on a bundle never depends on the environment. The JS verifier matches.
_MAX_INT_DIGITS = 4300


def _parse_bounded_int(literal: str) -> int:
    digits = literal.lstrip("-")
    if len(digits) > _MAX_INT_DIGITS:
        raise ValueError(f"integer literal has more than {_MAX_INT_DIGITS} digits (rejected fail-closed)")
    # An interpreter configured with a LOWER int-string limit (PYTHONINTMAXSTRDIGITS) cannot print such an
    # integer later (every str/repr/json.dumps would raise), so refuse it HERE, while reading, with the limit
    # named: an unreadable verdict, never a traceback further on.
    env_limit = sys.get_int_max_str_digits()
    if env_limit and len(digits) > env_limit:
        raise ValueError(f"integer literal has {len(digits)} digits, beyond this Python's PYTHONINTMAXSTRDIGITS "
                         f"limit ({env_limit}); the reference reads up to {_MAX_INT_DIGITS} digits at the default "
                         "limit -- re-run without lowering it")
    return int(literal)


def _sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


# --- independent RFC 8032 Ed25519 verify (its own field arithmetic; no shared code) ---
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493   # the prime-order subgroup order (RFC 8032)
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_ISQRT = pow(2, (_Q - 1) // 4, _Q)


def _recover_x(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _ISQRT) % _Q
    # RFC 8032 5.1.3 step 4: if the recovered x is 0 and the encoded sign bit is 1, the encoding is
    # non-canonical and decoding MUST fail -- there is no distinct "negative zero" point. Without this a
    # crafted key/R with x==0 and the sign bit set would be silently normalised and accepted.
    if x == 0 and sign == 1:
        raise ValueError("non-canonical encoding: x == 0 with sign bit set (RFC 8032 5.1.3)")
    if x % 2 != sign:
        x = _Q - x
    return x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_BASE = (_recover_x(_BY, 0), _BY)


def _add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    t = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _Q - 2, _Q) % _Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _Q - 2, _Q) % _Q
    return (x3, y3)


def _mul(p: tuple[int, int], e: int) -> tuple[int, int]:
    result = (0, 1)
    while e > 0:
        if e & 1:
            result = _add(result, p)
        p = _add(p, p)
        e >>= 1
    return result


def _on_curve(p: tuple[int, int]) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


#: The 8 canonical low-order Ed25519 point encodings (the 8-torsion subgroup, which includes the
#: identity `0100...00`). A public key or signature R that decodes to one of these is a low-order point
#: whose order divides 8 -- standard Ed25519 would accept it, but it carries no origin and enables known
#: small-subgroup games, so this independent verifier rejects it on decode (defense in depth). NOT
#: hardcoded from memory: each was computed as [L]P over random on-curve points P and VERIFIED to satisfy
#: [8]P == identity. Kept byte-for-byte in lock-step with proof_core.signing._LOW_ORDER_ENCODINGS; the KAT
#: and OpenSSL cross-validation vectors use full-order keys, so they are unaffected.
_LOW_ORDER_ENCODINGS = frozenset({
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
})


def _decodepoint(b: bytes) -> tuple[int, int]:
    if bytes(b) in _LOW_ORDER_ENCODINGS:          # reject a low-order / identity point (order | 8)
        raise ValueError("low-order point encoding (order divides 8; rejected)")
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _Q:                                   # reject a non-canonical (y >= p) point encoding
        raise ValueError("non-canonical point encoding")
    x = _recover_x(y, (b[31] >> 7) & 1)
    p = (x, y)
    if not _on_curve(p):
        raise ValueError("point not on curve")
    return p


def _ed25519_verify(signature: bytes, msg: bytes, pubkey: bytes) -> bool:
    if len(signature) != 64 or len(pubkey) != 32:
        return False
    try:
        r_point = _decodepoint(signature[:32])
        a_point = _decodepoint(pubkey)
    except (ValueError, IndexError):
        return False
    # Reject a small-order public key OR R ([8]P == identity <=> P has order dividing 8). Under the
    # cofactorless equation a small-order A (e.g. the identity point) accepts a "signature" that needs no
    # private key, and a small-order R launders torsion the equation would otherwise catch. Redundant with
    # the `_LOW_ORDER_ENCODINGS` table above (same order-|8 set, caught on decode), so it rejects NOTHING the
    # table did not already reject -- a prime-order key is unaffected -- but it makes this implementation
    # mechanically identical to the producer's copy. Kept in lock-step with proof_core.signing.
    if _mul(a_point, 8) == (0, 1) or _mul(r_point, 8) == (0, 1):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:                                   # reject a non-canonical / malleable scalar (RFC 8032)
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + pubkey + msg).digest(), "little")
    return _mul(_BASE, s) == _add(r_point, _mul(a_point, k))


def _check_signature(bundle: dict, bundle_sha256: str, problems: list[str],
                     origin_problems: list[str], profile=None, sig_out: dict | None = None) -> str | None:
    """The signature check, split on the two distinct things a signature proves.

    INTEGRITY (-> `problems`): the block is well-formed and the Ed25519 signature is VALID over the
    recomputed seal under the public key the bundle itself carries. That binds the sealed digest-list
    -- and through it every section -- to what the signer signed: an edited, re-keyed or forged
    signature fails here, whoever the claimed signer is. This is checked under the EMBEDDED key on
    purpose: a signature that is invalid under its own key is a broken record, never merely "not ours".

    ORIGIN (-> `origin_problems`): that embedded key IS the pinned key. A valid signature under any
    other key (the public demo key a dev machine signs with, a third party's key) proves the record is
    untampered but says nothing about WHO produced it. Origin is decided by the pin alone -- never by a
    label the bundle carries.

    Returns the embedded public key (hex) when the block is readable, else None.
    """
    sig = bundle.get("signature")
    if not isinstance(sig, dict):
        problems.append("bundle is not signed")
        return None
    # S1: the block carries EXACTLY {alg, public_key, signature, message}. The Ed25519 signature covers
    # only `bundle_sha256`, so every other key in this block rides UNSIGNED -- a stapled "attestation" or
    # a self-asserted "identity" label would survive the signature check untouched. Fail closed.
    extra = sorted(set(sig) - _SIGNATURE_KEYS)
    if extra:
        problems.append(f"unsigned key in signature block: {extra}")
    missing = [k for k in _SIGNATURE_REQUIRED if k not in sig]
    if missing:
        problems.append(f"signature block is missing required keys: {missing}")
    # S2: `message` names what was signed and MUST be the literal `bundle_sha256` -- a different label
    # (or none) is a block that does not describe the seal it claims to cover.
    if sig.get("message") != _SIGNATURE_MESSAGE:
        problems.append(f"signature.message must be {_SIGNATURE_MESSAGE!r} (got {sig.get('message')!r})")
    alg = sig.get("alg")
    if not (isinstance(alg, str) and alg in _ALG_SUPPORTED):
        signer_v, sig_hex_v = sig.get("public_key"), sig.get("signature")
        # mirror the JS `blockShapeOk` gate: grant the soft fail-forward ONLY when the block is OTHERWISE
        # well-formed (hex fields valid; S1/S2 above already recorded any extra/missing key or bad message).
        # A garbage/forged/truncated hex field alongside a plausible future-suite label is a plain FAIL, not a
        # benign "use a newer verifier" -- the one-contract gate is "the unknown suite is the SOLE problem".
        signer_ok = isinstance(signer_v, str) and _PUBKEY_HEX_RE.fullmatch(signer_v) is not None
        sighex_ok = isinstance(sig_hex_v, str) and _SIGNATURE_HEX_RE.fullmatch(sig_hex_v) is not None
        if isinstance(alg, str) and _ALG_TOKEN_RE.fullmatch(alg) and signer_ok and sighex_ok:
            if sig_out is not None:
                sig_out["unsupported_alg"] = True
            problems.append(
                f"{STATE_UNSUPPORTED_ALG}: signed with signature suite {alg!r}; this verifier can check "
                f"{sorted(_ALG_SUPPORTED)} and so CANNOT check this signature -- use a newer verifier "
                "(integrity and origin UNDETERMINED; this verdict can be produced from any content and "
                "attests nothing about the sections)")
        else:
            problems.append(f"unsupported signature alg: {alg!r}")
            if not signer_ok:
                problems.append("signature public_key is not a 32-byte hex Ed25519 key (64 lowercase hex characters)")
            if not sighex_ok:
                problems.append("signature.signature is not a 64-byte Ed25519 signature (128 lowercase hex "
                                "characters, no whitespace)")
        return None
    signer = sig.get("public_key")
    # ADR-049 (one strict dialect): hold both hex fields to EXACTLY lowercase hex (the schema pattern)
    # BEFORE `bytes.fromhex`, which is case-insensitive and skips ASCII whitespace -- so an upper-cased or
    # space-separated key/signature is rejected with a pointed message instead of silently verifying
    # (== a strict JSON-Schema / browser check). A producer writes lowercase, unbroken hex.
    if not (isinstance(signer, str) and _PUBKEY_HEX_RE.fullmatch(signer)):
        problems.append("signature public_key is not a 32-byte hex Ed25519 key (64 lowercase hex characters)")
        return None
    pk = bytes.fromhex(signer)
    sig_hex = sig.get("signature")
    if not (isinstance(sig_hex, str) and _SIGNATURE_HEX_RE.fullmatch(sig_hex)):
        problems.append("signature.signature is not a 64-byte Ed25519 signature (128 lowercase hex "
                        "characters, no whitespace)")
        ok = False
    else:
        try:
            ok = _ed25519_verify(bytes.fromhex(sig_hex), bundle_sha256.encode(), pk)
        except (ValueError, TypeError):
            ok = False
    if not ok:
        problems.append("Ed25519 signature does not verify under the bundle's own embedded public key")
    # ORIGIN pin: a dialect may pin its OWN trust root (profile.pinned_pubkey, 64 hex). None keeps the
    # verifier's module-global pin unchanged -- the neutral default -- so the deliberate single-pin design
    # is intact unless a caller opts a profile in. This never affects INTEGRITY (checked above under the
    # embedded key); it only decides which key counts as "origin".
    pinned = _profile_value(profile, "pinned_pubkey", None) or _PINNED_PUBKEY
    if signer != pinned:
        origin_problems.append("signature is not under the pinned public key")
    return signer


_ATTESTATION_SCHEMA = "evidence.attestation.v1"
#: the label an approver's `message` field MUST carry; like the producer signature's S2 `message`, it names
#: what was signed and is itself BOUND INTO the signed bytes, so neither it nor the schema can be swapped.
_ATTESTATION_MESSAGE = "attests:v1"
_ATT_KEYS = {"schema", "role", "name", "public_key", "timestamp", "message", "signature"}
#: Exact problem text for a present-but-null `attestations`. The verdict exposes `attestations_null` as a
#: structured flag so a caller never infers it from problem text (which echoes attacker-chosen names).
_ATTESTATIONS_NULL_PROBLEM = "attestations is present but null; omit the key instead"


def _check_attestations(bundle: dict, bundle_sha256: str, problems: list[str], out: list) -> None:
    """Validate human sign-offs (countersignatures) riding alongside the decision seal, INDEPENDENTLY of it.

    Each attestation is an Ed25519 signature over the sealed bundle digest bound to the attestation SCHEMA and
    message label AND the approver's role, name and timestamp (so none of those can be swapped without breaking
    it -- a sign-off cannot be lifted onto a different schema, relabelled, or re-attributed). This is a SEPARATE
    dimension from the decision's integrity/origin: a bad sign-off is reported here, it does not make the
    decision read as tampered (the seal already answers that). Appends a {role, name, timestamp, signer, valid}
    entry per attestation.

    Whether a signing key actually belongs to the named person is an identity question (a pinned approver
    registry / hardware-key attestation / SSO binding), not decided here -- the same honest boundary as origin.
    """
    atts = bundle.get("attestations")
    if atts is None:
        if "attestations" in bundle:
            problems.append(_ATTESTATIONS_NULL_PROBLEM)
        return
    if not isinstance(atts, list):
        problems.append(f"attestations is not a list (got {type(atts).__name__})")
        return
    if len(atts) > _MAX_SLOT_LIST:
        # cap the sign-off list like every other list slot (derived_from / caveats / captured), so a
        # bundle cannot staple an unbounded run of countersignatures. Fail closed on the whole list.
        problems.append(f"attestations has more than {_MAX_SLOT_LIST} entries")
        return
    for i, a in enumerate(atts):
        if not isinstance(a, dict):
            problems.append(f"attestation[{i}] is not a JSON object")
            continue
        extra = sorted(set(a) - _ATT_KEYS)
        if extra:
            problems.append(f"attestation[{i}] has unexpected keys: {extra}")
        schema, label = a.get("schema"), a.get("message")
        if schema != _ATTESTATION_SCHEMA:
            problems.append(f"attestation[{i}] has wrong schema: {schema!r}")
        if label != _ATTESTATION_MESSAGE:
            problems.append(f"attestation[{i}] message must be {_ATTESTATION_MESSAGE!r} (got {label!r})")
        role, name, ts, pkhex = a.get("role"), a.get("name"), a.get("timestamp"), a.get("public_key")
        # role/name/timestamp are REQUIRED strings (the published schema marks them so, and `make_attestation`
        # always emits them as strings). Hold them to that here -- present, string-typed, and capped at the
        # same free-text bound as every other unsigned field -- so a keyless, non-string, or oversize sign-off
        # (`attestations` rides OUTSIDE the seal) cannot be stapled on and rendered. Reported, not gating.
        for _fld, _val in (("role", role), ("name", name), ("timestamp", ts)):
            if not isinstance(_val, str):
                problems.append(f"attestation[{i}] {_fld} must be a string")
            elif len(_val) > _FREE_TEXT_MAX:
                problems.append(f"attestation[{i}] {_fld} exceeds {_FREE_TEXT_MAX} characters")
        # strict lowercase hex BEFORE bytes.fromhex (which is case-insensitive and skips whitespace), matching
        # the schema's LeanAttestation patterns and the JS verifier.
        pk = bytes.fromhex(pkhex) if isinstance(pkhex, str) and _PUBKEY_HEX_RE.fullmatch(pkhex) else b""
        valid = False
        if len(pk) != 32:
            problems.append(f"attestation[{i}] public_key is not a 32-byte hex key")
        else:
            # the signed bytes bind the schema and message label alongside who/what/when, so tampering any
            # of them breaks the signature (not only the structural checks above).
            msg = _canon({"attests": bundle_sha256, "schema": schema, "message": label,
                          "role": role, "name": name, "timestamp": ts})
            sig_hex = a.get("signature")
            try:
                valid = (isinstance(sig_hex, str) and _SIGNATURE_HEX_RE.fullmatch(sig_hex) is not None
                         and _ed25519_verify(bytes.fromhex(sig_hex), msg, pk))
            except (ValueError, TypeError):
                valid = False
            if not valid:
                problems.append(f"attestation[{i}] sign-off by {name!r} ({role!r}) does not verify")
        out.append({"role": role, "name": name, "timestamp": ts,
                    "signer": ("ed25519:" + pkhex) if (isinstance(pkhex, str) and len(pk) == 32) else None,
                    "valid": valid})


# --- frontier assertion slots (optional, sealed in provenance.value) --------------------------------
# Three OPTIONAL producer assertions a bundle may seal into provenance to carry a frontier claim in a
# correctness-NEUTRAL way: `applicability` (a domain adapter's in-distribution verdict), `completeness`
# (an honest declaration of what the record captured), and `derived_from` (a transitive-chain link binding
# this record to the exact seal of a prior one). The spine CARRIES and shape-checks them; it never
# evaluates the claim -- whether a model is in-distribution is the adapter's evidence, never the verifier's.
# This is "defensible, not correct" applied to the frontier: the seal proves the producer asserted X and
# nobody edited it, not that X is true. An absent slot is the honest default; a malformed slot FAILs like a
# malformed digest (it is sealed, so a shape a conformant reader cannot trust is rejected outright).
_APPLICABILITY_KEYS = {"assessed", "in_distribution", "method", "caveats"}
_COMPLETENESS_KEYS = {"complete", "captured", "note"}
_DERIVED_FROM_KEYS = {"bundle_sha256", "sha256sums", "consumed", "role"}
_DERIVED_VERIFIED = (None, "integrity", "integrity+origin")
_MAX_SLOT_LIST = 256          # cap list-valued slots (caveats / captured / derived_from) by count, not just bytes

# --- BINDING `derived_from` shape (domain-neutral; the ONE chain shape, ADR-049) ------------------------
# These are the offline per-link rule for every sealed `derived_from`, and name NOTHING about any domain --
# digests, identifiers and RFC 6901 pointers only. ADR-049 made binding the kernel's only chain shape, so
# they run for every dialect that seals a `derived_from` (there is no lenient decoration mode to toggle).
# A BINDING link is a CLOSED record of FACTS:
# the upstream's seal + the digest-triple it is the seal of, WHAT was consumed (which of this bundle's own
# sealed inputs, WHERE in the upstream's result core, and the digest of that value), and a `role` label --
# never a verdict about the upstream (origin is the walking verifier's call, never a sealed field).
_DERIVED_FROM_CONSUMED_KEYS = {"input", "path", "sha256"}
#: Named explicitly so a rejection SAYS why: a verdict LABEL inside a sealed link is the false-attestation
#: class moved inside the seal. An unexpected key is rejected regardless; these get the pointed message.
_DERIVED_FROM_VERDICT_KEYS = {"verified", "integrity", "origin", "state", "verdict", "certified",
                              "integrity_ok", "origin_ok", "chain"}
#: ...and never a verdict smuggled into the identifier token itself (`role: "origin-VERIFIED"` passes the
#: identifier shape yet reads, sealed, as an attestation nobody made). A label CONTAINING any of these
#: (case-insensitive) is rejected; the walking verifier is the only party that says `verified`.
_DERIVED_FROM_VERDICT_TOKENS = ("verified", "accepted", "approved", "certified", "origin", "valid", "pass",
                                "trusted")
#: `role` and `consumed.input` are IDENTIFIERS (an input key, a role slug), never prose: one bounded token.
_DERIVED_FROM_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}")
#: `consumed.path` is an RFC 6901 JSON pointer that MUST address the upstream result MAP: it starts
#: `/result/<capability>` and may descend further. The whole-capability output is `/result/<capability>`,
#: NOT the empty pointer -- the chain walker resolves capability-scoped paths only, so an `""`/`/result`/
#: non-`/result` pointer would mint and single-verify yet never WALK to `verified`. Requiring the walkable
#: shape here keeps "offline-valid" == "walkable" and stops a second conformant walker from disagreeing.
_CONSUMED_PATH_RE = re.compile(r"/result/(?:[^/~]|~[01])+(?:/(?:[^/~]|~[01])*)*")
_MAX_JSON_POINTER_LEN = 1024
_MAX_DERIVED_FROM_LINKS = 64


def _verdict_token_in(label: str) -> str | None:
    # match a verdict token as a WHOLE word (segments split on any non-alphanumeric: the identifier
    # separators `_ . : / -`), not as a bare substring -- so a legitimate identifier like `validator`,
    # `compass`, `passthrough`, or `cross-validation` is not rejected for merely containing `valid`/`pass`,
    # while `origin-verified` (segment `verified`) still is.
    words = set(re.split(r"[^a-z0-9]+", label.lower()))
    return next((tok for tok in _DERIVED_FROM_VERDICT_TOKENS if tok in words), None)


def _is_digest(v: Any) -> bool:
    return isinstance(v, str) and _SHA256_RE.fullmatch(v) is not None


def _derived_from_binding_problems(link: Any, own_seal: str | None, allowed_keys) -> list[str]:
    """Every way ONE `derived_from` link fails the closed BINDING shape (empty list = well-formed). This is
    the shared offline per-link rule, so a standalone port rejects exactly what the full chain verifier does
    (verdict parity).
    OFFLINE only (no upstream needed): the closed key set (a verdict label named as such is rejected), every
    digest a well-formed `sha256:<64 hex>`, `sha256sums` exactly the three sections plus `canon_version`,
    `bundle_sha256 == sha(canon(sha256sums))` (the link is self-consistent, held to the same equality the
    seal itself is), the closed `consumed` triple (an identifier-shaped input key, a bounded RFC 6901 pointer
    into `/result/<capability>`, a digest), an identifier-shaped `role`, and no link to this bundle's OWN
    seal (`own_seal`)."""
    if not isinstance(link, dict):
        return [f"is not a JSON object (got {type(link).__name__})"]
    problems: list[str] = []
    extra = set(link) - allowed_keys
    verdicts = sorted(extra & _DERIVED_FROM_VERDICT_KEYS)
    if verdicts:
        problems.append(f"carries a verdict field {verdicts}: a sealed link records FACTS only -- origin/integrity "
                        "of the upstream are the walking verifier's call, never a sealed field")
    other = sorted(extra - _DERIVED_FROM_VERDICT_KEYS)
    if other:
        problems.append(f"has unexpected keys: {other}")
    missing = sorted(allowed_keys - set(link))
    if missing:
        problems.append(f"is missing required keys: {missing}")
    target = link.get("bundle_sha256")
    if "bundle_sha256" in link and not _is_digest(target):
        problems.append(f"bundle_sha256 is not a well-formed sha256:<64 hex> digest: {target!r}")
    sums = link.get("sha256sums")
    sums_ok = False
    if "sha256sums" in link:
        if not isinstance(sums, dict):
            problems.append(f"sha256sums is not a JSON object (got {type(sums).__name__})")
        elif set(sums) != _SHA256SUMS_KEYS:
            # ADR-050: a link carries the upstream's WHOLE sha256sums -- the three digests PLUS canon_version.
            problems.append(f"sha256sums has unexpected/missing sections: {sorted(set(sums) ^ _SHA256SUMS_KEYS)}")
        elif not all(_is_digest(sums[s]) for s in _SECTIONS):
            problems.append("sha256sums values must each be a well-formed sha256:<64 hex> digest")
        elif isinstance(sums["canon_version"], bool) or not isinstance(sums["canon_version"], int) \
                or sums["canon_version"] < 1:
            problems.append(f"sha256sums.canon_version must be an integer >= 1, got {sums['canon_version']!r}")
        else:
            sums_ok = True
    if sums_ok and _is_digest(target):
        recomputed = _sha(_canon(sums))
        if recomputed != target:
            problems.append(f"bundle_sha256 {target} != sha(canon(sha256sums)) {recomputed} (the link is not "
                            "self-consistent: it does not name the seal of the triple it carries)")
    if own_seal is not None and target == own_seal:
        problems.append("links to this bundle's own seal (a self-reference)")
    consumed = link.get("consumed")
    if "consumed" in link:
        if not isinstance(consumed, dict):
            problems.append(f"consumed is not a JSON object (got {type(consumed).__name__})")
        else:
            c_extra = sorted(set(consumed) - _DERIVED_FROM_CONSUMED_KEYS)
            if c_extra:
                problems.append(f"consumed has unexpected keys: {c_extra}")
            c_missing = sorted(_DERIVED_FROM_CONSUMED_KEYS - set(consumed))
            if c_missing:
                problems.append(f"consumed is missing required keys: {c_missing}")
            inp = consumed.get("input")
            if "input" in consumed and not (isinstance(inp, str) and _DERIVED_FROM_LABEL_RE.fullmatch(inp)):
                problems.append(f"consumed.input must be a bounded identifier (an input key): {inp!r}")
            elif "input" in consumed and _verdict_token_in(inp):
                problems.append(f"consumed.input {inp!r} carries a verdict token ({_verdict_token_in(inp)!r}): a sealed "
                                "link records FACTS only -- origin/integrity of the upstream are the walking "
                                "verifier's call, never a sealed label")
            path = consumed.get("path")
            if "path" in consumed and not (isinstance(path, str) and len(path) <= _MAX_JSON_POINTER_LEN
                                           and _CONSUMED_PATH_RE.fullmatch(path)):
                problems.append("consumed.path must be a bounded RFC 6901 pointer into the upstream result map "
                                "(/result/<capability>/...); the empty pointer and non-/result pointers are not walkable")
            if "sha256" in consumed and not _is_digest(consumed.get("sha256")):
                problems.append(f"consumed.sha256 is not a well-formed sha256:<64 hex> digest: {consumed.get('sha256')!r}")
    role = link.get("role")
    if "role" in link and not (isinstance(role, str) and _DERIVED_FROM_LABEL_RE.fullmatch(role)):
        problems.append(f"role must be a bounded identifier, not prose: {role!r}")
    elif "role" in link and _verdict_token_in(role):
        problems.append(f"role {role!r} carries a verdict token ({_verdict_token_in(role)!r}): a sealed link records "
                        "FACTS only -- origin/integrity of the upstream are the walking verifier's call, never a "
                        "sealed label")
    return problems


def derived_from_problems(links: Any, allowed_keys, own_seal: str | None = None) -> list[str]:
    """Every problem with a sealed BINDING `derived_from` value, each prefixed `derived_from` (the list-level
    rule of the Stage-2 port UP). A non-list, an EMPTY list (a chain claim with no links would walk to a
    vacuous pass -- omit the key instead) and an over-long list are rejected whole; otherwise every link is
    held to `_derived_from_binding_problems`. SHARED by the spine verifier
    and a dialect's mint-time belt, so a producer can never seal a link the verifier rejects. `allowed_keys`
    is the dialect's closed binding key set (`profile.derived_from_keys`); `own_seal` (None at mint) adds the
    self-reference check at verify."""
    if not isinstance(links, list):
        return [f"derived_from is not a JSON list (got {type(links).__name__})"]
    if not links:
        return ["derived_from is an empty list (a chain claim with no links); omit the key instead"]
    if len(links) > _MAX_DERIVED_FROM_LINKS:
        return [f"derived_from has too many links ({len(links)} > {_MAX_DERIVED_FROM_LINKS})"]
    return [f"derived_from[{i}] {p}" for i, link in enumerate(links)
            for p in _derived_from_binding_problems(link, own_seal, allowed_keys)]


def _is_bool_or_null(value) -> bool:
    # NB: `value in (True, False, None)` is WRONG -- `1 == True` and `0 == False` in Python, so an int would
    # slip through. A JSON boolean is a real bool; identity/isinstance is the only sound test.
    return value is None or isinstance(value, bool)


#: The schema's LeanReproducibility `required` fields and their types. A signed bundle must say who produced
#: it, with what code and data, and how to re-run it; an empty or partial provenance asserts none of that.
_PROV_REQUIRED_STR = ("engine_version", "code_version", "deterministic", "reproduce")
_PROV_REQUIRED_NONEMPTY = ("produced_by",)
#: Required, but their VALUE format is the S6 data-library rule's job (below); here only their presence.
_PROV_REQUIRED_PRESENT = ("data_library", "data_library_sha256")


def _is_json_integer(v) -> bool:
    # JSON Schema `integer` (a whole number, written 1 or 1.0); never a bool. A whole float is accepted so the
    # verdict cannot depend on spelling under canon v2, where 1 and 1.0 seal identically.
    if isinstance(v, bool):
        return False
    return isinstance(v, int) or (isinstance(v, float) and v.is_integer())


def _check_required_provenance(prov_val: dict, problems: list[str]) -> None:
    for k in _PROV_REQUIRED_STR:
        if not isinstance(prov_val.get(k), str):
            problems.append(f"provenance.{k} is required and must be a string")
    for k in _PROV_REQUIRED_NONEMPTY:
        v = prov_val.get(k)
        if not (isinstance(v, str) and v):
            problems.append(f"provenance.{k} is required and must be a non-empty string")
    for k in _PROV_REQUIRED_PRESENT:
        if k not in prov_val:
            problems.append(f"provenance.{k} is required")
    if not _is_json_integer(prov_val.get("rng_seed")):
        problems.append("provenance.rng_seed is required and must be an integer")


def _check_optional_provenance(prov_val: dict, problems: list[str]) -> None:
    """The schema's typed OPTIONAL provenance fields, held to their types when present. `attestation_scope` is the
    signed claim boundary (what the seal does and does not attest): a non-object there is not a boundary."""
    if "engine" in prov_val and not isinstance(prov_val["engine"], str):
        problems.append("provenance.engine must be a string")
    for k in ("toolchain", "data"):
        if k in prov_val and not isinstance(prov_val[k], dict):
            problems.append(f"provenance.{k} must be a JSON object")
    if "attestation_scope" in prov_val:
        sc = prov_val["attestation_scope"]
        if not isinstance(sc, dict) or not all(isinstance(v, str) for v in sc.values()):
            problems.append("provenance.attestation_scope must be a JSON object of strings")
    if "lineage" in prov_val:
        ln = prov_val["lineage"]
        if not (isinstance(ln, dict) and _is_json_integer(ln.get("count")) and isinstance(ln.get("steps"), list)):
            problems.append("provenance.lineage must be an object with an integer count and a steps list")


def _no_null_leaf(obj: dict, key: str, label: str, problems: list[str]) -> None:
    # an optional field present but null is malformed (the schema types it string/list); omit it instead.
    if key in obj and obj[key] is None:
        problems.append(f"{label} is present but null; omit the key instead")


def _cap_text(value, label: str, problems: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        problems.append(f"{label} must be a string (got {type(value).__name__})")
    elif len(value) > _FREE_TEXT_MAX:
        problems.append(f"{label} exceeds {_FREE_TEXT_MAX} characters")


def _cap_str_list(value, label: str, problems: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        problems.append(f"{label} must be a list (got {type(value).__name__})")
        return
    if len(value) > _MAX_SLOT_LIST:
        problems.append(f"{label} has more than {_MAX_SLOT_LIST} entries")
        return                                  # already rejected; don't emit a per-item problem for each
    for j, item in enumerate(value):
        # a list ITEM must be a string -- flag a non-str (incl. null) directly, NOT via _cap_text (whose
        # None early-return is for OPTIONAL scalar fields and would let a null list item slip through).
        if not isinstance(item, str):
            problems.append(f"{label}[{j}] must be a string (got {type(item).__name__})")
        elif len(item) > _FREE_TEXT_MAX:
            problems.append(f"{label}[{j}] exceeds {_FREE_TEXT_MAX} characters")


def _check_frontier_slots(prov_val: dict, problems: list[str], profile=None, own_seal=None) -> None:
    """SHAPE-ONLY checks for the optional frontier slots sealed in provenance.value. Never evaluates a
    claim (that would be asserting correctness); only rejects a malformed sealed assertion.

    ADR-049: a `derived_from` is always BINDING (the one chain shape). Every link is held to the full
    binding shape (`_derived_from_binding_problems`: the consumed triple, self-consistency, self-reference,
    verdict-token rejection) plus the list-level empty / over-length rejects. The allowed KEY SET is the
    dialect's `derived_from_keys` (data; the neutral default is the binding set). `own_seal` is this bundle's
    recomputed seal, used for the binding self-reference check."""
    derived_from_keys = _profile_value(profile, "derived_from_keys", _DERIVED_FROM_KEYS)
    app = prov_val.get("applicability")
    if app is None and "applicability" in prov_val:
        problems.append("provenance.applicability is present but null; omit the key to not assert it")
    elif app is not None:
        if not isinstance(app, dict):
            problems.append(f"provenance.applicability must be a JSON object (got {type(app).__name__})")
        else:
            extra = sorted(set(app) - _APPLICABILITY_KEYS)
            if extra:
                problems.append(f"provenance.applicability has unexpected keys: {extra}")
            if not isinstance(app.get("assessed"), bool):
                problems.append("provenance.applicability.assessed must be a boolean")
            if not _is_bool_or_null(app.get("in_distribution")):
                problems.append("provenance.applicability.in_distribution must be true, false, or null")
            _no_null_leaf(app, "method", "provenance.applicability.method", problems)
            _no_null_leaf(app, "caveats", "provenance.applicability.caveats", problems)
            _cap_text(app.get("method"), "provenance.applicability.method", problems)
            _cap_str_list(app.get("caveats"), "provenance.applicability.caveats", problems)
    comp = prov_val.get("completeness")
    if comp is None and "completeness" in prov_val:
        problems.append("provenance.completeness is present but null; omit the key to not assert it")
    elif comp is not None:
        if not isinstance(comp, dict):
            problems.append(f"provenance.completeness must be a JSON object (got {type(comp).__name__})")
        else:
            extra = sorted(set(comp) - _COMPLETENESS_KEYS)
            if extra:
                problems.append(f"provenance.completeness has unexpected keys: {extra}")
            if not _is_bool_or_null(comp.get("complete")):
                problems.append("provenance.completeness.complete must be true, false, or null")
            _no_null_leaf(comp, "captured", "provenance.completeness.captured", problems)
            _no_null_leaf(comp, "note", "provenance.completeness.note", problems)
            _cap_str_list(comp.get("captured"), "provenance.completeness.captured", problems)
            _cap_text(comp.get("note"), "provenance.completeness.note", problems)
    dfrom = prov_val.get("derived_from")
    if dfrom is None and "derived_from" in prov_val:
        problems.append("provenance.derived_from is present but null; omit the key to not assert a chain")
    elif dfrom is not None:
        if not isinstance(dfrom, list):
            problems.append(f"provenance.derived_from must be a list (got {type(dfrom).__name__})")
        else:
            # ADR-049 (one strict dialect): a `derived_from` is always BINDING. Reject a VACUOUS chain claim
            # (an empty list that would walk to a silent pass) and the link-count cap, then hold every link
            # to the full closed binding shape (consumed triple, self-consistency, self-reference,
            # verdict-token rejection) -- there is no decoration mode.
            if not dfrom:
                problems.append("provenance.derived_from is an empty list (a chain claim with no links); "
                                "omit the key instead")
            if len(dfrom) > _MAX_DERIVED_FROM_LINKS:
                problems.append(f"provenance.derived_from has more than {_MAX_DERIVED_FROM_LINKS} entries")
                return                          # already rejected; skip the per-link checks
            for i, link in enumerate(dfrom):
                for p in _derived_from_binding_problems(link, own_seal, derived_from_keys):
                    problems.append(f"provenance.derived_from[{i}] {p}")


def _frontier_report(bundle: dict) -> dict:
    """The frontier slots as sealed in provenance.value -- producer assertions the spine carries, never
    evaluates. Read from the hashed provenance so the report reflects the sealed content."""
    pv = {}
    try:
        maybe = bundle["manifest"]["provenance"]["value"]
        if isinstance(maybe, dict):
            pv = maybe
    except (KeyError, TypeError):
        pv = {}
    return {"applicability": pv.get("applicability"),
            "completeness": pv.get("completeness"),
            "derived_from": pv.get("derived_from") or []}


def classify_bundle(bundle: dict, *, profile=None) -> dict:
    """The THREE-state verdict. Recompute every hash, check the embedded result.v1 core, validate the
    signature under the bundle's own key (integrity) and check that key against the pin (origin).

    `profile` (optional, duck-typed, additive) selects an on-disk DIALECT: its `envelope_schema`,
    `result_required_fields`, `redaction_schema` shape strings and the `pinned_pubkey` origin root. None
    (the default) verifies the spine's own neutral `evidence.*` dialect exactly as before this seam. The
    canonicalization, hashing and Ed25519 math are profile-INVARIANT, so a profile never relaxes integrity.

    Returns::

        {"state": STATE_VERIFIED | STATE_INTEGRITY_ONLY_DEMO | STATE_INTEGRITY_ONLY | STATE_FAIL,
         "integrity_ok": bool,      # every hash recomputes AND the signature is valid under the
                                    # embedded key: the sealed inputs/result are exactly as signed
         "key_matches_pin": bool,   # integrity_ok AND the signing key IS the pinned key. This is the
                                    # conformance question ("well-formed + signed under the pinned key");
                                    # it is NOT origin while the pin is the public demo identity.
         "origin_ok": bool,         # key_matches_pin AND the pin is a real production trust root (NOT the
                                    # demo identity). False under the demo pin even for a pin-signed bundle,
                                    # and never True on a bundle whose integrity fails.
         "problems": [...],         # every problem, integrity first then origin -- what
                                    # `verify_bundle` returns
         "integrity_problems": [...], "origin_problems": [...],
         "signer": "ed25519:<hex>" | None,   # the key the bundle carries
         "signer_is_demo": bool, "pinned_key_is_demo": bool, "pinned_key": "ed25519:<hex>"}

    `verify_bundle(bundle)` is `(origin_ok, problems)`. This classifier exists so a consumer can tell
    "untampered but not origin-proven" (re-derivable: its sealed inputs are exactly what the signer
    sealed) from "edited/forged" (never to be re-derived) without loosening what a plain pass means.
    """
    problems: list[str] = []
    origin_problems: list[str] = []
    attestation_problems: list[str] = []
    attestations: list = []
    canon_info: dict = {}
    sig_info: dict = {}
    signer = _check(bundle, problems, origin_problems, attestation_problems, attestations,
                    profile=profile, canon_out=canon_info, sig_out=sig_info)
    integrity_ok = not problems
    # ORIGIN has two independent gates. First, the signature must be under the PINNED key
    # (`_check_signature` records a key mismatch in `origin_problems`). Second, the pin itself must be a
    # real production trust root: while proof-core pins the PUBLIC demo identity, anyone can reproduce a
    # signature under its published seed, so even a bundle signed under the pin proves integrity, NEVER
    # origin. `key_matches_pin` answers the first gate alone (the conformance question); `origin_ok`
    # requires both, so it is False under the demo pin whatever key signed.
    key_matches_pin = integrity_ok and not origin_problems
    # the EFFECTIVE pin is the profile's trust root when one is supplied, else the module-global pin.
    # On the DEFAULT (no-profile) path `demo_pin` still comes from `pinned_key_is_demo()` so the existing
    # module-global pin controls (and stays test-monkeypatchable); a profile that supplies its OWN pin
    # decides demo-ness from that key, keeping a profiled origin verdict self-consistent.
    #
    # A profile may ALSO declare its pin demo via `pin_is_demo` (default False). The literal match against
    # this verifier's own well-known demo key catches only a pin that reuses THAT key; a dialect that pins
    # its OWN demo/test key (!= `_DEMO_PUBKEY`) would otherwise earn a full origin verdict. `pin_is_demo`
    # is the dialect's honest self-declaration that its pin is not a production trust root -- OR'd in below
    # so such a pin is treated as demo (integrity-only) even when the literal match does not hold. It
    # defaults False and `_profile_value` returns False for `profile is None`, so the neutral / no-profile
    # path is byte/verdict-identical.
    profile_pin = _profile_value(profile, "pinned_pubkey", None)
    profile_declares_demo = _profile_value(profile, "pin_is_demo", False)
    if profile_pin is None:
        effective_pin = _PINNED_PUBKEY
        demo_pin = pinned_key_is_demo() or profile_declares_demo
    else:
        effective_pin = profile_pin
        demo_pin = (effective_pin == _DEMO_PUBKEY) or profile_declares_demo
    if demo_pin and key_matches_pin:
        origin_problems.append("pinned key is the public demo identity; origin cannot be established")
    origin_ok = integrity_ok and not origin_problems
    if not integrity_ok:
        # ADR-050: a bundle sealed under a newer-than-supported canon whose header seal + signature are
        # valid is a DISTINCT, NAMED fail-FORWARD verdict, not a plain integrity failure. integrity_ok is
        # still False (a boolean consumer stays fail-closed); only the state + message distinguish it.
        if canon_info.get("unsupported"):
            state = STATE_UNSUPPORTED_CANON
        elif sig_info.get("unsupported_alg") and len(problems) == 1:
            state = STATE_UNSUPPORTED_ALG
        else:
            state = STATE_FAIL
    elif origin_ok:
        state = STATE_VERIFIED
    elif demo_pin and key_matches_pin:
        state = STATE_INTEGRITY_ONLY_DEMO
    else:
        state = STATE_INTEGRITY_ONLY
    return {
        "state": state,
        "integrity_ok": integrity_ok,
        "key_matches_pin": key_matches_pin,
        "origin_ok": origin_ok,
        "problems": problems + origin_problems,
        "integrity_problems": problems,
        "origin_problems": origin_problems,
        # human sign-offs (countersignatures), a SEPARATE dimension from the decision seal above:
        "attestations": attestations,                 # [{role, name, timestamp, signer, valid}]
        "attestations_ok": not attestation_problems,  # structure well-formed AND every present sign-off valid
        "attestation_problems": attestation_problems,
        "attestations_null": isinstance(bundle, dict) and "attestations" in bundle and bundle["attestations"] is None,
        # optional frontier assertion slots, as sealed in provenance -- PRODUCER claims the spine carries
        # and shape-checks but never evaluates (applicability is the adapter's judgement, not the seal's):
        "frontier": _frontier_report(bundle),
        "signer": ("ed25519:" + signer) if isinstance(signer, str) else None,
        "signer_is_demo": signer == _DEMO_PUBKEY,
        "pinned_key_is_demo": demo_pin,
        "pinned_key": "ed25519:" + effective_pin,
        # ADR-050: the sealed canon version this bundle claims, and the highest version this verifier can
        # apply. `canon_version` is None when the header was malformed/missing (an integrity FAIL).
        "canon_version": canon_info.get("version"),
        "supported_canon_max": canon_info.get("supported_max", _CANON_SUPPORTED_MAX),
    }


def verify_bundle(bundle: dict, *, profile=None) -> tuple[bool, list[str]]:
    """Recompute every hash, check the embedded result.v1 core, and verify the signature
    under the pinned key; return (ok, problems). `ok` means INTEGRITY AND ORIGIN: a bundle
    that is untampered but signed under a key other than the pinned one is NOT ok here, and
    neither is ANY bundle while the pin is the public demo identity (origin cannot be
    established under the demo pin). See `classify_bundle` for the full verdict, and
    `integrity_ok` for callers that only need the untampered check. `profile` (optional) selects a
    dialect; see `classify_bundle`."""
    rep = classify_bundle(bundle, profile=profile)
    return rep["origin_ok"], rep["problems"]


def integrity_ok(bundle: dict, *, profile=None) -> bool:
    """INTEGRITY only: every hash recomputes and the Ed25519 signature is valid under the bundle's OWN
    embedded key, so the sealed inputs/result are exactly as signed. Says NOTHING about origin -- the
    signing key need not be the pin, and under the demo pin origin can never be established. Callers that
    only need 'is this record untampered' use this; `verify_bundle` additionally requires origin.
    `profile` (optional) selects a dialect; see `classify_bundle`."""
    return classify_bundle(bundle, profile=profile)["integrity_ok"]


def _check(bundle: dict, problems: list[str], origin_problems: list[str],
           attestation_problems: list[str] | None = None, attestations_out: list | None = None,
           profile=None, canon_out: dict | None = None, sig_out: dict | None = None) -> str | None:
    """Run every check, appending integrity problems to `problems` and origin problems to
    `origin_problems`; return the embedded signer key (hex) if the signature block was readable.
    Human sign-offs, if any, are validated into `attestations_out` with problems to `attestation_problems`
    (a separate dimension -- a bad sign-off never makes the decision itself read as tampered)."""
    # a malformed top-level value (a JSON list/string/number, not an object) must fail CLOSED with a
    # problem, not crash with an AttributeError on the .get() calls below -- a verifier a reviewer
    # points at arbitrary bytes must never throw instead of returning a verdict.
    if not isinstance(bundle, dict):
        problems.append(f"bundle is not a JSON object (got {type(bundle).__name__})")
        return None
    # a pathologically deep structure must fail CLOSED with a verdict too: the recursive walks below
    # (`_non_finite_paths`, `_canon`) would otherwise raise RecursionError instead of answering.
    if _exceeds_depth(bundle):
        problems.append(f"bundle nests deeper than {_MAX_JSON_DEPTH} levels (rejected fail-closed)")
        return None
    # ADR-050: READ `canon_version` BEFORE trusting any hash -- after the depth guard, BEFORE the schema
    # check (so a future envelope tag never masks the verdict as "unknown envelope schema"). The header
    # canonicalizes identically under every canon version, so this is a plain parse.
    sha256sums_hdr = bundle.get("sha256sums")
    canon_problem, canon_version, canon_newer = _read_canon_version(sha256sums_hdr)
    if canon_out is not None:
        canon_out["version"] = canon_version
        canon_out["supported_max"] = _CANON_SUPPORTED_MAX
        canon_out["unsupported"] = False
    if canon_problem is not None:
        # MISSING / non-int / < 1 / float / bool: a malformed header -> integrity FAIL (no implicit default).
        # Nothing below can be trusted, so stop here with the one clear reason.
        problems.append(canon_problem)
        return None
    if canon_newer:
        # fail-FORWARD. The header (`sha256sums`) canonicalizes identically under every canon version
        # (ADR-050 header invariant), so we CAN still check the seal and the Ed25519 signature over it. We
        # do NOT recompute the sections (we lack that canon), so the verdict says only that this verifier
        # CANNOT CHECK them -- never that the record is "untampered". Per ADR-050 Decision 4, the pinned-key
        # status is still recorded (via `origin_problems` below) so a reader can tell a trustworthy "get a
        # newer verifier" from a possibly attacker-planted version label. A record whose header does NOT seal
        # under a valid signature is tampering, not a newer format: a plain integrity FAIL, never
        # `unsupported-canon`.
        bsum = bundle.get("bundle_sha256")
        cb = _try_canon(sha256sums_hdr, "sha256sums", problems)
        recomputed = _sha(cb) if cb is not None else ""
        header_seals = (cb is not None and isinstance(bsum, str)
                        and _SHA256_RE.fullmatch(bsum) is not None and recomputed == bsum)
        sig_problems: list[str] = []
        # populates `origin_problems` with the pinned-key mismatch (Decision 4) even on fail-forward.
        signer = _check_signature(bundle, recomputed, sig_problems, origin_problems, profile, sig_out=sig_out)
        if header_seals and not sig_problems:
            if canon_out is not None:
                canon_out["unsupported"] = True
            problems.append(
                f"{STATE_UNSUPPORTED_CANON}: sealed under canon_version {canon_version}; this verifier "
                f"supports up to {_CANON_SUPPORTED_MAX} and so CANNOT recompute or check this bundle's "
                "sections under that canon -- use a newer verifier (not an integrity failure, and not a "
                "statement that the sections are untampered)")
            # Canon-INDEPENDENT trust-surface check (pure top-level key membership): an unsigned key riding
            # outside the sealed shape -- e.g. "conclusion": "accepted by the regulator" -- is caught even
            # on a fail-forward bundle, so a field-rendering UI is never handed an unsigned claim with no
            # warning. The newer bundle's SECTIONS are left to the newer verifier; this is the envelope only.
            extra_top = sorted(set(bundle) - _ALLOWED_TOP)
            if extra_top:
                problems.append(
                    f"bundle has unexpected top-level keys (unsigned, riding outside the seal): {extra_top}")
        elif header_seals and sig_out is not None and sig_out.get("unsupported_alg") and len(sig_problems) == 1:
            # F3: header seals, sole signature problem is an unknown suite -> unsupported-alg precedence.
            # BUT an unsigned top-level key riding outside the seal must still be caught (I1), matching the
            # normal path and the unsupported-canon sibling; if present, fall through to FAIL.
            extra_top = sorted(set(bundle) - _ALLOWED_TOP)
            if extra_top:
                problems.append(
                    f"bundle has unexpected top-level keys (unsigned, riding outside the seal): {extra_top}")
                problems.extend(sig_problems)
            else:
                problems.append(sig_problems[0])
        else:
            problems.append(
                f"declares canon_version {canon_version} but its header does not seal under a valid "
                "signature: an unsigned/edited version claim is tampering, not a newer format")
            problems.extend(sig_problems)
        return signer
    # canon_version is now a KNOWN version (1..max; the newer branch returned above). Select the matching
    # canon so a v2 bundle's SECTION values recompute under JCS, not v1. The all-ASCII sha256sums header and
    # the bundle-seal recompute stay on `_canon` (byte-identical across versions), so only section values move.
    canon_fn = _CANON[canon_version]
    envelope_schema = _profile_value(profile, "envelope_schema", "evidence.envelope.v3")
    if bundle.get("schema") != envelope_schema:
        problems.append(f"unknown envelope schema: {bundle.get('schema')!r}")

    # The signature covers only the three section DIGESTS (sha256sums), so any key OUTSIDE the known
    # envelope shape rides UNSIGNED. Without this check an intermediary who cannot re-sign could add a
    # top-level field -- e.g. "conclusion": "accepted by the regulator" -- to a bundle that still "verifies", and a
    # downstream reader/UI that renders bundle fields would show an attacker-authored claim the seal
    # never committed to. Reject unknown top-level keys so nothing unsigned can ride along.
    # ADR-049 (one strict dialect): `host` is RETIRED -- it is NOT an allowed top-level key, so a stapled
    # host block FAILs the top-level allowlist (`_ALLOWED_TOP`) with the "unexpected top-level keys"
    # message. Its structured replacement is the SIGNED `toolchain` axis (always carrying `machine`).
    extra_top = sorted(set(bundle) - _ALLOWED_TOP)
    if extra_top:
        problems.append(f"bundle has unexpected top-level keys (unsigned): {extra_top}")

    # RFC 8259 strictness: a NaN/Infinity anywhere in the bundle is not JSON. Rejected as a verdict
    # up front so the canonicalization below (allow_nan=False) never raises instead of answering.
    non_finite = _non_finite_paths(bundle)
    if non_finite:
        problems.append(f"bundle contains non-JSON (NaN/Infinity) values at: {non_finite[:5]}")
        return None

    # every structural sub-object must be an object: a list/string where a dict belongs must fail
    # CLOSED with a problem, not crash on the .get() calls below (a verifier pointed at arbitrary
    # bytes returns a verdict, always).
    manifest = bundle.get("manifest", {})
    if not isinstance(manifest, dict):
        problems.append(f"manifest is not a JSON object (got {type(manifest).__name__})")
        manifest = {}
    sha256sums = bundle.get("sha256sums", {})
    if not isinstance(sha256sums, dict):
        problems.append(f"sha256sums is not a JSON object (got {type(sha256sums).__name__})")
        sha256sums = {}
    # sections whose CONTENTS are lawfully withheld -- still pinned by digest (see redaction). The
    # redaction record is UNSIGNED, so it is held to a strict shape: only its known keys, and a
    # non-empty `withheld` naming real sections (a `reason` riding over an empty `withheld` is just
    # unsigned prose on a bundle that would otherwise verify).
    withheld = _check_redaction(bundle, problems, profile)
    _check_host(bundle, problems)
    _check_timestamp(bundle, problems, profile)

    # the manifest and the sealed digest-list must be EXACTLY the three sections -- no injected
    # extra keys (the seal covers the sha256sums key set, but the manifest is not sealed whole)
    sections = set(_SECTIONS)
    if set(manifest) != sections:
        problems.append(f"manifest has unexpected/missing sections: {sorted(set(manifest) ^ sections)}")
    # ADR-050: `sha256sums` is the three sections PLUS the integer `canon_version` (already validated as a
    # good int above, since we are past the fail-forward gate). Exactly those four keys -- no injected extra.
    if set(sha256sums) != _SHA256SUMS_KEYS:
        problems.append(f"sha256sums has unexpected/missing sections: {sorted(set(sha256sums) ^ _SHA256SUMS_KEYS)}")

    for side in _SECTIONS:
        blk = manifest.get(side, {})
        if not isinstance(blk, dict):
            problems.append(f"{side}: manifest block is not a JSON object (got {type(blk).__name__})")
            blk = {}
        extra_blk = sorted(set(blk) - {"sha256", "value"})
        if extra_blk:
            problems.append(f"{side}: manifest block has unexpected keys (unsigned): {extra_blk}")
        declared = blk.get("sha256")
        sealed = sha256sums.get(side)
        # Each digest must be a WELL-FORMED `sha256:<64 lowercase hex>`, not merely equal to its twin.
        # A pair of identical-but-malformed digests ("not-a-digest") would pass the equality check below
        # and ride on the seal; a digest that is not a real content hash is never trustworthy. (S3)
        for lbl, dig in ((f"{side} manifest sha256", declared), (f"{side} sealed digest", sealed)):
            if not (isinstance(dig, str) and _SHA256_RE.fullmatch(dig)):
                problems.append(f"{lbl} is not a well-formed sha256:<64 hex> digest: {dig!r}")
        if declared != sealed:               # the manifest digest must match the SEALED digest
            problems.append(f"{side}: manifest digest {declared} != sealed digest {sealed}")
        if "value" in blk:
            cb = _try_canon(blk["value"], f"{side}: manifest value", problems, canon_fn=canon_fn)
            if cb is not None:
                recomputed = _sha(cb)
                if recomputed != declared:
                    problems.append(f"{side}: manifest {declared} != recomputed {recomputed}")
            if side in withheld:
                problems.append(f"{side}: declared withheld but its value is still present")
        elif side not in withheld:           # a missing value is only OK if lawfully redacted
            problems.append(f"{side}: value is missing but not declared redacted")

    # embedded readable copies must match the hashed ones -- unless that section is withheld
    if "result" in withheld:
        if "result" in bundle:
            problems.append("result section withheld but the embedded result core is still present")
    else:
        core = bundle.get("result", {})
        if not isinstance(core, dict):
            problems.append(f"embedded result core is not a JSON object (got {type(core).__name__})")
            core = {}
        for k in _profile_value(profile, "result_required_fields", _RESULT_REQUIRED):
            if k not in core:
                problems.append(f"embedded result.v1 core missing required field: {k!r}")
        # Pin the result-core CONTRACT IDENTITY, not just field presence: the producer stamps a specific
        # `schema`/`schema_version` at mint, so a future `evidence.result.v2` core (different required fields
        # / meaning) must not verify identically to v1. Enforce the values the profile pins.
        want_result_schema = _profile_value(profile, "result_schema", "evidence.result.v1")
        want_result_schema_version = _profile_value(profile, "result_schema_version", 1)
        if "schema" in core and core.get("schema") != want_result_schema:
            problems.append(f"embedded result core schema is not {want_result_schema!r}: {core.get('schema')!r}")
        if "schema_version" in core and (isinstance(core.get("schema_version"), bool)
                                         or core.get("schema_version") != want_result_schema_version):
            problems.append(f"embedded result core schema_version is not {want_result_schema_version!r}: "
                            f"{core.get('schema_version')!r}")
        res_blk = manifest.get("result", {})
        cc = _try_canon(core, "embedded result core", problems, canon_fn=canon_fn)
        cr = _try_canon(res_blk.get("value") if isinstance(res_blk, dict) else None,
                        "hashed result core", problems, canon_fn=canon_fn)
        if cc is not None and cr is not None and cc != cr:
            problems.append("embedded result core != hashed result core")
    if "provenance" in withheld:
        if "reproducibility" in bundle:
            problems.append("provenance section withheld but embedded reproducibility is still present")
    else:
        prov_blk = manifest.get("provenance", {})
        prov_val = prov_blk.get("value") if isinstance(prov_blk, dict) else None
        # a signed bundle whose provenance is null asserts no producer, scope or pins at all: malformed, not a
        # quiet pass (a null provenance + null reproducibility used to compare equal and verify).
        if not isinstance(prov_val, dict):
            problems.append(f"hashed provenance value must be a JSON object (got {type(prov_val).__name__})")
        if "reproducibility" in bundle and not isinstance(bundle["reproducibility"], dict):
            problems.append("embedded reproducibility is present but not a JSON object "
                            f"(got {type(bundle['reproducibility']).__name__})")
        cp = _try_canon(bundle.get("reproducibility", {}), "embedded reproducibility", problems, canon_fn=canon_fn)
        cpv = _try_canon(prov_val, "hashed provenance", problems, canon_fn=canon_fn)
        if cp is not None and cpv is not None and cp != cpv:
            problems.append("embedded provenance != hashed provenance")
        # S6: the data-library pin must be well-formed: a real `sha256:<64 lowercase hex>`. This catches
        # a producer that stamps a garbage pin -- a claim that LOOKS like a content digest but was never
        # one -- which the seal alone would happily carry. Whenever a library is NAMED (any non-empty
        # string, INCLUDING the honest `unpinned` marker, which the producer always emits WITH a real
        # digest) the digest is mandatory: a null/missing digest is a name with nothing committing to the
        # bytes. There is no digest-less exception for any name.
        if isinstance(prov_val, dict):
            _check_required_provenance(prov_val, problems)
            _check_optional_provenance(prov_val, problems)
            dl = prov_val.get("data_library")
            dls = prov_val.get("data_library_sha256")
            _no_null_leaf(prov_val, "data_library", "provenance data_library", problems)
            if dl is not None and not (isinstance(dl, str) and dl):
                problems.append(f"provenance data_library is not a non-empty string: {dl!r}")
            if isinstance(dl, str) and dl:
                if not (isinstance(dls, str) and _SHA256_RE.fullmatch(dls)):
                    problems.append(f"provenance names data_library {dl!r} but data_library_sha256 is not a "
                                    f"well-formed sha256:<64 hex> digest: {dls!r}")
            elif dls is not None and not (isinstance(dls, str) and _SHA256_RE.fullmatch(dls)):
                problems.append(f"provenance data_library_sha256 is not a well-formed digest: {dls!r}")
            # optional frontier assertion slots (applicability / completeness / derived_from): shape only,
            # never the claim itself -- a sealed assertion the spine carries, not a correctness judgement.
            # `own_seal` (this bundle's recomputed seal) feeds ONLY the binding self-reference check, which
            # the binding self-reference check (ADR-049: a derived_from is always binding).
            try:
                own_seal = _sha(_canon(sha256sums))
            except (TypeError, ValueError):
                own_seal = None
            _check_frontier_slots(prov_val, problems, profile, own_seal=own_seal)

    # the sealed bundle digest itself must be a well-formed sha256:<64 hex>, not just equal to the
    # recompute -- a malformed seal is never a content hash whatever it matches. (S3)
    bsum = bundle.get("bundle_sha256")
    if not (isinstance(bsum, str) and _SHA256_RE.fullmatch(bsum)):
        problems.append(f"bundle_sha256 is not a well-formed sha256:<64 hex> digest: {bsum!r}")

    # the signature covers ONLY the sealed digest-list, so withholding a value never disturbs it
    cs = _try_canon(sha256sums, "sha256sums", problems)
    recomputed_bundle = _sha(cs) if cs is not None else ""
    if cs is not None and recomputed_bundle != bundle.get("bundle_sha256"):
        problems.append(f"bundle: {bundle.get('bundle_sha256')} != recomputed {recomputed_bundle}")

    # a lawful redaction leaves the seal untouched, so its recorded parent digest MUST equal this
    # bundle's own seal -- otherwise the (unsigned) record is claiming a false origin
    red = bundle.get("redaction")
    if isinstance(red, dict) and "parent_bundle_sha256" in red \
            and red["parent_bundle_sha256"] != bundle.get("bundle_sha256"):
        problems.append("redaction parent_bundle_sha256 does not match this bundle's seal")

    # LEAK GUARD (defense in depth): withholding a section must ACTUALLY withhold it. The raw inputs
    # were historically duplicated into the result core's provenance, so redacting `inputs` left them
    # readable there -- a redaction that does not redact (a proprietary or export-controlled-data
    # exposure, e.g. a regulatory docket's public copy). Refuse
    # any bundle that declares `inputs` withheld while the inputs are still recoverable in the (public)
    # result core -- both the readable top-level copy and the sealed manifest.result value.
    if "inputs" in withheld:
        res_blk = manifest.get("result", {})
        for core_src in (bundle.get("result"), res_blk.get("value") if isinstance(res_blk, dict) else None):
            if isinstance(core_src, dict) and isinstance(core_src.get("provenance"), dict) \
                    and "inputs" in core_src["provenance"]:
                problems.append("inputs declared withheld but still present in the result core's provenance")
                break

    # human sign-offs are validated against the RECOMPUTED seal (a tampered decision breaks both the
    # producer signature above AND every sign-off over the old digest), into their own dimension.
    if attestation_problems is not None and attestations_out is not None:
        _check_attestations(bundle, recomputed_bundle, attestation_problems, attestations_out)

    return _check_signature(bundle, recomputed_bundle, problems, origin_problems, profile, sig_out=sig_out)


# ====================================================================================================
# Stage-2: the cross-bundle CHAIN walker (ADR-042) -- a SEPARATE claim from the single-bundle verdict.
#
# DOMAIN-NEUTRAL and OFF-PATH: `verify_chain` is a NEW top-level symbol nothing on the neutral verify path
# calls. It names NOTHING about any domain (digests, RFC 6901 pointers and capability-NAME strings only).
# It is the Stage-2 port UP of a dialect's own chain verifier, proven by the parity tests to reproduce it;
# a dialect keeps its own production chain verifier as its verdict surface, so porting the walker UP is no
# trust regression. The walk is AIR-GAPPED: the caller injects `resolve(seal)->bundle|None` (the same seam
# as ReproduceRunner); nothing is fetched. `classify_bundle` is run under the supplied `profile`, so the
# walker verifies a dialect's packs exactly as that dialect's own verifier does.
# ====================================================================================================

_MAX_CHAIN_DEPTH = 32
_MAX_CHAIN_VISITED = 256
#: An RFC 6901 list index is canonical ASCII decimal ONLY (no leading zeros, no Unicode digits): bounded
#: so `int()` can never be asked to parse a blob, and so a JS verifier and this one agree.
_INDEX_RE = re.compile(r"0|[1-9][0-9]*")
_MAX_INDEX_DIGITS = 18

#: Per-link states.
LINK_VERIFIED = "verified"
LINK_INTEGRITY_ONLY = "integrity-only"
LINK_FAIL = "FAIL"
LINK_UNRESOLVED = "unresolved"
LINK_CONSUMED_UNVERIFIABLE = "consumed-unverifiable"
LINK_CONSUMED_MISMATCH = "consumed-mismatch"
LINK_CROSS_CAPABILITY_MISMATCH = "cross-capability-mismatch"
LINK_CYCLE = "cycle"
#: ADR-050 fail-FORWARD at the chain level: an upstream sealed under a canon this verifier cannot apply is
#: INCOMPLETE (get a newer verifier), never a tamper FAIL -- the same distinction the single-bundle verdict
#: makes. Without this the walker would collapse a legitimate newer-canon upstream into `FAIL`/"tampered".
LINK_UNSUPPORTED_CANON = "unsupported-canon"

#: Chain verdicts.
CHAIN_VERIFIED = "verified"
CHAIN_INTEGRITY_ONLY = "integrity-only"
CHAIN_INCOMPLETE = "incomplete"
CHAIN_FAIL = "fail"
CHAIN_UNKNOWN = "unknown"      # the root's provenance is withheld: its links are invisible
CHAIN_NONE = "none"            # the root seals no `derived_from`

#: The `cross_capability_guard` report field: whether the citing card's consumes POLICY (needs a registry
#: via `consumes_of`) was applied. The registry-free STRUCTURAL kind check is always applied.
GUARD_APPLIED = "applied"
GUARD_NOT_APPLIED = "not-applied"

_LINK_RANK = {
    LINK_VERIFIED: 3,
    LINK_INTEGRITY_ONLY: 2,
    LINK_UNRESOLVED: 1,
    LINK_CONSUMED_UNVERIFIABLE: 1,
    LINK_UNSUPPORTED_CANON: 1,          # fail-FORWARD: incomplete (get a newer verifier), not a tamper FAIL
    LINK_FAIL: 0,
    LINK_CONSUMED_MISMATCH: 0,
    LINK_CROSS_CAPABILITY_MISMATCH: 0,
    LINK_CYCLE: 0,
}
_CHAIN_OF_RANK = {3: CHAIN_VERIFIED, 2: CHAIN_INTEGRITY_ONLY, 1: CHAIN_INCOMPLETE, 0: CHAIN_FAIL}

#: Sentinel for "the citing bundle's sealed inputs value is PRESENT but not {capability, inputs}": distinct
#: from None (withheld). Present-but-malformed binds nothing -> `consumed-mismatch`.
_MALFORMED_INPUTS = ()


def _sealed_provenance(bundle: Any) -> tuple[str, Any]:
    """The sealed provenance value (`manifest.provenance.value`) and how it was found: ``("present", value)``,
    ``("withheld", None)`` (lawfully redacted or stripped), or ``("absent", None)`` (no readable manifest)."""
    manifest = bundle.get("manifest") if isinstance(bundle, dict) else None
    blk = manifest.get("provenance") if isinstance(manifest, dict) else None
    if not isinstance(blk, dict):
        return "absent", None
    if "value" not in blk:
        return "withheld", None
    return "present", blk["value"]


def _chain_state(bundle: Any, problems: list[str]) -> str:
    """The sealed chain claim's state: "none" | "declared-unwalked" | "malformed" | "unknown"."""
    how, prov_val = _sealed_provenance(bundle)
    if how == "withheld":
        return "unknown"
    if how != "present" or not isinstance(prov_val, dict) or "derived_from" not in prov_val:
        return "none"
    if any("derived_from" in p for p in problems):
        return "malformed"
    return "declared-unwalked"


def _classify_chain(bundle: Any, profile) -> dict:
    """`classify_bundle` under `profile`, augmented with the sealed-chain state the walker folds over."""
    rep = dict(classify_bundle(bundle, profile=profile))
    rep["chain"] = _chain_state(bundle, rep["integrity_problems"])
    return rep


def _pointer_tokens(pointer: str) -> list[str] | None:
    """The unescaped reference tokens of an RFC 6901 pointer, or None when it is not one (`""` -> [])."""
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        return None
    return [raw.replace("~1", "/").replace("~0", "~") for raw in pointer[1:].split("/")]


def resolve_pointer(doc: Any, pointer: str) -> tuple[bool, Any]:
    """Resolve an RFC 6901 JSON pointer; ``(True, value)`` or ``(False, None)``. "" is the whole document.
    List indices must be canonical ASCII decimal; anything else does not resolve -- never a crash."""
    tokens = _pointer_tokens(pointer)
    if tokens is None:
        return False, None
    cur = doc
    for token in tokens:
        if isinstance(cur, dict):
            if token not in cur:
                return False, None
            cur = cur[token]
        elif isinstance(cur, list):
            if len(token) > _MAX_INDEX_DIGITS or not _INDEX_RE.fullmatch(token):
                return False, None
            idx = int(token)
            if idx >= len(cur):
                return False, None
            cur = cur[idx]
        else:
            return False, None
    return True, cur


def _seal_of(bundle: Any) -> str | None:
    """A bundle's RECOMPUTED seal, `sha(canon(sha256sums))` -- never the `bundle_sha256` it claims."""
    sums = bundle.get("sha256sums") if isinstance(bundle, dict) else None
    if not isinstance(sums, dict):
        return None
    try:
        return _sha(_canon(sums))
    except (TypeError, ValueError):
        return None


def _result_block(bundle: Any) -> Any:
    manifest = bundle.get("manifest") if isinstance(bundle, dict) else None
    return manifest.get("result") if isinstance(manifest, dict) else None


def _candidate_rank(bundle: dict, profile) -> tuple[int, int, int]:
    rep = classify_bundle(bundle, profile=profile)
    res = _result_block(bundle)
    return (int(rep["integrity_ok"]), int(isinstance(res, dict) and "value" in res), int(rep["origin_ok"]))


def index_upstreams(bundles, *, profile=None) -> dict[str, dict]:
    """Index candidate upstream bundles by their RECOMPUTED seal (a convenience to build a `resolve` from:
    `index_upstreams(...).get`). When two copies share a seal, the intact copy with its `result` present
    (then: signed under the pin) wins; among equals the FIRST seen wins."""
    index: dict[str, dict] = {}
    ranks: dict[str, tuple[int, int, int]] = {}
    for b in bundles:
        seal = _seal_of(b)
        if seal is None:
            continue
        if seal not in index:
            index[seal] = b
            continue
        if seal not in ranks:
            ranks[seal] = _candidate_rank(index[seal], profile)
        rank = _candidate_rank(b, profile)
        if rank > ranks[seal]:
            index[seal], ranks[seal] = b, rank
    return index


def _digest_of_value(value: Any, canon_fn=_canon) -> str | None:
    """`sha(canon_fn(value))`, or None when the value cannot be canonicalized (never a traceback: the walker
    must answer with a verdict on any in-memory object, incl. a non-string key, which v2's key sort cannot
    encode). Under canon v2 a bare integer outside +/-(2^53-1) cannot be canonicalized (`_v2_number` refuses
    it), so it digests to None -- a v2 link cannot bind a float to a different, merely nearby big int."""
    try:
        return _sha(canon_fn(value))
    except (TypeError, ValueError, AttributeError, RecursionError):
        return None


def _finish(entry: dict, ranks: list[int], st: str, detail: str) -> None:
    entry["state"], entry["detail"] = st, detail
    ranks.append(_LINK_RANK[st])


def _note(report: dict, state: dict, problem: str) -> None:
    if problem not in state["noted"]:
        state["noted"].add(problem)
        report["problems"].append(problem)


def _own_inputs(citing: dict) -> Any:
    manifest = citing.get("manifest") if isinstance(citing, dict) else None
    blk = manifest.get("inputs") if isinstance(manifest, dict) else None
    if not isinstance(blk, dict) or "value" not in blk:
        return None
    value = blk["value"]
    if not isinstance(value, dict) or "inputs" not in value:
        return _MALFORMED_INPUTS
    return value["inputs"]


def _citing_canon_version(citing: Any) -> int | None:
    """The canon_version a citing bundle's links were digested under (ADR-054): its OWN sealed version, or
    None when it is not a supported one. `_walk` only walks a citing bundle that classified intact, so None
    is not expected; if it ever happens every link reads `consumed-mismatch` (fail-closed, no v1 guess)."""
    sums = citing.get("sha256sums") if isinstance(citing, dict) else None
    problem, version, newer = _read_canon_version(sums)
    if problem is None and not newer and version in _CANON:
        return version
    return None


def _consumed_verdict(link: dict, up: dict, own_inputs: Any, citing_cv: int | None = 1) -> tuple[str, str] | None:
    """Check the consumed value on BOTH ends of a link whose upstream is intact; None = it binds.

    ADR-054: `consumed.sha256` is taken under the CITING bundle's canon, so BOTH ends -- the upstream's result
    value and the citing bundle's own sealed input -- are re-digested under that canon. The citing canon must
    be AT LEAST the upstream's: a v1 digest is spelling-sensitive (`2.0` != `2`) while a v2 upstream's seal is
    not (JCS writes both as `2`), so a v1 link to a v2 upstream would bind or not depending on how the
    upstream's JSON text happens to be spelled, not on what was sealed. Such a link never binds."""
    if citing_cv is None:
        return (LINK_CONSUMED_MISMATCH, "the citing bundle's canon_version is unreadable; the link cannot be bound")
    up_cv = up["sha256sums"].get("canon_version") if isinstance(up.get("sha256sums"), dict) else None
    if not isinstance(up_cv, int) or isinstance(up_cv, bool) or up_cv > citing_cv:
        return (LINK_CONSUMED_MISMATCH,
                (f"a canon_version {citing_cv} link cannot bind a canon_version {up_cv!r} upstream: the citing "
                 "canon must be at least the upstream's (ADR-054), else the binding depends on how the "
                 "upstream's JSON is spelled rather than on what it sealed"))
    canon_fn = _CANON[citing_cv]
    consumed = link["consumed"]
    res_blk = up["manifest"]["result"]
    if "value" not in res_blk:
        return (LINK_CONSUMED_UNVERIFIABLE, "upstream result is withheld; the consumed value cannot be checked")
    found, value = resolve_pointer(res_blk["value"], consumed["path"])
    if not found:
        return (LINK_CONSUMED_MISMATCH,
                f"consumed.path {consumed['path']!r} does not resolve in the upstream result core")
    if _digest_of_value(value, canon_fn) != consumed["sha256"]:
        return (LINK_CONSUMED_MISMATCH,
                "the value at consumed.path in the upstream result does not have the sealed consumed.sha256")
    if own_inputs is None:
        return (LINK_CONSUMED_UNVERIFIABLE,
                "citing bundle's inputs are withheld; cannot confirm the consumed value was its sealed input")
    if not isinstance(own_inputs, dict):
        return (LINK_CONSUMED_MISMATCH,
                ("the citing bundle's sealed inputs are present but malformed (not {capability, inputs: {...}}): "
                 "there is no sealed input to bind the consumed value to"))
    if consumed["input"] not in own_inputs:
        return (LINK_CONSUMED_MISMATCH, f"names input {consumed['input']!r}, which the citing bundle did not seal")
    if _digest_of_value(own_inputs[consumed["input"]], canon_fn) != consumed["sha256"]:
        return (LINK_CONSUMED_MISMATCH,
                (f"the citing bundle's sealed input {consumed['input']!r} is not the consumed value (a link to "
                 "an upstream that did not feed this result: decoration, not binding)"))
    return None


def _path_capability(pointer: str) -> str | None:
    """The capability `consumed.path` names: the segment after `/result/`, or None when it does not address
    the upstream's result map."""
    tokens = _pointer_tokens(pointer)
    if tokens is None or len(tokens) < 2 or tokens[0] != "result" or tokens[1] == "":
        return None
    return tokens[1]


def _core_capability(core: Any) -> tuple[str | None, str]:
    """The capability an upstream's SEALED result core says it is: its `provenance.capability`, cross-checked
    against the sole key of its `result` map when both are readable."""
    prov = core.get("provenance") if isinstance(core, dict) else None
    named = prov.get("capability") if isinstance(prov, dict) else None
    named = named if isinstance(named, str) and named else None
    res = core.get("result") if isinstance(core, dict) else None
    keyed = next(iter(res)) if isinstance(res, dict) and len(res) == 1 and isinstance(next(iter(res)), str) else None
    if named is not None and keyed is not None and named != keyed:
        return None, f"the upstream's result core is keyed {keyed!r} but its provenance names {named!r} (no one kind)"
    cap = named if named is not None else keyed
    if cap is None:
        return None, ("the upstream's result core names no capability (no provenance.capability and its result "
                      "map is not single-keyed), so the kind of upstream consumed cannot be established")
    return cap, ""


def _structural_verdict(link: dict, up: dict) -> tuple[str, str] | None:
    """The registry-free cross-capability check: the kind `consumed.path` names must be the kind the
    upstream's own sealed core carries."""
    path = link["consumed"]["path"]
    path_cap = _path_capability(path)
    if path_cap is None:
        return (LINK_CROSS_CAPABILITY_MISMATCH,
                (f"consumed.path {path!r} does not address the upstream's result map (/result/<capability>/...): "
                 "the consumed value is not a result the upstream produced, so its kind cannot be established"))
    own, why = _core_capability(up["manifest"]["result"]["value"])
    if own is None:
        return (LINK_CROSS_CAPABILITY_MISMATCH, why)
    if own != path_cap:
        return (LINK_CROSS_CAPABILITY_MISMATCH,
                (f"consumed.path names capability {path_cap!r} but the upstream's sealed result core is {own!r} "
                 "(the link lies about the kind of upstream it consumed)"))
    return None


def _sealed_capability(bundle: dict) -> str | None:
    """The capability name sealed in a bundle's inputs section, or None when the inputs are withheld / odd."""
    manifest = bundle.get("manifest") if isinstance(bundle, dict) else None
    blk = manifest.get("inputs") if isinstance(manifest, dict) else None
    value = blk.get("value") if isinstance(blk, dict) else None
    cap = value.get("capability") if isinstance(value, dict) else None
    return cap if isinstance(cap, str) else None


def _consumes_policy(citing_cap, citing_seal: str, consumes_of, report: dict, state: dict):
    """What the citing card declares it consumes, resolved ONCE per citing bundle; None when the policy guard
    cannot apply (no resolver, citing capability unreadable, or the resolver does not know the card -- NOTED)."""
    if consumes_of is None or citing_cap is None:
        return None
    allowed = consumes_of(citing_cap)
    if allowed is None:
        _note(report, state, (f"citing bundle {citing_seal} is {citing_cap!r}, a card the supplied registry does not "
                              "know: its consumes policy was NOT checked for its links"))
        return None
    return tuple(allowed)


def _consumes_verdict(citing_cap, up: dict, allowed) -> tuple[str, str] | None:
    """The cross-capability POLICY guard; None = not applicable (no policy resolved) or it passes."""
    if allowed is None:
        return None
    up_cap = _sealed_capability(up)
    if up_cap is None:
        return (LINK_CONSUMED_UNVERIFIABLE, ("upstream inputs are withheld, so its capability cannot be checked "
                                             f"against what {citing_cap!r} declares it consumes {list(allowed)}"))
    if up_cap not in allowed:
        return (LINK_FAIL, (f"cross-capability link: the upstream is {up_cap!r} but {citing_cap!r} declares it "
                            f"consumes only {list(allowed)} (a link to the wrong kind of upstream)"))
    return None


def verify_chain(bundle: dict, resolve, *, profile=None, consumes_of=None,
                 max_depth: int = _MAX_CHAIN_DEPTH, max_visited: int = _MAX_CHAIN_VISITED) -> dict:
    """Walk `bundle`'s sealed `derived_from` links through the supplied upstreams; return the chain report.

    DOMAIN-NEUTRAL + OFF-PATH: a Stage-2 addition nothing on the neutral verify path calls. `resolve(seal)
    -> bundle | None` is the air-gapped upstream seam (build one with `index_upstreams(...).get`); nothing
    is fetched. `profile` selects the dialect for every `classify_bundle` the walk performs. `consumes_of`
    is the OPTIONAL cross-capability POLICY resolver (capability-name -> allowed upstream capability names,
    or None for a card the caller does not know); without it the registry-free STRUCTURAL kind check still
    runs and the report says the policy guard was `not-applied`.

    Chain verdict = the MINIMUM over every link and the root's own origin: `verified` > `integrity-only` >
    `incomplete` > `fail`. A root whose integrity fails is `fail`; one whose provenance is withheld is
    `unknown`; one with no `derived_from` is `none`. Fail-closed: a depth / fan-out cap hit is a `fail`.

    BINDING LINKS: every sealed `derived_from` is a BINDING link (ADR-049: the one chain shape) -- it carries
    the upstream's digest triple + a `consumed` triple ({input, path, sha256}) that the walk binds against the
    upstream (the consumed value must be the upstream's result at `consumed.path`, and its kind must match the
    upstream's sealed capability). A root whose link cannot be walked (malformed shape, a consumed value that
    does not bind) yields `fail` with a problem saying so -- never an exception; the single-bundle verdicts
    (`root_state`, integrity) are still reported."""
    root = _classify_chain(bundle, profile)
    report: dict[str, Any] = {
        "chain": CHAIN_FAIL,
        "root_state": root["state"],
        "root_bundle_sha256": _seal_of(bundle),
        "root_chain_field": root["chain"],
        "links": [],
        "problems": [],
        "visited": 0,
        "pinned_key": root["pinned_key"],
        "cross_capability_guard": GUARD_APPLIED if consumes_of is not None else GUARD_NOT_APPLIED,
    }
    if not root["integrity_ok"]:
        report["problems"] = ["root bundle integrity fails; its sealed links cannot be trusted"] + root["problems"]
        return report
    if root["chain"] == "unknown":
        report["chain"] = CHAIN_UNKNOWN
        report["problems"].append("root provenance is withheld: any derived_from link in it is invisible, "
                                  "so the chain cannot be walked (never a silent pass)")
        return report
    if root["chain"] == "none":
        report["chain"] = CHAIN_NONE
        return report
    # ADR-049 (one strict dialect): every `derived_from` is binding (it carries the `consumed` triple +
    # `sha256sums` the walk reads), so the walk always proceeds -- there is no decoration link to guard against.
    ranks = [3 if root["origin_ok"] else 2]
    state = {"visited": set(), "classified": {}, "walked": set(), "noted": set()}
    _walk(bundle, report["root_bundle_sha256"], 1, frozenset([report["root_bundle_sha256"]]),
          resolve, report, ranks, state, max_depth, max_visited, consumes_of, profile)
    report["visited"] = len(state["visited"])
    report["chain"] = _CHAIN_OF_RANK[min(ranks)]
    return report


def _walk(citing: dict, citing_seal: str, depth: int, path: frozenset, resolve, report: dict,
          ranks: list[int], state: dict, max_depth: int, max_visited: int, consumes_of, profile) -> None:
    _, prov = _sealed_provenance(citing)
    links = prov["derived_from"]                      # well-formed: the citing bundle classified intact
    own_inputs = _own_inputs(citing)
    citing_cv = _citing_canon_version(citing)          # ADR-054: links are digested under the citing canon
    citing_cap = _sealed_capability(citing)
    allowed = _consumes_policy(citing_cap, citing_seal, consumes_of, report, state)
    for i, link in enumerate(links):
        target = link["bundle_sha256"]
        entry: dict[str, Any] = {"from": citing_seal, "depth": depth, "index": i, "bundle_sha256": target,
                                 "role": link["role"], "consumed": dict(link["consumed"]),
                                 "state": None, "detail": "", "signer": None, "signer_is_demo": False,
                                 "upstream_capability": None}
        report["links"].append(entry)
        if target in path:
            _finish(entry, ranks, LINK_CYCLE, "names a bundle already on the walk path")
            continue
        if depth > max_depth:
            _note(report, state, f"chain deeper than {max_depth} links (rejected fail-closed)")
            _finish(entry, ranks, LINK_FAIL, f"beyond the depth cap ({max_depth})")
            continue
        if target not in state["visited"] and len(state["visited"]) >= max_visited:
            _note(report, state, f"chain opens more than {max_visited} upstream bundles (rejected fail-closed)")
            _finish(entry, ranks, LINK_FAIL, f"beyond the visited cap ({max_visited})")
            continue
        up = resolve(target)
        if up is None:
            _finish(entry, ranks, LINK_UNRESOLVED, "no supplied bundle has this seal")
            continue
        state["visited"].add(target)
        rep = state["classified"].get(target)           # one Ed25519 verify per DISTINCT upstream
        if rep is None:
            rep = state["classified"][target] = _classify_chain(up, profile)
        entry["signer"], entry["signer_is_demo"] = rep["signer"], rep["signer_is_demo"]
        if rep["state"] == STATE_UNSUPPORTED_CANON:
            # ADR-050 fail-FORWARD: the upstream's header seals + signs but was sealed under a newer canon
            # this verifier cannot apply. That is INCOMPLETE (get a newer verifier), NOT tampering -- mirror
            # the single-bundle verdict instead of collapsing it into an integrity FAIL.
            _finish(entry, ranks, LINK_UNSUPPORTED_CANON,
                    "upstream sealed under a newer canon this verifier cannot check: "
                    + "; ".join(rep["integrity_problems"][:1]))
            continue
        if not rep["integrity_ok"]:
            _finish(entry, ranks, LINK_FAIL, "upstream fails integrity: " + "; ".join(rep["integrity_problems"][:3]))
            continue
        if _seal_of(up) != target:
            _finish(entry, ranks, LINK_FAIL, "supplied upstream is indexed under a digest that is not its recomputed seal")
            continue
        if up["sha256sums"] != link["sha256sums"]:
            _finish(entry, ranks, LINK_FAIL, "upstream digest-list != the sha256sums the link sealed")
            continue
        entry["upstream_capability"] = _sealed_capability(up)
        verdict = (_consumed_verdict(link, up, own_inputs, citing_cv) or _structural_verdict(link, up)
                   or _consumes_verdict(citing_cap, up, allowed))
        if verdict is not None:
            _finish(entry, ranks, *verdict)
            continue
        signer_hex = (rep["signer"] or "").removeprefix("ed25519:")
        if rep["origin_ok"]:
            _finish(entry, ranks, LINK_VERIFIED, "integrity + origin; consumed value matches on both ends")
        else:
            _finish(entry, ranks, LINK_INTEGRITY_ONLY,
                    (f"untampered, but signed by {key_label(signer_hex)} -- origin NOT established; a "
                     "production-signed downstream does not launder it"))
        if rep["chain"] == "unknown":
            _note(report, state, f"upstream {target} has its provenance withheld: its own derived_from "
                                 "links (if any) are invisible, so the chain beyond it is unknown")
            ranks.append(_LINK_RANK[LINK_CONSUMED_UNVERIFIABLE])
        elif rep["chain"] == "declared-unwalked" and target not in state["walked"]:
            state["walked"].add(target)
            _walk(up, target, depth + 1, path | {target}, resolve, report, ranks, state, max_depth,
                  max_visited, consumes_of, profile)
