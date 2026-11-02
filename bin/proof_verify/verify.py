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

import copy
import hashlib
import hmac
import json
import math
import re
import sys
from decimal import Decimal
from typing import Any


def safe_text(text: Any) -> str:
    """Make text safe to print on a terminal: printable ASCII and newlines pass through, every other character
    (ESC and every control character, DEL, every non-ASCII character such as a look-alike letter or a direction
    mark) is written as a Python-style escape (``\\x1b``, ``\\u202e``, ``\\U0001f600``). A fixed rule, not
    ``str.isprintable()``, so the same bundle prints the same text on every Python. The JSON outputs never need it:
    ``json.dumps`` already escapes every non-ASCII character."""
    out = []
    for ch in str(text):
        if " " <= ch <= "~" or ch == "\n":
            out.append(ch)
            continue
        o = ord(ch)
        out.append(f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}")
    return "".join(out)


class _SafeStream:
    """A text stream that passes everything written to it through `safe_text` (see `safe_terminal_output`)."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, s: str) -> int:
        return self._stream.write(safe_text(s))

    def __getattr__(self, name):
        return getattr(self._stream, name)


class safe_terminal_output:  # a context manager, named in lower case like contextlib's helpers
    """Context manager: while active, ``sys.stdout`` and ``sys.stderr`` escape everything printed through them with
    `safe_text`. The text-mode CLIs print bundle-derived strings (problem lists, link details, capability names);
    a bundle must never be able to send a terminal escape sequence (clear the screen, recolour, forge an "OK"
    line). Disabled (``enabled=False``) it changes nothing, for the JSON modes."""

    def __init__(self, enabled: bool = True):
        self._enabled = enabled
        self._saved = None

    def __enter__(self):
        if self._enabled:
            self._saved = (sys.stdout, sys.stderr)
            sys.stdout, sys.stderr = _SafeStream(sys.stdout), _SafeStream(sys.stderr)
        return self

    def __exit__(self, *exc):
        if self._saved is not None:
            sys.stdout, sys.stderr = self._saved
            self._saved = None
        return False

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


#: Origin problem for a profile whose pin is present but not 64 lowercase hex. A malformed pin can never be
#: a trust root, so it fails origin closed (integrity is unaffected), on every path that reads the pin.
_MALFORMED_PIN_PROBLEM = "profile pinned_pubkey is not 64 lowercase hex; origin cannot be established"


def _profile_pin(profile):
    """The profile's origin pin as ``(pin, malformed)``. ``(None, False)``: no profile pin (use the module pin).
    ``(pin, False)``: a well-formed pin. ``(None, True)``: a pin is present but malformed (an empty string, a
    non-string, upper-case hex...). A duck-typed profile is not validated by ``Profile.__post_init__``, so the
    verifier checks the shape itself; every reader of the pin goes through here so they cannot disagree."""
    pin = _profile_value(profile, "pinned_pubkey", None)
    if pin is None:
        return None, False
    if isinstance(pin, str) and _PUBKEY_HEX_RE.fullmatch(pin):
        return pin, False
    return None, True


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


# --- pin sets and the receiver policy's pin input (SPEC v4 draft 7.11, 7.12, 13.4.1) --------------------------
# SPEC 7.12: "A verifier is configured with a **pin set**: the `pins` array of the effective receiver policy
# (13.4.1). Each entry is a closed object with **exactly one** of: `key_id`, per 7.11; or `legacy_raw_key`, 64
# lowercase hex characters ... plus `demo` (boolean, REQUIRED) and `label` (OPTIONAL restricted text, 1 to 256 code
# points, shown only, never compared)." The same semantics as kernel-js `_resolvePins` (its MR !16).

class PolicyError(ValueError):
    """A malformed receiver policy or pin set. SPEC 13.4.1: "A verifier MUST refuse a malformed policy: the library
    raises an error, and the CLI exits 2 with no verdict. It MUST NOT fall back to the default policy." ``kind`` is
    the runner protocol v2 error kind (13.3, ``expect_error: "policy"``)."""

    kind = "policy"


class PolicyUnsupportedError(PolicyError):
    """A WELL-FORMED receiver policy member this release does not evaluate (any value other than its default).
    Refused rather than ignored, so a caller who sets one never believes it ran; a distinct kind from a malformed
    policy (``policy``). Full policy evaluation (quorum, suites, aging, roles, TSAs, archive) comes in later releases."""

    kind = "policy_unsupported"


#: SIG-25: "A key id MUST match `[a-z0-9][a-z0-9.+\-]{0,31}:sha256:[0-9a-f]{64}`". The three-part form also refuses
#: a bare `alg:<hex>` string (SIG-26: "v4 policy input MUST NOT accept a bare `alg:<hex>` string as a key id").
_KEY_ID_RE = re.compile(r"[a-z0-9][a-z0-9.+\-]{0,31}:sha256:[0-9a-f]{64}", re.ASCII)
_PIN_KEYS = frozenset({"key_id", "legacy_raw_key", "demo", "label"})
_MAX_PINS = 64                                   # 13.4.1: "array of 0 to 64 pin objects"
POLICY_SCHEMA = "evidence.receiver-policy.v1"


def key_id(alg: str, public_key_hex: str) -> str:
    """SPEC 7.11: ``key_id = alg || ":sha256:" || lowerhex(SHA-256(public_key bytes))``."""
    return f"{alg}:sha256:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


#: The demo key's id (SPEC section 2: "key id `ed25519:sha256:7cb4fd86...`"). The P-256 demo key joins this set when
#: section 2 names its value (SIG-28: "The P-256 part takes effect when the P-256 demo key is written into section 2").
DEMO_KEY_ID = key_id("ed25519", _DEMO_PUBKEY)
_DEMO_KEY_IDS = frozenset({DEMO_KEY_ID})

#: SPEC 2.2: the frozen DICP-18 table (Unicode 18.0.0 Default_Ignorable_Code_Point, 27 ranges, 4,174 code points).
#: Rule 1: "An implementation MUST test DICP-18 membership against exactly this table. It MUST NOT consult its
#: runtime's Unicode tables".
_DICP18 = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180D), (0x180E, 0x180E), (0x180F, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x2064), (0x2065, 0x2065), (0x2066, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0000), (0xE0001, 0xE0001), (0xE0002, 0xE001F), (0xE0020, 0xE007F), (0xE0080, 0xE00FF),
    (0xE0100, 0xE01EF), (0xE01F0, 0xE0FFF),
)


def _forbidden_code_point(cp: int) -> bool:
    """The forbidden set F of SPEC 2.2: Cc (U+0000-001F, U+007F-009F), the surrogates U+D800-DFFF, and DICP-18."""
    if cp <= 0x1F or 0x7F <= cp <= 0x9F or 0xD800 <= cp <= 0xDFFF:
        return True
    return any(lo <= cp <= hi for lo, hi in _DICP18)


def is_restricted_text(s: Any, min_len: int, max_len: int) -> bool:
    """Restricted text (SPEC 2.2): a string with no code point of F, ``min_len`` to ``max_len`` code points long.
    Rule 4: "Restricted text is never normalized"; this reads the code points exactly as given."""
    return (isinstance(s, str) and min_len <= len(s) <= max_len
            and not any(_forbidden_code_point(ord(ch)) for ch in s))


def _pin_entry(pin: Any, where: str) -> tuple[str, bool]:
    """One pin object -> ``(key id, demo flag as stated)``. Raises PolicyError on any breach of 7.12 (SIG-27: "A pin
    entry that breaks this shape MUST make the policy malformed")."""
    if not isinstance(pin, dict):
        raise PolicyError(f"{where} must be a JSON object")
    unknown = sorted(set(pin) - _PIN_KEYS)
    if unknown:
        raise PolicyError(f"{where} has unknown key(s) {unknown}")
    if ("key_id" in pin) == ("legacy_raw_key" in pin):
        raise PolicyError(f"{where} must have exactly one of key_id or legacy_raw_key")
    if "key_id" in pin:
        kid = pin["key_id"]
        if not (isinstance(kid, str) and _KEY_ID_RE.fullmatch(kid)):
            raise PolicyError(f"{where}.key_id is not a key id of the form <alg>:sha256:<64 lowercase hex> "
                              "(SIG-25, SIG-26)")
    else:
        raw = pin["legacy_raw_key"]
        if not (isinstance(raw, str) and _PUBKEY_HEX_RE.fullmatch(raw)):
            raise PolicyError(f"{where}.legacy_raw_key must be 64 lowercase hex characters")
        kid = key_id("ed25519", raw)      # 13.4.1: "`legacy_raw_key` is turned into ed25519:sha256:<SHA-256 ...>"
    if not isinstance(pin.get("demo"), bool):
        raise PolicyError(f"{where}.demo is required and must be a boolean")
    if "label" in pin and not is_restricted_text(pin["label"], 1, 256):
        raise PolicyError(f"{where}.label must be restricted text of 1 to 256 code points (SPEC 2.2)")
    return kid, pin["demo"]


def resolve_pins(pins: Any, *, where: str = "pins", duplicates: str = "merge",
                 into: dict[str, bool] | None = None, labels: dict[str, str] | None = None) -> dict[str, bool]:
    """Resolve a list of pin objects to a pin set: a dict from key id to the pin's EFFECTIVE demo flag.

    - SIG-28: "Every demo key (section 2) MUST be treated as a demo pin whatever its entry's `demo` value says".
    - ``duplicates="merge"`` (pins added from outside a policy file, e.g. the ``pins=`` argument): SPEC 7.12 "a merged
      pin whose key id is already present is one pin, and if either is marked demo, the pin is a demo pin".
    - ``duplicates="refuse"`` (the ``pins`` of one policy file): SPEC 7.12 "Within one policy file, two pin entries
      with the same key id make the policy malformed".
    ``into`` is an existing pin set to merge into (always with the demo-wins rule). Raises PolicyError."""
    if not isinstance(pins, list):
        raise PolicyError(f"{where} must be an array of pin objects")
    if len(pins) > _MAX_PINS:
        raise PolicyError(f"{where} has {len(pins)} entries (at most {_MAX_PINS})")
    out = dict(into or {})
    seen: set[str] = set()
    for i, pin in enumerate(pins):
        kid, demo = _pin_entry(pin, f"{where}[{i}]")
        if duplicates == "refuse" and kid in seen:
            raise PolicyError(f"{where}[{i}] repeats key id {kid} (SPEC 7.12: malformed within one policy file)")
        seen.add(kid)
        out[kid] = out.get(kid, False) or demo or kid in _DEMO_KEY_IDS
        if labels is not None and "label" in pin:
            labels.setdefault(kid, pin["label"])     # shown only, never compared (7.12); the first label is kept
    return out


#: The members of the receiver policy (SPEC 13.4.1) with their defaults. This release implements `schema` and
#: `pins`; every other member is accepted only AT ITS DEFAULT (where it changes nothing), and a non-default value is
#: refused rather than ignored, so a caller who sets one never believes it ran. Quorum, required suites and aging
#: (7.13) arrive with co-signatures; sign-offs, time and archive in later releases.
_POLICY_DEFAULTS: dict[str, Any] = {
    "origin_quorum": 1, "require_seal_suites": [], "min_envelope": "v3", "suites": {}, "hashes": {}, "tsas": [],
    "min_seal_tsas": 0, "require_archive": False, "min_archive_tsas": 1, "roster": [], "require_roles": [],
    "require_order": True, "require_signoff_timestamps": False, "allow_self_verify": False, "originator_keys": [],
    "originator_signer_ids": [], "max_attest_lag_s": 86400, "allow_ess_v1": False,
}


def _same_json(a: Any, b: Any) -> bool:
    """Equality on the parsed value model (SPEC 4.3): `true` is never 1, and an int equals a whole double only where
    the field is a JSON integer (``origin_quorum`` 1.0 is 1). Used only to test 'is this member at its default'."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same_json(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same_json(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _json_int(v: Any, lo: int, hi: int) -> bool:
    # section 2 "JSON integer": an integer or a whole double, never a boolean. The int is compared directly:
    # `math.isfinite` / `float()` raise OverflowError on an integer of a few hundred digits, which must be a
    # malformed policy (exit 2), never a traceback.
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return lo <= v <= hi
    return isinstance(v, float) and math.isfinite(v) and v.is_integer() and lo <= v <= hi


_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)
_ROLE_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{0,63}", re.ASCII)
_SIGNER_ID_RE = re.compile(r"[!-~]{1,256}", re.ASCII)


def _utc_or_null(v: Any) -> bool:
    """SPEC 2.3: a UTC timestamp (a real instant, no leap second), or null."""
    if v is None:
        return True
    if not (isinstance(v, str) and _UTC_RE.fullmatch(v)):
        return False
    import calendar
    y, mo, d, h, mi, se = int(v[0:4]), int(v[5:7]), int(v[8:10]), int(v[11:13]), int(v[14:16]), int(v[17:19])
    return (1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] if y >= 1 else False) \
        and h <= 23 and mi <= 59 and se <= 59


def _trust_map(v: Any, keys=None) -> bool:
    return isinstance(v, dict) and all(
        isinstance(k, str) and (k in keys if keys else _ALG_TOKEN_RE.fullmatch(k) is not None)
        and isinstance(e, dict) and set(e) == {"trusted_until"} and _utc_or_null(e["trusted_until"])
        for k, e in v.items())


def _str_list(v: Any, n: int, pattern=None, unique: bool = True) -> bool:
    return (isinstance(v, list) and len(v) <= n and all(isinstance(x, str) for x in v)
            and (not unique or len(set(v)) == len(v))
            and (pattern is None or all(pattern.fullmatch(x) for x in v)))


#: SPEC 13.4.1: the TYPE and range of each member (a breach makes the policy malformed). Members whose inner object
#: shapes belong to later phases (`tsas`, `roster`) are checked here only as arrays of objects of the right length.
_POLICY_SHAPES = {
    "origin_quorum": lambda v: _json_int(v, 1, 8),
    "require_seal_suites": lambda v: _str_list(v, 8, _ALG_TOKEN_RE),
    "min_envelope": lambda v: isinstance(v, str) and v in ("v3", "v4"),
    "suites": lambda v: _trust_map(v),
    "hashes": lambda v: _trust_map(v, ("sha256", "sha384", "sha512")),
    "tsas": lambda v: isinstance(v, list) and len(v) <= 16 and all(isinstance(x, dict) for x in v),
    "min_seal_tsas": lambda v: _json_int(v, 0, 16),
    "require_archive": lambda v: isinstance(v, bool),
    "min_archive_tsas": lambda v: _json_int(v, 1, 4),
    "roster": lambda v: isinstance(v, list) and len(v) <= 1024 and all(isinstance(x, dict) for x in v),
    "require_roles": lambda v: _str_list(v, 16, _ROLE_RE, unique=False),
    "require_order": lambda v: isinstance(v, bool),
    "require_signoff_timestamps": lambda v: isinstance(v, bool),
    "allow_self_verify": lambda v: isinstance(v, bool),
    "originator_keys": lambda v: _str_list(v, 64, _KEY_ID_RE),
    "originator_signer_ids": lambda v: _str_list(v, 64, _SIGNER_ID_RE),
    "max_attest_lag_s": lambda v: _json_int(v, 0, 31_622_400),
    "allow_ess_v1": lambda v: isinstance(v, bool),
}
#: The members whose type is "JSON integer" (SPEC 2): a whole double such as `1.0` is the same value as `1`, so it is
#: normalized to the integer before the policy is hashed (13.4.1: policies with the same meaning have the same digest).
_POLICY_INT_MEMBERS = frozenset({"origin_quorum", "min_seal_tsas", "min_archive_tsas", "max_attest_lag_s"})
#: Members this release EVALUATES at a non-default value (13.4.3 row 2). Every other member is accepted only at its
#: default; a well-formed other value raises PolicyUnsupportedError (a limitation of this release, see CHANGELOG).
_POLICY_EVALUATED = frozenset({"min_envelope"})


def _policy_members(policy: Any) -> dict[str, Any]:
    """Validate a receiver policy object (SPEC 13.4.1) and return its members with defaults filled in (step 1).
    Raises PolicyError for a malformed policy ("An unknown key, a wrong type, a value out of range or a breach of a
    uniqueness rule makes the policy **malformed**") and PolicyUnsupportedError for a well-formed member this
    release does not evaluate."""
    if not isinstance(policy, dict):
        raise PolicyError("a receiver policy must be a JSON object")
    if policy.get("schema") != POLICY_SCHEMA:
        raise PolicyError(f"policy schema must be {POLICY_SCHEMA!r} (got {policy.get('schema')!r})")
    unknown = sorted(set(policy) - {"schema", "pins"} - set(_POLICY_DEFAULTS))
    if unknown:
        raise PolicyError(f"policy has unknown key(s) {unknown}")
    for k in sorted(set(policy) & set(_POLICY_DEFAULTS)):
        if not _POLICY_SHAPES[k](policy[k]):
            raise PolicyError(f"policy member {k!r} has a wrong type or a value out of range: {policy[k]!r}")
    for k in sorted(set(policy) & set(_POLICY_DEFAULTS) - _POLICY_EVALUATED):
        if not _same_json(policy[k], _POLICY_DEFAULTS[k]):
            raise PolicyUnsupportedError(
                f"policy member {k!r} is well-formed but not evaluated by this release except at its default "
                f"{_POLICY_DEFAULTS[k]!r}; it is refused rather than ignored")
    given = {k: (int(policy[k]) if k in _POLICY_INT_MEMBERS else policy[k]) for k in _POLICY_DEFAULTS if k in policy}
    return {**_POLICY_DEFAULTS, **given}


def policy_pins(policy: Any) -> dict[str, bool]:
    """Validate a receiver policy object and return its resolved pin set. Raises PolicyError (or
    PolicyUnsupportedError, see `_policy_members`)."""
    _policy_members(policy)
    return resolve_pins(policy.get("pins", []), where="policy.pins", duplicates="refuse")


def effective_policy(policy: Any = None, pins: Any = None) -> tuple[dict[str, bool] | None, dict]:
    """SPEC 13.4.1 "Effective policy": (the effective pin set, or None on the single-pin v3 path when neither
    argument is given; the normalized members WITHOUT the pins). Steps 1-4: defaults filled in, legacy_raw_key
    turned into key_id, caller pins merged with the demo-wins rule, demo flags made effective."""
    members = _policy_members(policy) if policy is not None else dict(_POLICY_DEFAULTS)
    labels: dict[str, str] = {}
    members["_labels"] = labels
    if policy is None and pins is None:
        return None, members
    out = (resolve_pins(policy.get("pins", []), where="policy.pins", duplicates="refuse", labels=labels)
           if policy is not None else {})
    if pins is not None:
        out = resolve_pins(pins, where="pins", duplicates="merge", into=out, labels=labels)
    return out, members


def effective_pins(policy: Any = None, pins: Any = None) -> dict[str, bool] | None:
    """The effective pin set (SPEC 13.4.1 steps 2-4). None when neither argument is given."""
    return effective_policy(policy, pins)[0]


def policy_sha256(members: dict, pin_set: dict[str, bool]) -> str:
    """SPEC 13.4.1: ``policy_sha256 = digest(canon_1(effective policy))`` after step 5 (null trust entries dropped;
    pins sorted by key_id; the string lists sorted by code point; a pin's label kept only when present)."""
    labels = members.get("_labels", {})
    eff = {k: copy.deepcopy(v) for k, v in members.items() if k != "_labels"}
    eff["schema"] = POLICY_SCHEMA
    for m in ("suites", "hashes"):
        eff[m] = {k: e for k, e in eff[m].items() if e.get("trusted_until") is not None}
    for m in ("require_seal_suites", "originator_keys", "originator_signer_ids", "require_roles"):
        eff[m] = sorted(eff[m])
    eff["pins"] = [{"key_id": k, "demo": pin_set[k], **({"label": labels[k]} if k in labels else {})}
                   for k in sorted(pin_set)]
    return _sha(_canon(eff))


def _verdict_pins(rep: dict) -> dict[str, bool] | None:
    """The effective pin set a verdict was made under, as it reports it (`pin_set`, or the single pin)."""
    ps = rep.get("pin_set")
    if isinstance(ps, list):
        return {e["key_id"]: bool(e["demo"]) for e in ps if isinstance(e, dict) and "key_id" in e and "demo" in e}
    pk = rep.get("pinned_key")
    if isinstance(pk, str) and pk.startswith("ed25519:"):
        return {key_id("ed25519", pk.removeprefix("ed25519:")): bool(rep.get("pinned_key_is_demo"))}
    return None


def evaluate(rep: dict, members: dict, pin_set: dict[str, bool] | None = None) -> list[str]:
    """SPEC 13.4.3, the reason codes in table order, for the rows this release can evaluate. Rows 4-12 read v2
    sign-off entries, rows 15 and 18 TSA and archive evaluation: they cannot apply until those blocks are checked,
    and a PRESENT unchecked block already rejects through rows 3, 14 and 17 (see `_dims`).

    13.4.2: "`verdict` MUST have been produced under the same effective policy ... If the hashes differ, `evaluate`
    MUST refuse (an error, not a decision)". A verdict records its `policy_sha256`; ``members`` (with ``pin_set``,
    or the verdict's own pins when it is None) must hash to it, else PolicyError is raised."""
    recorded = rep.get("policy_sha256")
    if recorded is None and isinstance(rep.get("decision"), dict):
        recorded = rep["decision"].get("policy_sha256")
    if recorded is not None:
        pins = pin_set if pin_set is not None else _verdict_pins(rep)
        if pins is None or policy_sha256(members, pins) != recorded:
            raise PolicyError("evaluate: the verdict was made under a different policy "
                              f"(its policy_sha256 is {_shown(recorded)}); re-verify under this policy instead")
    reasons = []
    if rep["state"] != STATE_VERIFIED:
        reasons.append("state_not_accepted")
    if members.get("min_envelope") == "v4" and rep.get("canon_version") in (1, 2):
        reasons.append("envelope_below_minimum")
    dims = rep.get("dims", {})
    if dims.get("signoffs") == "invalid":
        reasons.append("signoffs_invalid")
    if dims.get("time") == "invalid":
        reasons.append("time_invalid")
    if dims.get("time") == "malformed":
        reasons.append("time_malformed")
    if dims.get("archive") == "broken":
        reasons.append("archive_broken")
    if dims.get("archive") == "malformed":
        reasons.append("archive_malformed")
    return reasons


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
#: Every character JCS escapes: the C0 controls, '"', '\\', and (lone) surrogates. Everything else is written raw.
_V2_MUST_ESCAPE = re.compile(r'[\x00-\x1f"\\\ud800-\udfff]')
#: What is left to escape once '\\', '"', '\n', '\r' and '\t' are done: the other C0 controls and surrogates.
_V2_RARE_ESCAPE = re.compile(r"[\x00-\x1f\ud800-\udfff]")


def _v2_escape_rare(m: re.Match) -> str:
    c = ord(m.group())
    esc = _V2_SHORT_ESCAPE.get(c)                 # \b \f; the rest -> lowercase \uXXXX (C0 control or surrogate)
    return esc if esc is not None else f"\\u{c:04x}"


def _v2_string(s: str) -> str:
    # JCS / ECMAScript JSON.stringify escaping: the short forms for \b \t \n \f \r " \, lowercase \uXXXX for the
    # other C0 controls and lone surrogates, every other character raw (all other non-ASCII, astral scalars). One
    # C-level scan finds whether anything needs escaping; most strings need nothing and are copied whole.
    if _V2_MUST_ESCAPE.search(s) is None:
        return '"' + s + '"'
    # '\\' first, so no backslash an escape writes is doubled; the escapes written are printable ASCII, so the
    # final pass (rare characters) never sees one.
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    if _V2_RARE_ESCAPE.search(s) is not None:
        s = _V2_RARE_ESCAPE.sub(_v2_escape_rare, s)
    return '"' + s + '"'


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
    if type(n) is float:
        # Fast path: repr() writes the shortest round-trip digits in positional form exactly when the decimal
        # exponent is in [-4, 16), a sub-range of ECMAScript's positional range (-7, 21), where the ES form is the
        # same text except a whole value ("2.0" in repr, "2" in ES). Exponent-form reprs take the general path.
        r = repr(n)
        if "e" not in r:
            return r.removesuffix(".0")
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


def _v2_utf16(kv: tuple) -> bytes:
    return kv[0].encode("utf-16-be", "surrogatepass")


def _v2_into(obj: Any, out: list) -> None:
    # Appends the JCS text of `obj` to `out` (joined once by `_v2_emit`), so no container's text is copied into
    # its parent's string level by level. Exact types first (what json.loads builds); subclasses take the
    # isinstance branches after them.
    t = type(obj)
    if t is str:
        out.append(_v2_string(obj))
        return
    if t is dict:
        if all(type(k) is str and k.isascii() for k in obj):
            # ASCII keys sort the same by code point as by UTF-16 code unit (and are distinct): plain sort
            items = [(k, obj[k]) for k in sorted(obj)]
        else:
            items = sorted(obj.items(), key=_v2_utf16)
    elif t is list:
        items = None
    elif t is int and -_JS_SAFE_INT <= obj <= _JS_SAFE_INT:
        out.append(str(obj))
        return
    elif t is float:
        out.append(_v2_number(obj))
        return
    elif obj is None:
        out.append("null")
        return
    elif obj is True:
        out.append("true")
        return
    elif obj is False:
        out.append("false")
        return
    elif isinstance(obj, str):
        out.append(_v2_string(obj))
        return
    elif isinstance(obj, (int, float)):
        out.append(_v2_number(obj))
        return
    elif isinstance(obj, (list, tuple)):
        items = None
    elif isinstance(obj, dict):
        items = sorted(obj.items(), key=_v2_utf16)
    else:
        raise TypeError(f"not a JSON value: {type(obj).__name__}")
    mark = len(out)
    if items is None:                             # an array: each element then ",", the last "," -> "]"
        out.append("[")
        for v in obj:
            _v2_into(v, out)
            out.append(",")
        close = "]"
    else:                                         # an object, members in JCS order
        out.append("{")
        for k, v in items:
            out.append(_v2_string(k))
            out.append(":")
            _v2_into(v, out)
            out.append(",")
        close = "}"
    if len(out) == mark + 1:                      # empty: "[" -> "[]" / "{" -> "{}"
        out.append(close)
    else:
        out[-1] = close


def _v2_emit(obj: Any) -> str:
    out: list[str] = []
    _v2_into(obj, out)
    return "".join(out)


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


# --- canon_version 3: canon_2 over the projection T (SPEC v4 draft 5.6, 6.6) ----------------------------------
# SPEC 5.6.1: "canon_3(x) = canon_2(T(x))". T maps both forms of a committed item to the same projected form
# {"$committed": 1, "commitment": C, "marks": M}, so withholding an item changes no digest, header or seal. T is
# undefined when an item breaks a form or field rule (6.6.1, 6.6.2); then canon_3 is undefined, which "MUST fail the
# check that needed it. It MUST NOT crash the verifier" -- here it raises ValueError, which `_try_canon` turns into a
# problem. Placement, the item cap and the path cap are rules of the item walk (`_v4_item_walk`), not of T (5.6.2
# item 1: "T depends only on the value it is given").
_COMMITTED = "$committed"
#: 6.6.3: "tag = the 26 ASCII bytes "evidence.committed-item.v1"", then a NUL, then canon_2(value).
_ITEM_TAG = b"evidence.committed-item.v1"
_ITEM_DISCLOSED_KEYS = frozenset({_COMMITTED, "marks", "salt", "value"})
_ITEM_WITHHELD_KEYS = frozenset({_COMMITTED, "commitment", "marks"})
_SALT_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_COMMITMENT_RE = re.compile(r"hmac-sha256:[0-9a-f]{64}", re.ASCII)
_MARK_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{0,63}", re.ASCII)
_MAX_MARKS = 16
_MAX_ITEMS = 16_384                 # 6.6.6 P6: "At most 16,384 items per bundle"
_MAX_ITEM_PATH = 1024               # 6.6.5 item 2: "An item path MUST be at most 1,024 code points"


def commit(salt_hex: str, value: Any) -> str:
    """SPEC 6.6.3: ``"hmac-sha256:" || lowerhex(HMAC-SHA256(key = the 32 salt bytes, tag || 0x00 || canon_2(value)))``.
    The salt must already be 64 lowercase hex (checked as a string before decoding). Raises ValueError when canon_2
    cannot encode the value."""
    msg = _ITEM_TAG + b"\x00" + _canon_v2(value)
    return "hmac-sha256:" + hmac.new(bytes.fromhex(salt_hex), msg, hashlib.sha256).hexdigest()


def _has_committed_member(obj: Any) -> bool:
    """True if an object anywhere in ``obj`` has a member named ``$committed`` (iterative)."""
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if _COMMITTED in cur:
                return True
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
    return False


def item_problems(item: Any) -> list[str]:
    """Every breach of the item form and field rules (SPEC 6.6.1, 6.6.2) by one object that has a ``$committed``
    member; an empty list is a well-formed item. Placement is not checked here (6.6.6)."""
    if not isinstance(item, dict) or _COMMITTED not in item:
        return ["is not an object with a $committed member"]
    problems: list[str] = []
    tag = item[_COMMITTED]
    # 6.6.2: "MUST be an integer literal equal to 1 in the parsed value model of 4.3 ... `true`, `1.0` and `1e0` fail.
    # The check MUST run on the parsed value **before** canonicalization" (canon_2 writes all three as `1`).
    if type(tag) is not int or tag != 1:
        problems.append(f"$committed must be the integer literal 1 (got {tag!r})")
    keys = set(item)
    if keys == _ITEM_DISCLOSED_KEYS:
        salt = item["salt"]
        if not (isinstance(salt, str) and _SALT_RE.fullmatch(salt)):
            problems.append("salt must be exactly 64 lowercase hex characters (32 bytes)")
        if _has_committed_member(item["value"]):
            problems.append("value contains an object member named $committed (no nesting, 6.6.2 / P4)")
        else:
            try:
                _canon_v2(item["value"])
            except (TypeError, ValueError, RecursionError) as exc:
                problems.append(f"value cannot be canonicalized under canon 2 ({exc})")
    elif keys == _ITEM_WITHHELD_KEYS:
        c = item["commitment"]
        if not (isinstance(c, str) and _COMMITMENT_RE.fullmatch(c)):
            problems.append("commitment must match hmac-sha256:[0-9a-f]{64}")
    elif {"salt", "value"} & keys and "commitment" in keys:
        problems.append("carries both the disclosed (salt, value) and the withheld (commitment) form")
    else:
        problems.append(f"key set {sorted(keys)} is neither the disclosed form {sorted(_ITEM_DISCLOSED_KEYS)} nor "
                        f"the withheld form {sorted(_ITEM_WITHHELD_KEYS)}")
    if "marks" in item:
        marks = item["marks"]
        if not (isinstance(marks, list) and all(isinstance(m, str) for m in marks)):
            problems.append("marks must be an array of strings")
        else:
            if len(marks) > _MAX_MARKS:
                problems.append(f"marks has {len(marks)} entries (at most {_MAX_MARKS})")
            bad = [m for m in marks if not _MARK_RE.fullmatch(m)]
            if bad:
                problems.append(f"marks {bad[:3]!r} do not match [a-z0-9][a-z0-9.\\-]{{0,63}}")
            if len(set(marks)) != len(marks):
                problems.append("marks has duplicate entries")
            elif marks != sorted(marks):                     # Python str order IS code point order
                problems.append("marks are not sorted ascending in code point order")
    return problems


def _item_commitment(item: dict) -> str:
    """The projected commitment of a WELL-FORMED item: read from the withheld form, always RECOMPUTED for the
    disclosed form (6.6.3: "MUST NOT read a commitment from a disclosed item")."""
    if "commitment" in item:
        return item["commitment"]
    return commit(item["salt"], item["value"])


def project(obj: Any) -> Any:
    """The projection T of SPEC 5.6.2. Raises ValueError where T is undefined (a malformed item)."""
    if isinstance(obj, dict):
        if _COMMITTED in obj:
            bad = item_problems(obj)
            if bad:
                raise ValueError("committed item is malformed: " + "; ".join(bad))
            return {_COMMITTED: 1, "commitment": _item_commitment(obj), "marks": list(obj["marks"])}
        return {k: project(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [project(v) for v in obj]
    return obj


def _canon_v3(obj: Any) -> bytes:
    # canon_version 3 (SPEC 5.6.1): canon_2 over the projection T.
    return _canon_v2(project(obj))


# --- ADR-050: the version -> canon map (append-only, frozen) ------------------------------------------
#: The REFERENCE canon's output-definition version -> the canon function that produces it. APPEND-ONLY and
#: FROZEN: a future change to what the reference canon EMITS becomes `canon_version = 2` with a NEW `_canon_v2`
#: entry while `1: _canon` is preserved VERBATIM, so every v1 bundle verifies forever. A VERIFIER-port bug
#: (a port disagreeing with the reference for version N) is fixed IN PLACE with NO bump -- that verifier was
#: non-conformant; the format did not move. For v1 the map's canon IS this module's `_canon`.
_CANON = {1: _canon, 2: _canon_v2, 3: _canon_v3}
#: The highest `canon_version` this verifier can apply. A bundle sealed under anything higher is a
#: fail-FORWARD (`STATE_UNSUPPORTED_CANON`), never an integrity failure.
_CANON_SUPPORTED_MAX = max(_CANON)

#: The exact set of top-level keys the envelope allows. Anything else rides UNSIGNED (the seal commits
#: only to `sha256sums`), so a rendering UI must never show it. This membership test is canon-INDEPENDENT
#: (pure key-set), so the fail-FORWARD branch applies it too, even though it leaves the newer bundle's
#: sections to a newer verifier. ADR-049: `host` is RETIRED -- a stapled host block fails this allowlist.
_ALLOWED_TOP = frozenset({"schema", "result", "reproducibility", "manifest", "sha256sums",
                          "bundle_sha256", "signature", "redaction", "timestamp", "attestations"})
#: SPEC v4 draft 3.4: the twelve top-level keys of an `evidence.envelope.v4` bundle (v3's singular `timestamp` and
#: the legacy `host` are not among them).
_ALLOWED_TOP_V4 = frozenset({"schema", "manifest", "sha256sums", "bundle_sha256", "signature", "signatures", "result",
                             "reproducibility", "redaction", "timestamps", "attestations", "archive"})
#: SPEC v4 draft 11.6 step 3: the newer-canon branch checks the top-level keys "against the **union** of the v3 and
#: v4 sets ... The branch trusts no section-level field, so `schema` does not select the set."
_ALLOWED_TOP_UNION = _ALLOWED_TOP | _ALLOWED_TOP_V4


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
    # Iterative, with parent links: a path string is built only for a hit, never per node (a long key above a long
    # array would otherwise cost key length x array length to walk).
    if isinstance(obj, float):
        return [] if math.isfinite(obj) else [path]
    if not isinstance(obj, (dict, list, tuple)):
        return []
    out: list[str] = []

    def spell(chain: Any) -> str:
        parts = []
        while chain is not None:
            chain, tok = chain
            parts.append(f"[{tok}]" if isinstance(tok, int) else f".{tok}")
        return path + "".join(reversed(parts))

    stack = [(_children(obj), None)]
    while stack:
        it, chain = stack[-1]
        nxt = next(it, _END)
        if nxt is _END:
            stack.pop()
            continue
        tok, v = nxt
        if isinstance(v, float):
            if not math.isfinite(v):
                out.append(spell((chain, tok)))
        elif isinstance(v, (dict, list, tuple)):
            stack.append((_children(v), (chain, tok)))
    return out


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
    # One iterator per nesting level (memory proportional to depth, not to the number of nodes); a scalar child
    # counts as one more level, as before.
    if limit < 1:
        return True
    if not isinstance(obj, (dict, list, tuple)):
        return False
    stack = [iter(obj.values() if isinstance(obj, dict) else obj)]
    while stack:
        nxt = next(stack[-1], _END)
        if nxt is _END:
            stack.pop()
            continue
        if len(stack) + 1 > limit:          # the child sits at depth len(stack) + 1
            return True
        if isinstance(nxt, dict):
            stack.append(iter(nxt.values()))
        elif isinstance(nxt, (list, tuple)):
            stack.append(iter(nxt))
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


def _parse_finite_float(literal: str) -> float:
    """parse_float hook: a number literal with a fraction or exponent, read as an IEEE-754 binary64 double.

    SPEC (evidence.envelope.v4 draft) 4.2 item 9, "(Changed in v4, for every version.)": "A number literal that
    is finite as written but overflows an IEEE-754 binary64 double (for example `1e400`) MUST make the input
    **unreadable**. This holds on every path: canon 1, 2 or 3, and the newer-canon branch." This resolves open
    issue 17.2.1: before it, Python's json read `1e400` as infinity and the bundle failed later as a non-finite
    value (label `fail`) on the normal path, or read as `unsupported-canon` on the newer-canon branch, while the
    JavaScript reference refused it at parse time. Refusing it HERE makes it unreadable on every path, in both
    references. Underflow (`1e-400` -> 0.0) is finite and is not affected; integer literals (no `.`, no
    exponent) never reach this hook (they are integers, capped by `_parse_bounded_int`)."""
    value = float(literal)
    if math.isinf(value):
        raise ValueError(f"number literal {literal[:40]!r} overflows an IEEE-754 double (finite as written, "
                         "infinite when read; SPEC 4.2 item 9: unreadable)")
    return value


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
    NaN/Infinity (not RFC 8259 JSON), and a number literal that overflows a double (`1e400`, SPEC 4.2
    item 9). Any reader that bypasses this -- a plain ``json.loads`` in
    conformance, the lineage index, reproduce/certify -- could attest or re-derive a bundle this
    authoritative verifier would refuse to even parse, so they all route through here."""
    nbytes = len(text) if len(text) > _MAX_BUNDLE_BYTES else len(text.encode("utf-8", "surrogatepass"))
    if nbytes > _MAX_BUNDLE_BYTES:
        raise ValueError(f"bundle text is {nbytes} UTF-8 bytes (> {_MAX_BUNDLE_BYTES} cap; rejected)")
    if not _text_depth_ok(text):
        raise ValueError(f"JSON nesting exceeds {_MAX_JSON_DEPTH} levels (rejected fail-closed)")
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_non_finite,
                      parse_int=_parse_bounded_int, parse_float=_parse_finite_float)


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


# Scalar multiplication runs in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z (RFC 8032
# 5.1.4), so no addition or doubling needs a modular inverse; the one inverse is paid in `_affine` when the
# multiple is compared. The affine `_add` above costs two inverses per addition (~200 ms a verify). Unified
# addition "add-2008-hwcd-3" (complete on Ed25519) and doubling "dbl-2008-hwcd", as RFC 8032 gives them.
# Written for this verifier alone; it shares no code or imports with proof_core.signing. That is code
# independence, NOT independent derivation: both files transcribe the same RFC formulas, so a typo made in
# both would agree with itself. The real independent reference is the RFC 8032 known-answer vectors and the
# OpenSSL (`cryptography`) cross-check in tests/test_ed25519_extended_coords.py.
_D2 = 2 * _D % _Q


def _ext_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = t1 * _D2 * t2 % _Q
    d = z1 * 2 * z2 % _Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _ext_dbl(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = x1 * x1 % _Q
    b = y1 * y1 % _Q
    c = 2 * z1 * z1 % _Q
    h = a + b
    e = h - (x1 + y1) * (x1 + y1) % _Q
    g = a - b
    f = c + g
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _affine(p: tuple[int, int, int, int]) -> tuple[int, int]:
    zinv = pow(p[2], _Q - 2, _Q)
    return (p[0] * zinv % _Q, p[1] * zinv % _Q)


def _mul(p: tuple[int, int], e: int) -> tuple[int, int]:
    # Affine in, affine out: the same point the affine double-and-add returned.
    x, y = p
    acc = (0, 1, 1, 0)
    cur = (x % _Q, y % _Q, 1, x * y % _Q)
    while e > 0:
        if e & 1:
            acc = _ext_add(acc, cur)
        cur = _ext_dbl(cur)
        e >>= 1
    return _affine(acc)


# [2^i]B for i = 0..252, so [e]B is additions only. B has prime order L, so [e]B == [e mod L]B.
_BASE_DOUBLINGS = [(_BASE[0], _BASE[1], 1, _BASE[0] * _BASE[1] % _Q)]
while len(_BASE_DOUBLINGS) < 253:
    _BASE_DOUBLINGS.append(_ext_dbl(_BASE_DOUBLINGS[-1]))


def _mul_base(e: int) -> tuple[int, int]:
    # Same point as _mul(_BASE, e). A negative e gives the identity, as _mul does (its loop never runs);
    # that is checked before the mod-L reduction, which would otherwise give [e mod L]B.
    if e < 0:
        return (0, 1)
    acc = (0, 1, 1, 0)
    e %= _L
    for pt in _BASE_DOUBLINGS:
        if e == 0:
            break
        if e & 1:
            acc = _ext_add(acc, pt)
        e >>= 1
    return _affine(acc)


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
    return _mul_base(s) == _add(r_point, _mul(a_point, k))


def _check_signature(bundle: dict, bundle_sha256: str, problems: list[str],
                     origin_problems: list[str], profile=None, sig_out: dict | None = None,
                     pin_set: dict[str, bool] | None = None, v4_suites: bool = False) -> str | None:
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
        # Canon 3 and newer (`v4_suites`): the v4 suite table (SPEC 7.5). A suite this release does not implement
        # is shape-checked against its row, and for every reserved or unknown token that row is the GENERIC hex
        # row, so a real-size ML-DSA key and signature are `unsupported-alg` (SIG-1, SIG-2, 11.4), consistent with
        # `provenance.seal_signers` (7.9). `ecdsa-p256` is a supported suite in v4 that this release does not
        # implement yet (a declared limitation): it keeps the Ed25519 shapes and so reads `fail`. Canon 1 and 2
        # keep the v3 rule (Ed25519 shapes for any suite), unchanged.
        if v4_suites and isinstance(alg, str) and alg != "ecdsa-p256":
            key_rx, sig_rx = _GENERIC_HEX_RE, _GENERIC_HEX_RE
        else:
            key_rx, sig_rx = _PUBKEY_HEX_RE, _SIGNATURE_HEX_RE
        signer_ok = isinstance(signer_v, str) and key_rx.fullmatch(signer_v) is not None
        sighex_ok = isinstance(sig_hex_v, str) and sig_rx.fullmatch(sig_hex_v) is not None
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
            if key_rx is _GENERIC_HEX_RE:
                if not signer_ok:
                    problems.append("signature public_key does not match the generic hex row of the suite table "
                                    "(SPEC 7.5)")
                if not sighex_ok:
                    problems.append("signature.signature does not match the generic hex row of the suite table "
                                    "(SPEC 7.5)")
            else:
                if not signer_ok:
                    problems.append("signature public_key is not a 32-byte hex Ed25519 key (64 lowercase hex "
                                    "characters)")
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
    if pin_set is not None:
        # SPEC 7.12 (v3 input, E = [signature]): key_matches_pin iff the verified block's key id is in the pin set;
        # the matched pin's EFFECTIVE demo flag decides demo-ness (7.4 "with a pin set of one entry the outcome is
        # exactly the v3 outcome").
        kid = key_id("ed25519", signer)
        if kid not in pin_set:
            origin_problems.append("signature key is not in the pin set")
        elif sig_out is not None:
            sig_out["pin_demo"] = pin_set[kid]
            sig_out["pin_key_id"] = kid
        return signer
    profile_pin, malformed_pin = _profile_pin(profile)
    if malformed_pin:
        origin_problems.append(_MALFORMED_PIN_PROBLEM)
    elif signer != (profile_pin or _PINNED_PUBKEY):
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


def _shown(value: Any) -> str:
    """A bundle-supplied digest field as a problem string shows it: a well-formed digest as is, anything else as a
    bounded ``repr`` (so a control character in a hostile field reaches the problem list escaped, never raw)."""
    if _is_digest(value):
        return value
    r = repr(value)
    return r if len(r) <= 100 else r[:100] + "..."


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


# ====================================================================================================
# The canon-3 path: evidence.envelope.v4 (SPEC v4 draft 12.2). The canon-1/2 path (`_check` below) is the v3
# algorithm, unchanged except for the pairing message of 11.5.
# ====================================================================================================

_ENVELOPE_V4 = "evidence.envelope.v4"
_REDACTION_V2_SCHEMA = "evidence.envelope.redaction.v2"
_REDACTION_V2_KEYS = frozenset({"schema", "parent_bundle_sha256", "withheld_sections", "withheld_items"})
#: 10.4 R2: "`withheld_sections` MUST be an array of distinct strings from {"inputs", "result"}" (provenance cannot
#: be withheld in v4, 6.6.6 P5).
_V4_WITHHOLDABLE = ("inputs", "result")
#: 7.5 suite table: the `public_key` pattern of each row (the generic hex row for reserved and unknown suites).
_SUITE_KEY_RE = {"ed25519": re.compile(r"[0-9a-f]{64}", re.ASCII),
                 "ecdsa-p256": re.compile(r"0[23][0-9a-f]{64}", re.ASCII)}
_GENERIC_HEX_RE = re.compile(r"(?:[0-9a-f]{2}){1,65536}", re.ASCII)
_MAX_SEAL_SIGNERS = 8
#: Advisory note code (6.6.1, 6.6.8): a `$committed` object under canon 1 or 2 is plain data, never an item.
NOTE_COMMITTED_KEY_PLAIN_DATA = "committed_key_plain_data"


def _ptr_token(key: str) -> str:
    """One RFC 6901 reference token: `~` as `~0`, `/` as `~1` (6.6.5 item 1)."""
    return key.replace("~", "~0").replace("/", "~1")


_END = object()


def _children(cur: Any):
    """(token, child) pairs of a container, tokens as the walk keeps them (a str key or an int index)."""
    if isinstance(cur, dict):
        return ((k if isinstance(k, str) else str(k), v) for k, v in cur.items())
    return enumerate(cur)


def _token_len(tok: str | int) -> int:
    """The length of one escaped RFC 6901 reference token, without building it."""
    if isinstance(tok, int):
        return len(str(tok))
    return len(tok) + tok.count("~") + tok.count("/")


def _iter_committed(value: Any):
    """Yield ``(chain, pointer_length, object)`` for every object with a ``$committed`` member in ``value``, in
    document order, without descending into one. ``chain`` is a parent-linked ``(parent_chain, token)`` pair (None for
    ``value`` itself), so no pointer string is built during the walk: the walk holds one iterator per nesting level,
    and memory stays proportional to the depth, never to (key length x number of nodes)."""
    if isinstance(value, dict) and _COMMITTED in value:
        yield None, 0, value
        return
    if not isinstance(value, (dict, list, tuple)):
        return
    stack = [(_children(value), None, 0)]
    while stack:
        it, chain, plen = stack[-1]
        nxt = next(it, _END)
        if nxt is _END:
            stack.pop()
            continue
        tok, v = nxt
        if not isinstance(v, (dict, list, tuple)):
            continue
        node, nlen = (chain, tok), plen + 1 + _token_len(tok)
        if isinstance(v, dict) and _COMMITTED in v:
            yield node, nlen, v
        else:
            stack.append((_children(v), node, nlen))


def _chain_tokens(chain: Any) -> list[str]:
    toks = []
    while chain is not None:
        chain, tok = chain
        toks.append(tok if isinstance(tok, str) else str(tok))
    toks.reverse()
    return toks


def _pointer(prefix: str, toks: list[str], limit: int | None = None) -> str:
    """The JSON pointer ``prefix`` + tokens. With ``limit``, a pointer longer than ``limit`` code points is cut to
    its first ``limit`` code points plus ``"..."`` (so it is never a valid item path and never equals one), and no
    string longer than about ``limit`` is ever built."""
    if limit is None:
        return prefix + "".join("/" + _ptr_token(t) for t in toks)
    out, n = [prefix], len(prefix)
    for t in toks:
        piece = "/" + _ptr_token(t[:limit + 1])
        out.append(piece)
        n += len(piece)
        if n > limit:
            return "".join(out)[:limit] + "..."
    return "".join(out)


def _committed_walk(value: Any, prefix: str = "", *, max_items: int | None = None,
                    max_path: int | None = None) -> tuple[list[tuple[str, list[str], dict, int]], int]:
    """The bounded committed-item walk: ``(found, count)``. ``found`` holds at most ``max_items`` entries
    ``(pointer, tokens, object, true pointer length)`` sorted by pointer; ``count`` is the number of items in
    ``value``. With ``max_path`` a pointer over the limit is truncated (see `_pointer`); its true length is kept."""
    found = []
    count = 0
    for chain, plen, obj in _iter_committed(value):
        count += 1
        if max_items is not None and len(found) >= max_items:
            continue
        toks = _chain_tokens(chain)
        found.append((_pointer(prefix, toks, max_path), toks, obj, len(prefix) + plen))
    found.sort(key=lambda t: t[0])
    return found, count


def committed_objects(value: Any, prefix: str = "") -> list[tuple[str, list[str], dict]]:
    """Every object with a ``$committed`` member in ``value``, as ``(pointer, tokens, object)``; the walk does not
    descend into such an object. Pointers use canonical decimal array indices (6.6.5). Iterative; sorted by pointer
    in code point order. Pointer strings are built only for the items found (never per node)."""
    found, _n = _committed_walk(value, prefix)
    return [(ptr, toks, obj) for ptr, toks, obj, _len in found]


def count_committed(value: Any, *, withheld_only: bool = False) -> int:
    """The number of committed items (or of withheld-form items) in ``value``, without building any pointer."""
    return sum(1 for _c, _l, obj in _iter_committed(value) if not withheld_only or "commitment" in obj)


def _placement_problem(section: str, tokens: list[str], section_value: Any) -> str | None:
    """SPEC 6.6.6 P1-P3: where an item may sit. None when the placement is allowed."""
    if not tokens:
        return "is a section root; whole-section withholding is the mechanism for that (P3)"
    if section == "provenance":
        return "is in provenance, which carries no items in v4 (P2)"
    if section == "inputs":
        # P1: "strictly below `/inputs/inputs/` (so never at `/inputs`, `/inputs/capability` or `/inputs/inputs`)"
        if tokens[0] == "inputs" and len(tokens) >= 2:
            return None
        return "is outside /inputs/inputs/ (P1)"
    # P1: "strictly below `/result/result/<capability>/` ... If `manifest.result.value.result` is not an object, no
    # item may appear below it."
    res = section_value.get("result") if isinstance(section_value, dict) else None
    if tokens[0] == "result" and len(tokens) >= 3 and isinstance(res, dict):
        return None
    if tokens[0] == "result" and not isinstance(res, dict):
        return "is below a result core `result` that is not an object (P1)"
    return "is outside /result/result/<capability>/, in a result-core field the verifier reads or the frontier (P1, P2)"


def _v4_redaction(bundle: dict, problems: list[str], profile) -> tuple[set[str], set[str], bool]:
    """SPEC 10.4 R1, R2, R6. Returns (withheld sections, D, record present)."""
    if "redaction" not in bundle:
        return set(), set(), False
    red = bundle["redaction"]
    if not isinstance(red, dict):
        problems.append(f"redaction is not a JSON object (got {type(red).__name__}); it withholds nothing (R6)")
        return set(), set(), True
    extra = sorted(set(red) - _REDACTION_V2_KEYS)
    if extra:
        problems.append(f"redaction has unexpected keys (unsigned): {extra} (R1)")
    missing = sorted(_REDACTION_V2_KEYS - set(red))
    if missing:
        problems.append(f"redaction is missing required keys: {missing} (R1)")
    want = _profile_value(profile, "redaction_schema_v2", _REDACTION_V2_SCHEMA)
    if red.get("schema") != want:
        problems.append(f"redaction schema is not {want!r}: {red.get('schema')!r} (R1)")
    ws = red.get("withheld_sections")
    sections: set[str] = set()
    ws_ok = (isinstance(ws, list) and all(isinstance(w, str) and w in _V4_WITHHOLDABLE for w in ws)
             and len(set(ws)) == len(ws) and ws == sorted(ws))
    if ws_ok:
        sections = set(ws)
    else:
        # R6: "then **no** section counts as withheld, not even the valid entries of a partly bad list"
        problems.append("redaction.withheld_sections must be a sorted array of distinct sections from "
                        f"{list(_V4_WITHHOLDABLE)}: {ws!r}; no section counts as withheld (R2, R6)")
    wi = red.get("withheld_items")
    declared: set[str] = set()
    wi_ok = isinstance(wi, list) and all(isinstance(w, str) for w in wi)
    if not wi_ok:
        # R6: "If ... `withheld_items` is not an array of strings, then D is empty"
        problems.append("redaction.withheld_items must be an array of strings; no item counts as declared (R6)")
    else:
        declared = set(wi)
        if len(wi) > _MAX_ITEMS:
            problems.append(f"redaction.withheld_items has {len(wi)} entries (at most {_MAX_ITEMS}) (R2)")
        long = [w for w in wi if len(w) > _MAX_ITEM_PATH]
        if long:
            problems.append(f"redaction.withheld_items has {len(long)} path(s) over {_MAX_ITEM_PATH} code points (R2)")
        if len(declared) != len(wi):
            problems.append("redaction.withheld_items has duplicate paths (R2)")
        elif wi != sorted(wi):
            problems.append("redaction.withheld_items is not sorted in code point order (R2)")
    if ws_ok and wi_ok and not ws and not wi:
        problems.append("redaction lists no withheld section and no withheld item; omit the record instead (R2)")
    parent = red.get("parent_bundle_sha256")
    if "parent_bundle_sha256" in red and not _is_digest(parent):
        problems.append(f"redaction.parent_bundle_sha256 is not a well-formed sha256:<64 hex> digest: {parent!r}")
    return sections, declared, True


def _seal_signers_problems(prov_val: dict) -> list[str]:
    """SPEC 7.9 SIG-18, SIG-19: the shape of `provenance.seal_signers` (the full signer-list check against the
    `signatures` array, 7.10 G2, comes with co-signatures; here E is the primary block alone)."""
    if "seal_signers" not in prov_val:
        return ["provenance.seal_signers is required in v4 (SIG-18)"]
    ss = prov_val["seal_signers"]
    if not isinstance(ss, list) or not 1 <= len(ss) <= _MAX_SEAL_SIGNERS:
        return [f"provenance.seal_signers must be an array of 1 to {_MAX_SEAL_SIGNERS} objects (SIG-19)"]
    problems = []
    for i, e in enumerate(ss):
        if not isinstance(e, dict) or set(e) != {"alg", "public_key"}:
            problems.append(f"provenance.seal_signers[{i}] must be an object with exactly the keys alg, public_key")
            continue
        alg, pk = e["alg"], e["public_key"]
        if not (isinstance(alg, str) and _ALG_TOKEN_RE.fullmatch(alg)):
            problems.append(f"provenance.seal_signers[{i}].alg is not a suite token: {alg!r}")
            continue
        rx = _SUITE_KEY_RE.get(alg, _GENERIC_HEX_RE)
        if not (isinstance(pk, str) and rx.fullmatch(pk)):
            problems.append(f"provenance.seal_signers[{i}].public_key does not match the {alg} row of the suite table")
    pairs = [(e.get("alg"), e.get("public_key")) for e in ss if isinstance(e, dict)]
    if not problems and len(set(pairs)) != len(pairs):
        problems.append("provenance.seal_signers has a duplicate (alg, public_key) pair (SIG-19)")
    return problems


def _v4_item_walk(manifest: dict, visible: set[str], problems: list[str]) -> dict:
    """SPEC 12.2 step 10 over the MANIFEST copies of the visible sections: form and fields (6.6.1, 6.6.2), placement
    (P1-P4), path length (6.6.5), the item cap (P6), duplicate salts and commitments (6.6.4). Returns the walk:
    {"items": [(path, item, ok)], "W": set of withheld-form paths}."""
    # Bounded (finding 1 of v0.21.1): at most one item past the P6 cap is kept, and a pointer past the 6.6.5 length
    # limit is kept truncated, so a hostile bundle cannot make the walk hold (pointer length x items) in memory.
    found = []
    count = 0
    for s in _SECTIONS:
        if s not in visible:
            continue
        value = manifest[s]["value"]
        sec_found, n = _committed_walk(value, f"/{s}", max_items=_MAX_ITEMS + 1 - len(found),
                                       max_path=_MAX_ITEM_PATH)
        count += n
        for ptr, toks, obj, plen in sec_found:
            found.append((s, ptr, toks, obj, value, plen))
    if count > _MAX_ITEMS:
        problems.append(f"bundle has {count} committed items (at most {_MAX_ITEMS}, P6)")
    items, withheld = [], set()
    salts: dict[str, str] = {}
    commitments: dict[str, str] = {}
    for s, ptr, toks, obj, value, plen in found:
        bad = item_problems(obj)
        where = f"committed item at {ptr[:80]!r}"
        for b in bad:
            problems.append(f"{where}: {b}")
        place = _placement_problem(s, toks, value)
        if place:
            problems.append(f"{where} {place}")
        if plen > _MAX_ITEM_PATH:
            problems.append(f"{where}: item path is {plen} code points (at most {_MAX_ITEM_PATH})")
        ok = not bad
        items.append((ptr, obj, ok))
        if not ok:
            continue
        if "commitment" in obj:
            withheld.add(ptr)
        else:
            if obj["salt"] in salts:
                problems.append(f"{where} reuses the salt of the item at {salts[obj['salt']][:80]!r} (6.6.4)")
            salts.setdefault(obj["salt"], ptr)
        c = _item_commitment(obj)
        if c in commitments:
            problems.append(f"{where} has the same commitment as the item at {commitments[c][:80]!r} (6.6.4)")
        commitments.setdefault(c, ptr)
    return {"items": items, "W": withheld, "count": count}


def _items_report(walk: dict | None) -> dict:
    """SPEC 6.6.8: items: {total, disclosed, withheld, withheld_by_mark, withheld_paths: [{path, marks}]}."""
    rep = {"total": 0, "disclosed": 0, "withheld": 0, "withheld_by_mark": {}, "withheld_paths": []}
    if not walk:
        return rep
    for path, obj, ok in walk["items"]:
        if not ok:
            continue
        if "commitment" in obj:
            rep["withheld"] += 1
            for m in obj["marks"]:
                rep["withheld_by_mark"][m] = rep["withheld_by_mark"].get(m, 0) + 1
            rep["withheld_paths"].append({"path": path, "marks": list(obj["marks"])})
        else:
            rep["disclosed"] += 1
    rep["total"] = walk.get("count", len(walk["items"]))
    rep["withheld_paths"].sort(key=lambda e: e["path"])
    rep["withheld_by_mark"] = dict(sorted(rep["withheld_by_mark"].items()))
    return rep


def _check_v4(bundle: dict, problems: list[str], origin_problems: list[str],
              attestation_problems: list[str] | None, attestations_out: list | None, *, profile=None,
              sig_out: dict | None = None, pin_set: dict[str, bool] | None = None,
              v4_out: dict | None = None) -> str | None:
    """SPEC v4 draft 12.2 steps 5-19 for a canon-3 bundle. Returns the embedded signer (hex) like `_check`."""
    # step 5, the pairing (11.5): "Canon 3 MUST appear only in v4"
    want_v4 = _profile_value(profile, "envelope_schema_v4", _ENVELOPE_V4)
    schema = bundle.get("schema")
    if schema != want_v4:
        if schema == _profile_value(profile, "envelope_schema", "evidence.envelope.v3"):
            problems.append("canon 3 requires envelope v4 (SPEC 11.5)")
        else:
            problems.append(f"unknown envelope schema: {schema!r} (canon 3 pairs only with {want_v4!r}, SPEC 11.5)")
    # step 6, the top-level key set (3.4)
    extra_top = sorted(set(bundle) - _ALLOWED_TOP_V4)
    if extra_top:
        problems.append(f"bundle has unexpected top-level keys (unsigned): {extra_top}")
    # step 7, the non-finite scan for an already-parsed input (4.2 item 10)
    non_finite = _non_finite_paths(bundle)
    if non_finite:
        problems.append(f"bundle contains non-JSON (NaN/Infinity) values at: {non_finite[:5]}")
        return None
    # step 8
    manifest = bundle.get("manifest", {})
    if not isinstance(manifest, dict):
        problems.append(f"manifest is not a JSON object (got {type(manifest).__name__})")
        manifest = {}
    sha256sums = bundle.get("sha256sums", {})
    if not isinstance(sha256sums, dict):
        problems.append(f"sha256sums is not a JSON object (got {type(sha256sums).__name__})")
        sha256sums = {}
    if set(manifest) != set(_SECTIONS):
        problems.append(f"manifest has unexpected/missing sections: {sorted(set(manifest) ^ set(_SECTIONS))}")
    if set(sha256sums) != _SHA256SUMS_KEYS:
        problems.append(f"sha256sums has unexpected/missing sections: {sorted(set(sha256sums) ^ _SHA256SUMS_KEYS)}")
    # step 9, the redaction record (10.4 R1, R2, R6)
    withheld, declared, record = _v4_redaction(bundle, problems, profile)
    blocks = {}
    for side in _SECTIONS:
        blk = manifest.get(side, {})
        if not isinstance(blk, dict):
            problems.append(f"{side}: manifest block is not a JSON object (got {type(blk).__name__})")
            blk = {}
        blocks[side] = blk
    visible = {s for s in _SECTIONS if "value" in blocks[s]}
    # step 10, the item walk (manifest copies), then the readable copies' form check (6.7.2 item 3)
    walk = _v4_item_walk({s: blocks[s] for s in _SECTIONS}, visible, problems)
    for copy_key, label in (("result", "result"), ("reproducibility", "reproducibility")):
        if copy_key in bundle:
            copy_found, _n = _committed_walk(bundle[copy_key], f"/{copy_key}", max_items=_MAX_ITEMS + 1,
                                             max_path=_MAX_ITEM_PATH)
            for ptr, _toks, obj, _plen in copy_found:
                if copy_key == "reproducibility":
                    problems.append(f"readable copy {label}: committed item at {ptr[:80]!r} (no items in "
                                    "reproducibility, P2)")
                for b in item_problems(obj):
                    problems.append(f"readable copy {label}: committed item at {ptr[:80]!r}: {b} (6.7.2 item 3)")
    if v4_out is not None:
        v4_out["walk"] = walk
    # step 11, the section digests under canon_3 (6.7.1) and presence (6.1, P5)
    for side in _SECTIONS:
        blk = blocks[side]
        extra_blk = sorted(set(blk) - {"sha256", "value"})
        if extra_blk:
            problems.append(f"{side}: manifest block has unexpected keys (unsigned): {extra_blk}")
        declared_d, sealed = blk.get("sha256"), sha256sums.get(side)
        for lbl, dig in ((f"{side} manifest sha256", declared_d), (f"{side} sealed digest", sealed)):
            if not _is_digest(dig):
                problems.append(f"{lbl} is not a well-formed sha256:<64 hex> digest: {dig!r}")
        if declared_d != sealed:
            problems.append(f"{side}: manifest digest {_shown(declared_d)} != sealed digest {_shown(sealed)}")
        if "value" in blk:
            cb = _try_canon(blk["value"], f"{side}: manifest value (canon 3)", problems, canon_fn=_canon_v3)
            if cb is not None and _sha(cb) != declared_d:
                problems.append(f"{side}: manifest {_shown(declared_d)} != recomputed {_sha(cb)}")
            if side in withheld:
                problems.append(f"{side}: declared withheld but its value is still present")
        elif side == "provenance":
            problems.append("provenance: its value is withheld, but provenance cannot be withheld in v4 (P5)")
        elif side not in withheld:
            problems.append(f"{side}: value is missing but not declared redacted")
    # step 12, the result copy, compared under canon_2 with NO projection (6.7.2 item 1)
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
        want_rs = _profile_value(profile, "result_schema", "evidence.result.v1")
        want_rsv = _profile_value(profile, "result_schema_version", 1)
        if "schema" in core and core.get("schema") != want_rs:
            problems.append(f"embedded result core schema is not {want_rs!r}: {core.get('schema')!r}")
        if "schema_version" in core and (isinstance(core.get("schema_version"), bool)
                                         or core.get("schema_version") != want_rsv):
            problems.append(f"embedded result core schema_version is not {want_rsv!r}: {core.get('schema_version')!r}")
        cc = _try_canon(core, "embedded result core", problems, canon_fn=_canon_v2)
        cr = _try_canon(blocks["result"].get("value"), "hashed result core", problems, canon_fn=_canon_v2)
        if cc is not None and cr is not None and cc != cr:
            problems.append("embedded result core != hashed result core (compared in stored form, canon 2 with no "
                            "projection, 6.7.2: every item must have the same form in both copies)")
    # step 13, reproducibility: REQUIRED in v4 (3.4), an object, equal under unprojected canon_2 (6.7.2 item 2)
    prov_val = blocks["provenance"].get("value")
    if "reproducibility" not in bundle:
        problems.append("reproducibility is required in v4 (3.4)")
    elif not isinstance(bundle["reproducibility"], dict):
        problems.append("embedded reproducibility is not a JSON object "
                        f"(got {type(bundle['reproducibility']).__name__})")
    elif "value" in blocks["provenance"]:
        cp = _try_canon(bundle["reproducibility"], "embedded reproducibility", problems, canon_fn=_canon_v2)
        cpv = _try_canon(prov_val, "hashed provenance", problems, canon_fn=_canon_v2)
        if cp is not None and cpv is not None and cp != cpv:
            problems.append("embedded provenance != hashed provenance")
    # step 14, R4 (W = D) and R5
    w_set = walk["W"]
    if (w_set or set(_SECTIONS) - visible) and not record:
        problems.append("a redaction record is required when a section or an item is withheld (R5)")
    for path in sorted(w_set - declared):
        problems.append(f"undeclared item strip: the withheld item at {path[:80]!r} is not in "
                        "redaction.withheld_items (R4)")
    for path in sorted(declared - w_set):
        sec = path.split("/")[1] if path.startswith("/") else None
        if sec in _SECTIONS and sec not in visible:
            problems.append(f"declared withheld item {path[:80]!r} lies in a withheld section and cannot be "
                            "checked (R4)")
        else:
            problems.append(f"declared but not withheld: {path[:80]!r} is not a withheld-form item of a visible "
                            "section (R4)")
    # step 16 first, for the self-reference check of step 15 (12.2 step 15 names it)
    try:
        own_seal = _sha(_canon(sha256sums))
    except (TypeError, ValueError):
        own_seal = None
    # step 15, provenance rules (8.2), seal_signers (7.9), the frontier slots (8.3) and derived_from (9.1)
    if not isinstance(prov_val, dict):
        if "value" in blocks["provenance"]:
            problems.append(f"hashed provenance value must be a JSON object (got {type(prov_val).__name__})")
    else:
        _check_required_provenance(prov_val, problems)
        _check_optional_provenance(prov_val, problems)
        dl, dls = prov_val.get("data_library"), prov_val.get("data_library_sha256")
        _no_null_leaf(prov_val, "data_library", "provenance data_library", problems)
        if dl is not None and not (isinstance(dl, str) and dl):
            problems.append(f"provenance data_library is not a non-empty string: {dl!r}")
        if isinstance(dl, str) and dl and not _is_digest(dls):
            problems.append(f"provenance names data_library {dl!r} but data_library_sha256 is not a "
                            f"well-formed sha256:<64 hex> digest: {dls!r}")
        elif not (isinstance(dl, str) and dl) and dls is not None and not _is_digest(dls):
            problems.append(f"provenance data_library_sha256 is not a well-formed digest: {dls!r}")
        ss_problems = _seal_signers_problems(prov_val)
        problems.extend(ss_problems)
        _check_frontier_slots(prov_val, problems, profile, own_seal=own_seal)
    bsum = bundle.get("bundle_sha256")
    if not _is_digest(bsum):
        problems.append(f"bundle_sha256 is not a well-formed sha256:<64 hex> digest: {bsum!r}")
    recomputed = own_seal or ""
    if own_seal is None:
        problems.append("sha256sums: value cannot be canonicalized")
    elif own_seal != bsum:
        problems.append(f"bundle: {_shown(bsum)} != recomputed {own_seal}")
    # step 17, R3 against the recomputed seal
    red = bundle.get("redaction")
    if isinstance(red, dict) and "parent_bundle_sha256" in red and red["parent_bundle_sha256"] != recomputed:
        problems.append("redaction parent_bundle_sha256 does not match this bundle's seal (R3)")
    # step 18, the leak guard (8.1)
    if "inputs" in withheld:
        for core_src in (bundle.get("result"), blocks["result"].get("value")):
            if isinstance(core_src, dict) and isinstance(core_src.get("provenance"), dict) \
                    and "inputs" in core_src["provenance"]:
                problems.append("inputs declared withheld but still present in the result core's provenance")
                break
    # unsigned v4 blocks this release does not check: never a pass by omission
    if "signatures" in bundle:
        problems.append("signatures: co-signatures (SPEC 7.8) are not checked by this verifier release; a bundle "
                        "that carries them is not verified")
    if attestation_problems is not None and "attestations" in bundle:
        attestation_problems.append("attestations: v2 entries (SPEC 10.3) are not checked by this verifier release")
    if v4_out is not None:
        v4_out["unchecked_blocks"] = sorted(k for k in ("timestamps", "archive", "attestations") if k in bundle)
    # step 19, the primary seal signature over the RECOMPUTED seal, and G2 for E = [signature]
    signer = _check_signature(bundle, recomputed, problems, origin_problems, profile, sig_out=sig_out,
                              pin_set=pin_set, v4_suites=True)
    sig = bundle.get("signature")
    declared_signers = ([(e["alg"], e["public_key"]) for e in prov_val["seal_signers"]]
                        if isinstance(prov_val, dict) and not ss_problems else None)
    if declared_signers is not None and isinstance(sig, dict) \
            and declared_signers != [(sig.get("alg"), sig.get("public_key"))]:
        problems.append("the seal signatures do not equal provenance.seal_signers (SIG-20, G2): the declared "
                        "signer list is [the primary signature] in this release")
    return signer


def _dims(bundle: Any, cv: int | None, integrity: bool, att_problems: list[str], atts: list, items: dict) -> dict:
    """The v4 dimensions (SPEC 13.7 item 4) as runner protocol v2 reports them (`dims`), plus `items` (6.6.8).

    - canon 1/2 (13.4.6): `signoffs` is `invalid` exactly when the v1 attestation check fails, `ok` when a valid block
      has an entry, else `none`; `time` and `archive` are `none`.
    - canon 3: this release checks no sign-off v2, timestamp or archive. An absent block reads `none`; a
      PRESENT one cannot be checked here and reads fail-closed (`signoffs: invalid`; `time`/`archive: malformed`
      once integrity holds, else `not_checked`, 13.7 table), so the default policy rejects it (13.4.3 rows 3, 14,
      17; 13.4.5 "a timestamp or archive that is present but invalid or malformed").
    - canon >= 4, or an unreadable header: `signoffs: none`, `time: not_checked`, `archive: not_checked` (11.6)."""
    b = bundle if isinstance(bundle, dict) else {}
    if cv in (1, 2):
        signoffs = "invalid" if att_problems else ("ok" if atts else "none")
        return {"signoffs": signoffs, "time": "none", "archive": "none", "items": items}
    if cv == 3:
        signoffs = "invalid" if "attestations" in b else "none"
        time = "not_checked" if not integrity else ("malformed" if "timestamps" in b else "none")
        archive = "not_checked" if not integrity else ("malformed" if "archive" in b else "none")
        return {"signoffs": signoffs, "time": time, "archive": archive, "items": items}
    return {"signoffs": "none", "time": "not_checked", "archive": "not_checked", "items": items}


def _plain_data_committed_paths(bundle: Any) -> list[str]:
    """SPEC 6.6.1 / 6.6.8: under canon 1 and 2 a `$committed` object is plain data; report its JSON Pointer."""
    manifest = bundle.get("manifest") if isinstance(bundle, dict) else None
    if not isinstance(manifest, dict) or _exceeds_depth(bundle):
        return []
    out: list[str] = []
    for s in _SECTIONS:
        blk = manifest.get(s)
        if isinstance(blk, dict) and "value" in blk:
            # bounded like the v4 walk: the note names at most _MAX_PLAIN_NOTE_PATHS pointers, each cut at the item
            # path limit, so plain data under a long key cannot blow up memory (it is advisory, never a state)
            sec_found, _n = _committed_walk(blk["value"], f"/{s}", max_items=_MAX_PLAIN_NOTE_PATHS - len(out),
                                            max_path=_MAX_ITEM_PATH)
            out.extend(ptr for ptr, _t, _o, _l in sec_found)
    return out


#: The most pointers the `committed_key_plain_data` note lists.
_MAX_PLAIN_NOTE_PATHS = 200


#: The problem recorded when verification itself runs out of memory or stack on a hostile bundle (always a fail).
_RESOURCE_PROBLEM = ("bundle could not be checked: verification ran out of resources ({}); a bundle that cannot be "
                     "checked fails")

#: The most problems a report lists per list (the state is always decided on the full list).
_MAX_REPORTED_PROBLEMS = 200


def classify_bundle(bundle: dict, *, profile=None, policy=None, pins=None) -> dict:
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
    # SPEC 7.12 / 13.4.1: a receiver ``policy`` (its ``pins``) and out-of-policy caller ``pins`` replace the single
    # v3 pin with a pin set. Either is validated FIRST: a malformed one raises PolicyError and no verdict is made
    # ("It MUST NOT fall back to the default policy"). A profile's data-only ``pinned_keys`` list (7.12, informative:
    # "Python `Profile.pinned_keys` is a data-only list that replaces `pinned_pubkey`") is read as caller pins.
    profile_keys = _profile_value(profile, "pinned_keys", None)
    if pins is None and profile_keys is not None:
        pins = list(profile_keys)
    pin_set, members = effective_policy(policy, pins)
    problems: list[str] = []
    origin_problems: list[str] = []
    attestation_problems: list[str] = []
    attestations: list = []
    canon_info: dict = {}
    sig_info: dict = {}
    v4_info: dict = {}
    try:
        signer = _check(bundle, problems, origin_problems, attestation_problems, attestations,
                        profile=profile, canon_out=canon_info, sig_out=sig_info, pin_set=pin_set, v4_out=v4_info)
    except (MemoryError, RecursionError) as exc:
        # A hostile bundle that exhausts memory or the stack is a verdict (fail), never a traceback.
        signer = None
        problems.append(_RESOURCE_PROBLEM.format(type(exc).__name__))
        canon_info.pop("unsupported", None)
        sig_info.pop("unsupported_alg", None)
        v4_info.pop("walk", None)
    # SPEC 6.6.8 / 13.7 item 4: the `items` report and the advisory `notes` (never a state). Under canon 1 and 2 a
    # `$committed` object is plain data: items stay zero and the note names its pointer.
    try:
        plain = _plain_data_committed_paths(bundle) if canon_info.get("version") in (1, 2) else []
    except (MemoryError, RecursionError) as exc:
        plain = []
        problems.append(_RESOURCE_PROBLEM.format(type(exc).__name__))
    notes = [NOTE_COMMITTED_KEY_PLAIN_DATA] if plain else []
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
    profile_pin, _malformed = _profile_pin(profile)   # a malformed pin already failed origin in _check_signature
    profile_declares_demo = _profile_value(profile, "pin_is_demo", False)
    if pin_set is not None:
        # the matched pin's effective demo flag (SIG-28 and the demo-wins merge are applied in resolve_pins);
        # `pin_is_demo = True` marks every entry as demo (7.12, informative).
        effective_pin = None
        demo_pin = bool(sig_info.get("pin_demo")) or profile_declares_demo
    elif profile_pin is None:
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
    out = {
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
        "pinned_key": ("ed25519:" + effective_pin) if effective_pin is not None else sig_info.get("pin_key_id"),
        # SPEC 7.11: the signer's key id, and (when a pin set is in force) the pin set as {key_id: effective demo}
        "signer_key_id": key_id("ed25519", signer) if isinstance(signer, str) else None,
        "pin_set": None if pin_set is None else [{"key_id": k, "demo": pin_set[k]} for k in sorted(pin_set)],
        # ADR-050: the sealed canon version this bundle claims, and the highest version this verifier can
        # apply. `canon_version` is None when the header was malformed/missing (an integrity FAIL).
        "canon_version": canon_info.get("version"),
        "supported_canon_max": canon_info.get("supported_max", _CANON_SUPPORTED_MAX),
        "items": _items_report(v4_info.get("walk")),
        "dims": _dims(bundle, canon_info.get("version"), integrity_ok, attestation_problems, attestations,
                      _items_report(v4_info.get("walk"))),
        "notes": notes,
        "note_details": {NOTE_COMMITTED_KEY_PLAIN_DATA: plain} if plain else {},
        # v4 unsigned blocks this release reports but does not check (timestamps, archive, attestations v2)
        "unchecked_blocks": v4_info.get("unchecked_blocks", []),
    }
    # SPEC 13.4.2: decision = evaluate(verdict, policy) -> {accept, policy_sha256, reasons}, under the EFFECTIVE
    # policy (the default policy plus the single v3 pin when no policy or pin set was given).
    eff_pins = pin_set if pin_set is not None else {key_id("ed25519", effective_pin): bool(demo_pin)}
    # the verdict records the policy it was made under (13.4.2), so `evaluate` can refuse a different one
    out["policy_sha256"] = policy_sha256(members, eff_pins)
    reasons = evaluate(out, members, eff_pins)
    out["decision"] = {"accept": not reasons, "policy_sha256": out["policy_sha256"], "reasons": reasons}
    # Bound the report: a bundle of many malformed items must not produce megabytes of problem text. The state was
    # decided above on the full list; only the reported lists are capped (`problems_truncated` says by how much).
    for key in ("problems", "integrity_problems", "origin_problems"):
        if len(out[key]) > _MAX_REPORTED_PROBLEMS:
            out[f"{key}_truncated"] = len(out[key]) - _MAX_REPORTED_PROBLEMS
            out[key] = out[key][:_MAX_REPORTED_PROBLEMS] + [
                f"... and {len(out[key]) - _MAX_REPORTED_PROBLEMS} more problems not shown"]
    return out


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
           profile=None, canon_out: dict | None = None, sig_out: dict | None = None,
           pin_set: dict[str, bool] | None = None, v4_out: dict | None = None) -> str | None:
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
        #
        # SPEC 4.2 item 10, "(New in v4, for every version.)": "A verifier entry point that receives an
        # already-parsed value has no unreadable outcome. It MUST scan for NaN and infinite doubles and fail the
        # bundle if it finds one. This applies on the canon-1/2 path (12.1 step 7), the canon-3 path (12.2 step
        # 7) and the newer-canon branch (11.6 step 4)." Text input never gets here with one (`loads` refuses it:
        # 4.2 items 7 and 9); an in-memory dict handed to `classify_bundle` can. Before this, the branch
        # returned before any non-finite check (open issue 17.2.1), so such a dict read as `unsupported-canon`.
        # The scan runs AFTER the seal and signature checks below, in the order of 11.6 (it is step 4, after
        # steps 1 and 2), so that on a hit "The pin comparison is still recorded" (11.6): `signer` and the
        # pinned-key result in `origin_problems` are reported, and only the state is `fail`.
        #
        # Open issue 17.3.7, "declared intended" (SPEC v4 draft 11.2 item 3 and 11.6): in this branch the
        # verifier checks ONLY the header seal, the signature over it, and the top-level key set. It does not
        # read `schema`, the `sha256sums` key set, `redaction`, `timestamp` or `attestations` (it cannot trust
        # any section-level field of a format it does not implement), and a top-level key outside the allowed
        # list is REPORTED as a problem while the state stays `unsupported-canon` (11.2 item 3: "the reference
        # verifiers report it as a problem but the state stays `unsupported-canon` (open issue 17.3.7, now
        # declared intended)"). On the unsupported-alg sub-branch the same key makes the state `fail` (11.2
        # item 4). Both are pinned by vectors (unsupported/c4_extra_top_key_reported.json,
        # v3:invalid/newer_canon_alg_extra_top.json) and must not be "tidied" into one behaviour.
        bsum = bundle.get("bundle_sha256")
        cb = _try_canon(sha256sums_hdr, "sha256sums", problems)
        recomputed = _sha(cb) if cb is not None else ""
        header_seals = (cb is not None and isinstance(bsum, str)
                        and _SHA256_RE.fullmatch(bsum) is not None and recomputed == bsum)
        sig_problems: list[str] = []
        # populates `origin_problems` with the pinned-key mismatch (Decision 4) even on fail-forward.
        signer = _check_signature(bundle, recomputed, sig_problems, origin_problems, profile, sig_out=sig_out,
                                  pin_set=pin_set, v4_suites=True)
        non_finite = _non_finite_paths(bundle)   # 11.6 step 4 / 4.2 item 10 (see above): a hit is `fail`
        if non_finite:
            problems.append(f"bundle contains non-JSON (NaN/Infinity) values at: {non_finite[:5]}")
            problems.extend(sig_problems)
            return signer
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
            extra_top = sorted(set(bundle) - _ALLOWED_TOP_UNION)
            if extra_top:
                problems.append(
                    f"bundle has unexpected top-level keys (unsigned, riding outside the seal): {extra_top}")
        elif header_seals and sig_out is not None and sig_out.get("unsupported_alg") and len(sig_problems) == 1:
            # F3: header seals, sole signature problem is an unknown suite -> unsupported-alg precedence.
            # BUT an unsigned top-level key riding outside the seal must still be caught (I1), matching the
            # normal path and the unsupported-canon sibling; if present, fall through to FAIL.
            extra_top = sorted(set(bundle) - _ALLOWED_TOP_UNION)
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
    if canon_version == 3:
        # SPEC v4 draft 12.2: canon 3 is the v4 algorithm (the canon-1/2 path below is the v3 one, unchanged).
        return _check_v4(bundle, problems, origin_problems, attestation_problems, attestations_out, profile=profile,
                         sig_out=sig_out, pin_set=pin_set, v4_out=v4_out)
    canon_fn = _CANON[canon_version]
    envelope_schema = _profile_value(profile, "envelope_schema", "evidence.envelope.v3")
    if bundle.get("schema") != envelope_schema:
        if bundle.get("schema") == _profile_value(profile, "envelope_schema_v4", _ENVELOPE_V4):
            # SPEC 11.5: "`evidence.envelope.v4` | 1 or 2 | `fail`: "envelope v4 requires canon 3""
            problems.append(f"envelope v4 requires canon 3 (sealed canon_version {canon_version}; SPEC 11.5)")
        else:
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
            problems.append(f"{side}: manifest digest {_shown(declared)} != sealed digest {_shown(sealed)}")
        if "value" in blk:
            cb = _try_canon(blk["value"], f"{side}: manifest value", problems, canon_fn=canon_fn)
            if cb is not None:
                recomputed = _sha(cb)
                if recomputed != declared:
                    problems.append(f"{side}: manifest {_shown(declared)} != recomputed {recomputed}")
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
        problems.append(f"bundle: {_shown(bundle.get('bundle_sha256'))} != recomputed {recomputed_bundle}")

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

    return _check_signature(bundle, recomputed_bundle, problems, origin_problems, profile, sig_out=sig_out,
                            pin_set=pin_set)


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
    if citing_cv == 3 and up_cv != 3:
        # SPEC v4 draft 9.4 rule 2: "When the upstream's `canon_version` is 1 or 2, both ends MUST be digested under
        # `canon_2` with **no** projection" (under canon 1/2 `$committed` is plain data; T would merge distinct
        # upstream values into one binding).
        canon_fn = _canon_v2
    consumed = link["consumed"]
    res_blk = up["manifest"]["result"]
    if "value" not in res_blk:
        return (LINK_CONSUMED_UNVERIFIABLE, "upstream result is withheld; the consumed value cannot be checked")
    if up_cv == 3:
        # 9.4 rule 3: "A `consumed.path` that resolves to an item in the upstream, or passes through one, MUST give
        # link state `consumed-mismatch`" (the binding would otherwise depend on what was disclosed).
        tokens = _pointer_tokens(consumed["path"]) or []
        cur = res_blk["value"]
        for tok in [None, *tokens]:
            if tok is not None:
                ok, cur = resolve_pointer(cur, "/" + _ptr_token(tok))
                if not ok:
                    break
            if isinstance(cur, dict) and _COMMITTED in cur:
                return (LINK_CONSUMED_MISMATCH,
                        (f"consumed.path {consumed['path']!r} resolves to, or passes through, a committed item "
                         "in the upstream (SPEC 9.4 rule 3)"))
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
    if citing_cv == 3 and up_cv != 3 and _has_committed_member(own_inputs[consumed["input"]]):
        # 9.4 rule 2, third bullet: "`own_inputs[consumed.input]` MUST NOT contain an object member named
        # `$committed`. Under canon 3 such a member would be an item, and the binding would then depend on its form"
        return (LINK_CONSUMED_MISMATCH,
                (f"the citing bundle's input {consumed['input']!r} holds a committed item, but the upstream is "
                 f"canon_version {up_cv}: such a link cannot bind (SPEC 9.4 rule 2)"))
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
