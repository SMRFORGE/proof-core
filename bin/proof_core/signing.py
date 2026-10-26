"""Bundle signing.

A hash proves a bundle wasn't edited; a SIGNATURE proves it came from the pinned signer's key.
Non-repudiation is what lets a customer hand a bundle to a regulator who trusts the key,
not the customer.

PRODUCTION: an Ed25519 private key held in an HSM/KMS, never in source; the public key is
distributed out-of-band to reviewers/regulators (or pinned in the standalone verifier).
DEMO: a self-contained RFC 8032 Ed25519 (stdlib `hashlib` only) with a hardcoded DEV seed,
so the project stays dependency-free AND the standalone verifier can check a REAL
signature with its own independent implementation. Swap in a vetted library + HSM for prod.

`pow(x, -1, q)`-style modular inverse via the builtin keeps the field ops at C speed, so a
sign is a few milliseconds despite being pure Python.
"""
from __future__ import annotations

import hashlib
import os

# --- RFC 8032 Ed25519, compact form (the builtin pow() does the heavy lifting) ---
_q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _q - 2, _q)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By) % _q
_B = (_Bx, _By)


def _edwards(p: tuple[int, int], qq: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = qq
    t = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + t) % _q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - t) % _q
    return (x3, y3)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    # Iterative double-and-add. This was recursive to depth ~e.bit_length(); `sign` and `verify` feed
    # it the UNREDUCED 512-bit SHA-512 scalars r and k (~510 bits), so under a lowered recursion limit
    # or a deep call stack it could raise an uncaught RecursionError (only _decodepoint was guarded),
    # diverging from the standalone verifiers' iterative _mul which return a clean bool. Same result,
    # no recursion.
    result = (0, 1)
    addend = p
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _hbytes(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    h = _hbytes(m)
    return sum((1 << i) * _bit(h, i) for i in range(512))


def _secret_scalar(h: bytes) -> int:
    return 2**254 + sum((1 << i) * _bit(h, i) for i in range(3, 254))


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def publickey(sk: bytes) -> bytes:
    a = _secret_scalar(_hbytes(sk))
    return _encodepoint(_scalarmult(_B, a))


def sign(msg: bytes, sk: bytes, pk: bytes) -> bytes:
    h = _hbytes(sk)
    a = _secret_scalar(h)
    r = _hint(h[32:64] + msg)
    renc = _encodepoint(_scalarmult(_B, r))
    s = (r + _hint(renc + pk + msg) * a) % _L
    return renc + s.to_bytes(32, "little")


#: The 8 canonical low-order Ed25519 point encodings (the 8-torsion subgroup, which includes the
#: identity `0100...00`). A public key or signature R that decodes to one of these is a low-order point
#: whose order divides 8 -- standard Ed25519 would accept it, but it carries no origin and enables
#: known small-subgroup games, so we reject it on decode (defense in depth). These are NOT hardcoded from
#: memory: each was computed as [L]P over random on-curve points P and VERIFIED to satisfy [8]P == identity
#: (tools/scratch enumeration of the 8-torsion). Kept in lock-step with proof_verify.verify. See
#: tests/test_low_order_point_reject.py, which re-derives and asserts this exact set.
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
    if y >= _q:                                   # reject a non-canonical (y >= p) point encoding
        raise ValueError("non-canonical point encoding")
    x = _xrecover(y)
    sign = (b[31] >> 7) & 1
    # RFC 8032 5.1.3 step 4: x == 0 with the sign bit set is a non-canonical encoding and MUST fail
    # (there is no negative zero). `_xrecover` normalises to the even root, so detect it here against the
    # encoded sign bit before the parity flip. Kept in lock-step with proof_verify.verify._recover_x.
    if x == 0 and sign == 1:
        raise ValueError("non-canonical encoding: x == 0 with sign bit set (RFC 8032 5.1.3)")
    if x & 1 != sign:
        x = _q - x
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _q != 0:
        raise ValueError("point not on curve")
    return (x, y)


def verify(signature: bytes, msg: bytes, pk: bytes) -> bool:
    """Producer-side raw Ed25519 check (self-consistency tests, cross-validation against the standalone
    verifier). The standalone bundle verifier keeps its OWN independent copy -- this one is not it."""
    if len(signature) != 64 or len(pk) != 32:
        return False
    try:
        r_point = _decodepoint(signature[:32])
        a_point = _decodepoint(pk)
    except (ValueError, IndexError):
        return False
    # Reject a small-order public key OR R ([8]P == identity <=> P has order dividing 8). Under the
    # cofactorless equation a small-order A (e.g. the identity point) accepts a "signature" that needs no
    # private key, and a small-order R launders torsion the equation would otherwise catch. Redundant with
    # the `_LOW_ORDER_ENCODINGS` table above (which catches the same order-|8 set on decode), so it rejects
    # NOTHING the table did not already reject -- a prime-order key is unaffected -- but it makes this
    # implementation mechanically identical to the standalone verifier. Mirrors proof_verify.verify.
    if _scalarmult(a_point, 8) == (0, 1) or _scalarmult(r_point, 8) == (0, 1):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:                                   # reject a non-canonical / malleable scalar (RFC 8032)
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + pk + msg).digest(), "little")
    return _scalarmult(_B, s) == _edwards(r_point, _scalarmult(a_point, k))


# --- the signing identity ---
# proof-core is KEYLESS by design: the only identity it ships is the public DEV seed. The built-in
# "seed" backend signs in-process from a 32-byte hex seed in PROOF_SIGNING_SEED (a secret manager /
# air-gapped machine); unset, it uses the PUBLIC DEV seed, so the demo + verifier work out of the box
# but a signature under it proves FORMAT / INTEGRITY, not ORIGIN (the seed is public). A consumer that
# holds a REAL key (HSM / KMS / YubiKey) does NOT get a hardware backend in this free kernel -- it
# INJECTS its own signer with `use_signer()` (the ADR-048 trust-root hook below), keeping the key and
# the hardware dependency entirely in the consumer's own tree. Either way the OUTPUT is a standard raw
# Ed25519 signature the standalone verifier checks unchanged.
_DEV_SEED = bytes.fromhex("1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809")
_BACKEND = os.environ.get("PROOF_SIGNING_BACKEND", "seed").lower()

# A non-"seed" backend is refused rather than silently falling back to the demo key: a misconfiguration
# must fail loud, and proof-core ships no hardware backend (inject one with use_signer instead).
if _BACKEND not in ("seed", ""):
    raise ValueError(
        f"PROOF_SIGNING_BACKEND={_BACKEND!r} is not supported; proof-core signs only with the built-in "
        "'seed' backend (keyless by design). Inject a hardware/HSM/KMS key with "
        "proof_core.use_signer(signer) in your own tree instead.")

_ENV_SEED = os.environ.get("PROOF_SIGNING_SEED")
if _ENV_SEED:
    # a real signing seed MUST be exactly 32 bytes of hex. Malformed hex used to crash the whole
    # producer at import with a raw ValueError; a valid-hex-but-wrong-length seed was SILENTLY
    # accepted and then labeled a production identity -- the worst case for the key ceremony.
    try:
        _SEED = bytes.fromhex(_ENV_SEED)
    except ValueError as exc:
        raise ValueError("PROOF_SIGNING_SEED must be 32 bytes of hex (64 hex chars); "
                         "the value is not valid hex") from exc
    if len(_SEED) != 32:
        raise ValueError("PROOF_SIGNING_SEED must be exactly 32 bytes (64 hex chars), "
                         f"got {len(_SEED)} bytes")
else:
    _SEED = _DEV_SEED
IS_DEMO_IDENTITY = _SEED == _DEV_SEED
_PK = publickey(_SEED)


def _raw_sign(msg: bytes) -> bytes:
    return sign(msg, _SEED, _PK)


# --- consumer-injected trust root (ADR-048) ---------------------------------------------------- #
# proof-core is keyless, so the ONLY way a real signing identity enters is here: a consumer sets a
# process-level signer carrying its own key (HSM / KMS / YubiKey). A signer provides
# `public_key() -> 32 bytes` and `sign(msg: bytes) -> 64-byte raw Ed25519`, plus an optional truthy
# `is_demo` attribute (default: a real injected key is treated as non-demo). `_ACTIVE_SIGNER` defaults
# to None -- the built-in seed path above -- so every default/golden mint is byte-identical to today.
_ACTIVE_SIGNER = None


def use_signer(signer) -> None:
    """Install a process-level signer that holds the real signing key (ADR-048 trust-root hook).

    proof-core ships only the public demo seed; a consumer that holds a production key (HSM / KMS /
    YubiKey) injects it here so the key and its hardware dependency stay entirely in the consumer's own
    tree -- the free kernel never imports a hardware backend. `signer` must provide
    ``public_key() -> bytes`` (32) and ``sign(msg: bytes) -> bytes`` (64-byte raw Ed25519). After it is
    installed, `sign_bundle_digest` uses it and the env-selected backend is never consulted, so a process
    holds exactly ONE signing identity and the double-sign hazard closes by construction.

    Guards (ADR-048 / ADR-044): refuses to install while `PROOF_SIGNING_SEED` / `PROOF_SIGNING_BACKEND` is
    set in the environment (a configured env identity AND an injected one is never intended -- a stray
    `PROOF_*` variable in a consumer process becomes a hard error, not a silent second identity); and
    refuses a low-order / small-order public key. Pass ``None`` to reset to the env default (for tests).
    Call once at process start, before sealing. Demo-ness is DERIVED from the key, never asserted:
    `is_demo_identity()` is True only when the active key is the public demo key."""
    global _ACTIVE_SIGNER
    if signer is None:
        _ACTIVE_SIGNER = None
        return
    if os.environ.get("PROOF_SIGNING_SEED") or os.environ.get("PROOF_SIGNING_BACKEND"):
        raise ValueError(
            "use_signer() refuses to install a signer while PROOF_SIGNING_SEED / PROOF_SIGNING_BACKEND is "
            "set: a process must hold exactly one signing identity. Unset the variable, or pass None.")
    pk = signer.public_key()
    if not isinstance(pk, (bytes, bytearray)) or len(pk) != 32:
        raise ValueError("signer.public_key() must return 32 bytes (an Ed25519 public key)")
    if bytes(pk) in _LOW_ORDER_ENCODINGS:
        raise ValueError("signer public key is a low-order point encoding (order divides 8; rejected)")
    _ACTIVE_SIGNER = signer


def _active_public_key() -> bytes:
    return _ACTIVE_SIGNER.public_key() if _ACTIVE_SIGNER is not None else _PK


def _active_sign(msg: bytes) -> bytes:
    return _ACTIVE_SIGNER.sign(msg) if _ACTIVE_SIGNER is not None else _raw_sign(msg)


def public_key_hex() -> str:
    return _active_public_key().hex()


def is_demo_identity() -> bool:
    """True when the active signing key is the public DEV key -- signatures then prove format/integrity,
    not origin. Derived from the key itself (never a self-asserted flag), so an injected production key
    reads non-demo and an injected copy of the public demo seed reads demo, both correctly."""
    return _active_public_key() == publickey(_DEV_SEED)


#: The ONLY keys a bundle's signature block may carry, and the ONLY value `message` may take. The seal
#: binds `bundle_sha256` alone, so any other key in the block would ride UNSIGNED -- a stapled
#: "attestation", a self-asserted "identity" label -- and survive the Ed25519 check untouched. Every
#: conforming verifier rejects an extra key (parity check S1) and a `message` other than this literal
#: (S2); the standalone verifier restates both independently (proof_verify/verify.py) on purpose, so the
#: producer can never loosen the check by editing one place.
SIGNATURE_KEYS = frozenset({"alg", "public_key", "signature", "message"})
SIGNATURE_REQUIRED = ("alg", "public_key", "signature")
SIGNATURE_MESSAGE = "bundle_sha256"


def signature_block_problems(sig: object) -> list[str]:
    """Why `sig` is not a conforming signature block (empty list == conforming). The PRODUCER-side twin
    of the verifier's S1/S2 checks: `build_bundle` runs it over the block it just minted so a producer
    can never emit a block the independent verifier will reject (an extra key, a mislabeled message)."""
    if not isinstance(sig, dict):
        return [f"signature block is not a JSON object (got {type(sig).__name__})"]
    problems: list[str] = []
    extra = sorted(set(sig) - SIGNATURE_KEYS)
    if extra:
        problems.append(f"unsigned key in signature block: {extra}")
    missing = [k for k in SIGNATURE_REQUIRED if k not in sig]
    if missing:
        problems.append(f"signature block is missing required keys: {missing}")
    if sig.get("message") != SIGNATURE_MESSAGE:
        problems.append(f"signature.message must be {SIGNATURE_MESSAGE!r} (got {sig.get('message')!r})")
    return problems


def _sign_digest(digest: str, message_label: str) -> dict:
    sig = _active_sign(digest.encode())
    # NOTE: no "identity" field. Origin (demo vs production) is a property of the PINNED KEY, decided
    # by the VERIFIER at check time (proof_verify.pinned_key_is_demo / pinned_key_fingerprint), never a
    # self-asserted label carried in the bundle: such a label rode UNSIGNED in the signature block and
    # was ignored by every verdict path, so it could be flipped "demo"->"production" on a demo bundle
    # without detection -- a latent origin-spoofing trap. Dropped so a reader can never mistake it for
    # proof of origin, and REJECTED by every conforming verifier under the S1 key allowlist. (The
    # producer still knows its own backend via is_demo_identity() / IS_DEMO_IDENTITY.)
    return {
        "alg": "ed25519",
        "public_key": _active_public_key().hex(),
        "message": message_label,
        "signature": sig.hex(),
    }


def sign_bundle_digest(bundle_sha256: str) -> dict:
    """Sign the bundle's manifest digest. The signature transitively covers inputs, result,
    and provenance (all hashed into bundle_sha256); tampering any of them breaks it. The block is
    exactly {alg, public_key, signature, message} with message == "bundle_sha256" (S1/S2)."""
    return _sign_digest(bundle_sha256, SIGNATURE_MESSAGE)
