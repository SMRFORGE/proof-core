"""Bundle signing.

A hash proves a bundle wasn't edited; a SIGNATURE proves it came from the pinned signer's key.
Non-repudiation is what lets a customer hand a bundle to a regulator who trusts the key,
not the customer.

PRODUCTION: an Ed25519 private key held in an HSM/KMS, never in source; the public key is
distributed out-of-band to reviewers/regulators (or pinned in the standalone verifier).
DEMO: a self-contained RFC 8032 Ed25519 (stdlib `hashlib` only) with a hardcoded DEV seed,
so the project stays dependency-free AND the standalone verifier can check a REAL
signature with its own independent implementation. Swap in a vetted library + HSM for prod.

Scalar multiplication runs in extended twisted-Edwards coordinates (RFC 8032 5.1.4), so the
only modular inverse (the builtin `pow(x, q - 2, q)`) is paid once per multiple, not per addition;
a sign is about a millisecond despite being pure Python. This signer is NOT constant-time: the
double-and-add branches on secret scalar bits. It is for demo/dev keys only; production signing
uses a hardware-held key.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re

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


# --- extended twisted-Edwards coordinates (RFC 8032 5.1.4) ---
# A point (x, y) is held as (X, Y, Z, T) with x = X/Z, y = Y/Z, x*y = T/Z. Addition and doubling then need
# NO modular inverse; the single inverse is paid once, in `_to_affine`, when a scalar multiple is encoded or
# compared. Affine `_edwards` costs two inverses PER addition, which is what made a verify ~200 ms. The
# formulas are the unified "add-2008-hwcd-3" (complete on Ed25519: a = -1 is a square, d is not) and
# "dbl-2008-hwcd", exactly as RFC 8032 5.1.4 gives them. Same points, same bytes, same accept/reject.
_d2 = 2 * _d % _q


def _to_extended(p: tuple[int, int]) -> tuple[int, int, int, int]:
    x, y = p
    return (x % _q, y % _q, 1, x * y % _q)


def _to_affine(p: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _t = p
    zi = _inv(z)
    return (x * zi % _q, y * zi % _q)


def _ext_add(p: tuple[int, int, int, int], qq: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = qq
    a = (y1 - x1) * (y2 - x2) % _q
    b = (y1 + x1) * (y2 + x2) % _q
    c = t1 * _d2 * t2 % _q
    dd = z1 * 2 * z2 % _q
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _q, g * h % _q, f * g % _q, e * h % _q)


def _ext_double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _t1 = p
    a = x1 * x1 % _q
    b = y1 * y1 % _q
    c = 2 * z1 * z1 % _q
    h = a + b
    e = h - (x1 + y1) * (x1 + y1) % _q
    g = a - b
    f = c + g
    return (e * f % _q, g * h % _q, f * g % _q, e * h % _q)


def _ext_scalarmult(p: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    # Iterative double-and-add over the scalar's bits (never recursive; see `_scalarmult`).
    result = (0, 1, 1, 0)
    addend = p
    while e > 0:
        if e & 1:
            result = _ext_add(result, addend)
        addend = _ext_double(addend)
        e >>= 1
    return result


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    # Iterative double-and-add. This was recursive to depth ~e.bit_length(); `sign` and `verify` feed
    # it the UNREDUCED 512-bit SHA-512 scalars r and k (~510 bits), so under a lowered recursion limit
    # or a deep call stack it could raise an uncaught RecursionError (only _decodepoint was guarded),
    # diverging from the standalone verifiers' iterative _mul which return a clean bool. Same result,
    # no recursion. Affine in, affine out; the work is done in extended coordinates.
    return _to_affine(_ext_scalarmult(_to_extended(p), e))


# [2^i]B for i < 253, built once at import, so a multiple of the base point is additions only (no
# doublings). B has prime order L, so [e]B == [e mod L]B and every reduced scalar fits in 253 bits.
_B_TABLE: list[tuple[int, int, int, int]] = [_to_extended(_B)]
for _ in range(252):
    _B_TABLE.append(_ext_double(_B_TABLE[-1]))


def _scalarmult_base(e: int) -> tuple[int, int]:
    """[e]B, the same point `_scalarmult(_B, e)` returns, via the precomputed `_B_TABLE`.

    A negative e returns the identity, exactly as `_scalarmult(_B, e)` does (its loop never runs);
    it is checked BEFORE the mod-L reduction, which would otherwise turn it into [e mod L]B."""
    if e < 0:
        return (0, 1)
    e %= _L
    result = (0, 1, 1, 0)
    i = 0
    while e > 0:
        if e & 1:
            result = _ext_add(result, _B_TABLE[i])
        e >>= 1
        i += 1
    return _to_affine(result)


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
    return _encodepoint(_scalarmult_base(a))


def sign(msg: bytes, sk: bytes, pk: bytes) -> bytes:
    h = _hbytes(sk)
    a = _secret_scalar(h)
    r = _hint(h[32:64] + msg)
    renc = _encodepoint(_scalarmult_base(r))
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
    return _scalarmult_base(s) == _edwards(r_point, _scalarmult(a_point, k))


# --- ECDSA P-256 (SPEC v4 7.6), producer side ---------------------------------------------------------------------
# The curve constants are copied from NIST SP 800-186 (Feb 2023) section 3.2.1.3 "P-256" and SECG SEC 2 v2.0 section
# 2.4.2 "secp256r1" (the two agree; phase-0 constants register rows P1-P9). The curve is y^2 = x^3 - 3x + b over
# GF(p). Points are held in Jacobian coordinates (X, Y, Z) with x = X/Z^2, y = Y/Z^3, so additions and doublings need
# no modular inverse; the point at infinity is any point with Z == 0. Fixed-base multiples of G use a table of
# [j * 16^i]G (i < 64, 1 <= j <= 15), built once at import, so [k]G is at most 64 mixed additions and no doubling.
#
# This is the PRODUCER's copy: it signs (RFC 6979 deterministic k, low-S normalized; SPEC 7.16 SIG-35 and item 4) and
# self-verifies at mint. The standalone verifier (proof_verify/verify.py) keeps its OWN independent copy; no code is
# shared. The signer is NOT constant-time (it branches on secret scalar bits): it is for the published demo key and
# tests only. Production P-256 keys are injected through `use_signer` / `build_bundle(cosigners=...)`.
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8   # floor(n/2), the low-S bound

# Import-time self-checks of the copied constants (the register's computed cross-checks, repeated here).
if not (P256_P == 2**256 - 2**224 + 2**192 + 2**96 - 1 and P256_HALF_N == (P256_N - 1) // 2 and P256_P % 4 == 3
        and (P256_GY * P256_GY - (P256_GX ** 3 - 3 * P256_GX + P256_B)) % P256_P == 0):
    raise ImportError("P-256 constants failed their self-check")

_P256_INF = (1, 1, 0)


def _p256_dbl(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    # "dbl-2001-b" (a = -3). P-256 has no point of order 2 (n is odd), so Y == 0 only at infinity.
    x1, y1, z1 = pt
    if z1 == 0 or y1 == 0:
        return _P256_INF
    p = P256_P
    delta = z1 * z1 % p
    gamma = y1 * y1 % p
    beta = x1 * gamma % p
    alpha = 3 * (x1 - delta) * (x1 + delta) % p
    x3 = (alpha * alpha - 8 * beta) % p
    z3 = ((y1 + z1) * (y1 + z1) - gamma - delta) % p
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p
    return (x3, y3, z3)


def _p256_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    # General Jacobian addition; it handles P + P (doubling), P + (-P) (infinity) and infinity on either side, so the
    # verify combination u1*G + u2*Q is right for every input, including the adversarial ones of SPEC 7.6 step 5.
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    p = P256_P
    z1z1 = z1 * z1 % p
    z2z2 = z2 * z2 % p
    u1 = x1 * z2z2 % p
    u2 = x2 * z1z1 % p
    s1 = y1 * z2 * z2z2 % p
    s2 = y2 * z1 * z1z1 % p
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    if h == 0:
        return _p256_dbl(p1) if r == 0 else _P256_INF
    hh = h * h % p
    hhh = h * hh % p
    v = u1 * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    y3 = (r * (v - x3) - s1 * hhh) % p
    return (x3, y3, z1 * z2 % p * h % p)


def _p256_madd(p1: tuple[int, int, int], x2: int, y2: int) -> tuple[int, int, int]:
    # Mixed addition: p1 Jacobian, (x2, y2) affine (Z2 = 1). Same special cases as _p256_add.
    x1, y1, z1 = p1
    if z1 == 0:
        return (x2, y2, 1)
    p = P256_P
    z1z1 = z1 * z1 % p
    h = (x2 * z1z1 - x1) % p
    r = (y2 * z1 * z1z1 - y1) % p
    if h == 0:
        return _p256_dbl(p1) if r == 0 else _P256_INF
    hh = h * h % p
    hhh = h * hh % p
    v = x1 * hh % p
    x3 = (r * r - hhh - 2 * v) % p
    y3 = (r * (v - x3) - y1 * hhh) % p
    return (x3, y3, z1 * h % p)


def _p256_affine_all(pts: list[tuple[int, int, int]]) -> list[tuple[int, int]]:
    """Batch Jacobian -> affine with ONE inversion (Montgomery's trick). No point may be the point at infinity."""
    p = P256_P
    prefix, acc = [], 1
    for _x, _y, z in pts:
        prefix.append(acc)
        acc = acc * z % p
    inv = pow(acc, -1, p)
    out: list[tuple[int, int]] = [(0, 0)] * len(pts)
    for i in range(len(pts) - 1, -1, -1):
        x, y, z = pts[i]
        zi = inv * prefix[i] % p
        inv = inv * z % p
        zi2 = zi * zi % p
        out[i] = (x * zi2 % p, y * zi2 * zi % p)
    return out


def _p256_build_g_table() -> list[list[tuple[int, int]]]:
    rows: list[tuple[int, int, int]] = []
    base = (P256_GX, P256_GY, 1)
    for _i in range(64):
        cur = base
        for _j in range(15):
            rows.append(cur)
            cur = _p256_add(cur, base)
        for _ in range(4):
            base = _p256_dbl(base)
    flat = _p256_affine_all(rows)
    return [flat[15 * i:15 * i + 15] for i in range(64)]


#: _P256_G_TABLE[i][j - 1] = [j * 16^i]G, affine.
_P256_G_TABLE = _p256_build_g_table()


def _p256_mul_g(k: int) -> tuple[int, int, int]:
    """[k]G (Jacobian), k reduced mod n first: G has prime order n."""
    k %= P256_N
    acc = _P256_INF
    i = 0
    while k:
        j = k & 15
        if j:
            x, y = _P256_G_TABLE[i][j - 1]
            acc = _p256_madd(acc, x, y)
        k >>= 4
        i += 1
    return acc


def _p256_mul(x: int, y: int, k: int) -> tuple[int, int, int]:
    """[k](x, y) for an affine point of order n: fixed 4-bit windows over [1..15](x, y), made affine with one
    inversion, so every addition in the loop is a mixed one."""
    k %= P256_N
    if k == 0:
        return _P256_INF
    pts = [(x, y, 1)]
    for _ in range(14):
        pts.append(_p256_madd(pts[-1], x, y))
    table = _p256_affine_all(pts)
    acc = _P256_INF
    for shift in range(252, -4, -4):
        acc = _p256_dbl(_p256_dbl(_p256_dbl(_p256_dbl(acc))))
        j = (k >> shift) & 15
        if j:
            acc = _p256_madd(acc, *table[j - 1])
    return acc


def _p256_x_affine(pt: tuple[int, int, int]) -> int:
    zi = pow(pt[2], -1, P256_P)
    return pt[0] * zi * zi % P256_P


def p256_decode_point(pk: bytes) -> tuple[int, int]:
    """SEC 1 section 2.3.4 for the COMPRESSED form only (SPEC 7.6 "Key encoding (proof-core keys only)"): 33 bytes,
    prefix 02 (y even) or 03 (y odd). Raises ValueError for any other length or prefix, x >= p, or an x with no
    point on the curve. The result is on the curve and is not infinity, so (h = 1) it has order n."""
    if len(pk) != 33 or pk[0] not in (2, 3):
        raise ValueError("a proof-core P-256 key is a 33-byte SEC 1 compressed point (prefix 02 or 03)")
    x = int.from_bytes(pk[1:], "big")
    if x >= P256_P:
        raise ValueError("P-256 key x coordinate is not below p (SEC 1 2.3.6)")
    alpha = (x * x * x - 3 * x + P256_B) % P256_P
    beta = pow(alpha, (P256_P + 1) // 4, P256_P)
    if beta * beta % P256_P != alpha:
        raise ValueError("P-256 key is not on the curve (x^3 - 3x + b has no square root mod p)")
    y = beta if beta % 2 == pk[0] - 2 else P256_P - beta
    return (x, y)


def p256_encode_point(x: int, y: int) -> bytes:
    """SEC 1 section 2.3.3 compressed form: 02 (y even) or 03 (y odd), then x as 32 big-endian bytes."""
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def p256_publickey(d: int) -> bytes:
    """The 33-byte compressed public key of the private scalar d (1 <= d <= n - 1)."""
    _p256_check_scalar(d)
    return p256_encode_point(*_p256_affine_all([_p256_mul_g(d)])[0])


def _rfc6979_k(d: int, h1: bytes) -> int:
    """RFC 6979 section 3.2 deterministic nonce for P-256 with HMAC-SHA-256 (qlen = hlen = 256, so bits2int is a
    plain big-endian read and bits2octets(h1) is int2octets(h1 mod q))."""
    x = d.to_bytes(32, "big")
    h = (int.from_bytes(h1, "big") % P256_N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < P256_N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def p256_low_s(s: int) -> int:
    """SPEC 7.16 SIG-35: s -> n - s when s > floor(n/2)."""
    return P256_N - s if s > P256_HALF_N else s


def _p256_check_scalar(d) -> int:
    """A P-256 private scalar must be an int (not a bool) in [1, n - 1]. Raises ValueError otherwise."""
    if type(d) is not int or not 1 <= d < P256_N:
        raise ValueError("a P-256 private scalar must be an int in [1, n - 1]")
    return d


def _p256_mul_g_ladder(k: int) -> tuple[int, int, int]:
    """[k]G for a SECRET k with a fixed number of iterations: k' = k + n or k + 2n (the same point, since G has
    order n) is always exactly 257 bits, and the Montgomery ladder does one addition and one doubling for every one
    of its 256 lower bits, so the work does not depend on k's bit length or on how many of its bits are set. CPython
    integer arithmetic is not constant-time, so this narrows the timing channel; it does not close it (see p256_sign)."""
    k1 = k + P256_N
    k2 = k1 + P256_N
    kk = (k2, k1)[k1 >> 256]
    r0 = (P256_GX, P256_GY, 1)
    r1 = _p256_dbl(r0)
    for i in range(255, -1, -1):
        if (kk >> i) & 1:
            r0, r1 = _p256_add(r0, r1), _p256_dbl(r1)
        else:
            r1, r0 = _p256_add(r0, r1), _p256_dbl(r0)
    return r0


def _p256_sign_k(msg: bytes, d: int, k: int) -> bytes:
    h1 = hashlib.sha256(msg).digest()
    e = int.from_bytes(h1, "big")
    r = _p256_x_affine(_p256_mul_g_ladder(k)) % P256_N
    # Fermat inverse: a fixed 256-bit exponent, so its cost does not track k's bit length as pow(k, -1, n) does
    s = pow(k, P256_N - 2, P256_N) * (e + r * d) % P256_N
    if r == 0 or s == 0:                           # probability ~2^-256; refusing is safe
        raise ValueError("degenerate P-256 signature")
    return r.to_bytes(32, "big") + p256_low_s(s).to_bytes(32, "big")


def p256_sign(msg: bytes, d: int) -> bytes:
    """ECDSA P-256 / SHA-256 over ``msg``: raw r || s (64 bytes), s normalized to the low half (SPEC 7.16 SIG-35:
    "MUST normalize s to n - s when s > floor(n/2)"). Deterministic k (RFC 6979, SPEC 7.16 item 4).

    FOR DEMO AND DEVELOPMENT KEYS ONLY. This is pure-Python signing: the nonce multiply runs a fixed-length ladder and
    the inverse a fixed exponent, but Python integers are not constant-time and the private scalar lives in process
    memory. A production P-256 key belongs in an HSM, KMS or token, used through an external signer
    (`use_signer(...)` or `build_bundle(cosigners=[...])`), never here."""
    d = _p256_check_scalar(d)
    k = _rfc6979_k(d, hashlib.sha256(msg).digest())
    return _p256_sign_k(msg, d, k)


def _der_ecdsa_sig(der: bytes) -> tuple[int, int]:
    """A strict DER ``ECDSA-Sig-Value`` (SEQUENCE of two minimal positive INTEGERs, short-form lengths)."""
    def _int(i: int) -> tuple[int, int]:
        if i + 2 > len(der) or der[i] != 0x02:
            raise ValueError("DER ECDSA signature: INTEGER expected")
        n = der[i + 1]
        body = der[i + 2:i + 2 + n]
        if not 1 <= n <= 33 or len(body) != n or body[0] & 0x80 or (n > 1 and body[0] == 0 and not body[1] & 0x80):
            raise ValueError("DER ECDSA signature: INTEGER is not a minimal positive encoding")
        return int.from_bytes(body, "big"), i + 2 + n
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("P-256 signature is neither 64 raw bytes nor a DER SEQUENCE")
    r, i = _int(2)
    s, i = _int(i)
    if i != len(der):
        raise ValueError("DER ECDSA signature: trailing bytes")
    return r, s


def p256_raw_low_s(sig: bytes) -> bytes:
    """A signer adapter's output -> the proof-core encoding (SPEC 7.6, 7.16 SIG-35): raw r || s with low S.

    HSM, PIV and PKCS#11 devices and native libraries emit DER ``ECDSA-Sig-Value`` or raw P1363 r || s, and neither
    normalizes S, so a signer adapter that skips this step has about half its signatures rejected. Accepts 64 raw
    bytes or a strict DER SEQUENCE; r and s must lie in [1, n - 1]. Raises ValueError for anything else."""
    sig = bytes(sig)
    if len(sig) == 64:
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    else:
        r, s = _der_ecdsa_sig(sig)
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        raise ValueError("P-256 signature r or s is outside [1, n - 1]")
    return r.to_bytes(32, "big") + p256_low_s(s).to_bytes(32, "big")


def p256_verify(signature: bytes, msg: bytes, pk: bytes) -> bool:
    """Producer-side ECDSA P-256 check, SPEC 7.6 steps 2-5 on bytes (self-verify at mint, cross-validation). The
    standalone bundle verifier keeps its OWN independent copy -- this one is not it."""
    if len(signature) != 64:
        return False
    try:
        qx, qy = p256_decode_point(pk)
    except ValueError:
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (1 <= r < P256_N and 1 <= s <= P256_HALF_N):       # FIPS 186-5 6.4.2 step 1, plus low-S (SIG-10)
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, P256_N)
    pt = _p256_add(_p256_mul_g(e * w % P256_N), _p256_mul(qx, qy, r * w % P256_N))
    if pt[2] == 0:                                            # step 6: R is the point at infinity
        return False
    return _p256_x_affine(pt) % P256_N == r


#: The published P-256 DEMO private scalar (SPEC section 2 "demo key"). Anyone can sign under it, so a signature
#: under its public key proves format and integrity, never origin. Tests, vectors and demos only.
P256_DEMO_D = 0x2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a
P256_DEMO_PUBLIC_KEY = p256_publickey(P256_DEMO_D)


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
    signer_key_problems(signer, where="signer")      # raises ValueError for a bad key of the signer's suite
    _ACTIVE_SIGNER = signer


#: The seal suites this kernel can sign AND verify itself (SPEC 7.5: S_sup = {ed25519, ecdsa-p256}).
SUPPORTED_SUITES = ("ed25519", "ecdsa-p256")
_SUITE_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9.+\-]{0,31}", re.ASCII)
_GENERIC_HEX_RE = re.compile(r"(?:[0-9a-f]{2}){1,65536}", re.ASCII)


def signer_alg(signer) -> str:
    """A signer's suite token: its ``alg`` attribute, default ``"ed25519"`` (the ADR-048 hook's original shape)."""
    return getattr(signer, "alg", "ed25519") if signer is not None else "ed25519"


def signer_key_problems(signer, *, where: str) -> None:
    """Refuse a signer whose public key does not fit its suite (SPEC 7.5 rows, 7.6 key encoding, 7.3 small order).
    Raises ValueError."""
    alg = signer_alg(signer)
    if not (isinstance(alg, str) and _SUITE_TOKEN_RE.fullmatch(alg)):
        raise ValueError(f"{where}.alg must be a suite token [a-z0-9][a-z0-9.+-]{{0,31}}, got {alg!r}")
    pk = signer.public_key()
    pk = bytes(pk) if isinstance(pk, (bytes, bytearray)) else b""
    if alg == "ed25519":
        if len(pk) != 32:
            raise ValueError(f"{where}.public_key() must return 32 bytes (an Ed25519 public key)")
        if pk in _LOW_ORDER_ENCODINGS:
            raise ValueError(f"{where} public key is a low-order point encoding (order divides 8; rejected)")
    elif alg == "ecdsa-p256":
        p256_decode_point(pk)            # 33-byte compressed, x < p, on the curve (SPEC 7.6 step 2)
    elif not 1 <= len(pk) <= 65536:
        raise ValueError(f"{where}.public_key() must return 1 to 65,536 bytes (SPEC 7.5 generic row)")


def _active_public_key() -> bytes:
    return bytes(_ACTIVE_SIGNER.public_key()) if _ACTIVE_SIGNER is not None else _PK


def _active_sign(msg: bytes) -> bytes:
    return _ACTIVE_SIGNER.sign(msg) if _ACTIVE_SIGNER is not None else _raw_sign(msg)


def active_alg() -> str:
    """The suite of the active (primary) signing identity."""
    return signer_alg(_ACTIVE_SIGNER)


def public_key_hex() -> str:
    return _active_public_key().hex()


def is_demo_key(alg: str, public_key: bytes) -> bool:
    """True for one of the published demo keys (SPEC section 2): the Ed25519 DEV key or the P-256 demo key."""
    return ((alg == "ed25519" and bytes(public_key) == publickey(_DEV_SEED))
            or (alg == "ecdsa-p256" and bytes(public_key) == P256_DEMO_PUBLIC_KEY))


def is_demo_identity() -> bool:
    """True when the active signing key is a public demo key -- signatures then prove format/integrity,
    not origin. Derived from the key itself (never a self-asserted flag), so an injected production key
    reads non-demo and an injected copy of a public demo key reads demo, both correctly."""
    return is_demo_key(active_alg(), _active_public_key())


class Ed25519Signer:
    """A software Ed25519 signer from a 32-byte seed (tests, demos, air-gapped dev keys; not constant-time)."""

    alg = "ed25519"

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        self._seed = bytes(seed)
        self._pk = publickey(self._seed)

    def public_key(self) -> bytes:
        return self._pk

    def sign(self, msg: bytes) -> bytes:
        return sign(msg, self._seed, self._pk)


class P256Signer:
    """A software ECDSA P-256 signer from a private scalar (RFC 6979 deterministic k, low-S; SPEC 7.16 items 1 and
    4). Tests and development only: it is not constant-time. Production keys come from an external signer."""

    alg = "ecdsa-p256"

    def __init__(self, d: int):
        # FOR DEMO AND DEVELOPMENT KEYS ONLY: production keys stay in an HSM behind an external signer (use_signer).
        self._d = _p256_check_scalar(d)
        self._pk = p256_publickey(d)

    def public_key(self) -> bytes:
        return self._pk

    def sign(self, msg: bytes) -> bytes:
        return p256_sign(msg, self._d)


def demo_p256_signer() -> P256Signer:
    """The published P-256 demo key (SPEC section 2) as a signer: integrity-only, never origin."""
    return P256Signer(P256_DEMO_D)


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


def _encode_sig(alg: str, sig: bytes) -> bytes:
    """SPEC 7.16 SIG-35: a P-256 signature leaves the producer as raw r || s with low S, whatever the signer
    emitted (DER or raw, either S). Other suites are passed through as the signer produced them."""
    return p256_raw_low_s(sig) if alg == "ecdsa-p256" else bytes(sig)


def verify_suite(alg: str, public_key: bytes, msg: bytes, sig: bytes) -> bool | None:
    """Producer-side check of one seal signature: True/False for a suite this kernel implements, None for any
    other (the caller must then use the signing library's own verify, SPEC 7.16 SIG-37)."""
    if alg == "ed25519":
        return verify(sig, msg, public_key)
    if alg == "ecdsa-p256":
        return p256_verify(sig, msg, public_key)
    return None


def sign_block(signer, digest: str) -> dict:
    """One seal signature block {alg, public_key, message, signature} from an explicit signer (a co-signer, SPEC
    7.8), signed over the 71 ASCII bytes of ``digest`` (7.2). The signer's key is checked against its suite first."""
    signer_key_problems(signer, where="cosigner")
    alg = signer_alg(signer)
    sig = _encode_sig(alg, signer.sign(digest.encode()))
    return {"alg": alg, "public_key": bytes(signer.public_key()).hex(), "message": SIGNATURE_MESSAGE,
            "signature": sig.hex()}


def _sign_digest(digest: str, message_label: str) -> dict:
    alg = active_alg()
    sig = _encode_sig(alg, _active_sign(digest.encode()))
    # NOTE: no "identity" field. Origin (demo vs production) is a property of the PINNED KEY, decided
    # by the VERIFIER at check time (proof_verify.pinned_key_is_demo / pinned_key_fingerprint), never a
    # self-asserted label carried in the bundle: such a label rode UNSIGNED in the signature block and
    # was ignored by every verdict path, so it could be flipped "demo"->"production" on a demo bundle
    # without detection -- a latent origin-spoofing trap. Dropped so a reader can never mistake it for
    # proof of origin, and REJECTED by every conforming verifier under the S1 key allowlist. (The
    # producer still knows its own backend via is_demo_identity() / IS_DEMO_IDENTITY.)
    return {
        "alg": alg,
        "public_key": _active_public_key().hex(),
        "message": message_label,
        "signature": sig.hex(),
    }


def sign_bundle_digest(bundle_sha256: str) -> dict:
    """Sign the bundle's manifest digest. The signature transitively covers inputs, result,
    and provenance (all hashed into bundle_sha256); tampering any of them breaks it. The block is
    exactly {alg, public_key, signature, message} with message == "bundle_sha256" (S1/S2)."""
    return _sign_digest(bundle_sha256, SIGNATURE_MESSAGE)
