"""The offline RFC 3161 time-stamp token checker of SPEC v4 10.7 (TT-1 to TT-41).

A strict DER reader, the CMS SignedData / TSTInfo walk, and the per-token check and classification of 10.7.6, in
the standard library only and independent of the producer. Tokens are attacker-supplied, so:

- every malformed input becomes a class (``malformed`` and so on), never an exception that escapes `classify_token`;
- no RSA or ECDSA operation runs until the token has a selected certificate that matches a receiver pin (K1) and
  has passed the window checks (K2) (TT-11, "Pin first");
- a pinned RSA key is bounded to 2,048 to 4,096 bits with e = 65537 (TT-14), every DER tree to depth 32 (TT-12), and
  a token to 200,000 characters and 150,000 decoded bytes (TT-6, TT-8).

The P-256 arithmetic is this verifier's own (`proof_verify.verify`, written for K2), reused here; RSA PKCS#1 v1.5
verification is one modular exponentiation and a byte-for-byte compare of the full EMSA encoding (B6), never a
DigestInfo parse. Every constant below is copied from SPEC v4 10.7, which copies it from the primary documents
(RFC 3161, RFC 5652, RFC 5035, RFC 5816, RFC 5754, RFC 3370, RFC 5480, RFC 8017, X.690, SP 800-186).
"""
from __future__ import annotations

import base64
import binascii
import calendar
import contextvars
import hashlib
import re
from typing import Any

# --- constants (SPEC v4 10.7.5; DER contents of each OBJECT IDENTIFIER, without the 06 tag and length) ----------
OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")          # 1.2.840.113549.1.7.2
OID_TSTINFO = bytes.fromhex("2a864886f70d0109100104")          # 1.2.840.113549.1.9.16.1.4
OID_CONTENT_TYPE = bytes.fromhex("2a864886f70d010903")         # 1.2.840.113549.1.9.3
OID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")       # 1.2.840.113549.1.9.4
OID_SIGNING_CERT_V2 = bytes.fromhex("2a864886f70d010910022f")  # 1.2.840.113549.1.9.16.2.47
OID_SIGNING_CERT = bytes.fromhex("2a864886f70d010910020c")     # 1.2.840.113549.1.9.16.2.12
OID_SHA256 = bytes.fromhex("608648016503040201")               # 2.16.840.1.101.3.4.2.1
OID_SHA384 = bytes.fromhex("608648016503040202")               # 2.16.840.1.101.3.4.2.2
OID_SHA512 = bytes.fromhex("608648016503040203")               # 2.16.840.1.101.3.4.2.3
OID_RSA = bytes.fromhex("2a864886f70d010101")                  # 1.2.840.113549.1.1.1 rsaEncryption
OID_SHA256_RSA = bytes.fromhex("2a864886f70d01010b")           # 1.2.840.113549.1.1.11
OID_SHA384_RSA = bytes.fromhex("2a864886f70d01010c")           # 1.2.840.113549.1.1.12
OID_SHA512_RSA = bytes.fromhex("2a864886f70d01010d")           # 1.2.840.113549.1.1.13
OID_ECDSA_SHA256 = bytes.fromhex("2a8648ce3d040302")           # 1.2.840.10045.4.3.2
OID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")            # 1.2.840.10045.2.1
OID_SECP256R1 = bytes.fromhex("2a8648ce3d030107")              # 1.2.840.10045.3.1.7

#: TT-26: the recognised hashes.
HASHES = {OID_SHA256: "sha256", OID_SHA384: "sha384", OID_SHA512: "sha512"}
#: TT-27: signatureAlgorithm -> (family, the hash it fixes or None, parameter rule).
SIG_ALGS = {
    OID_RSA: ("rsa", None, "null"),                 # RFC 3370 3.2: params MUST be NULL; the hash is digestAlgorithm
    OID_SHA256_RSA: ("rsa", "sha256", "null_or_absent"),   # RFC 5754 3.2
    OID_SHA384_RSA: ("rsa", "sha384", "null_or_absent"),
    OID_SHA512_RSA: ("rsa", "sha512", "null_or_absent"),
    OID_ECDSA_SHA256: ("ecdsa", "sha256", "absent"),       # RFC 5754 3.3; RFC 5758 3.2
}
#: B6 step 4: the DigestInfo prefix T of each hash (RFC 8017 9.2 Note 1).
DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_HASH_FN = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
#: K2: the signature suite name of each family, as the policy's `suites` member names it (7.13).
SUITE_OF = {"rsa": "rsa-pkcs1v15", "ecdsa": "ecdsa-p256"}

MAX_DEPTH = 32                 # TT-12
MAX_NODES = 4096               # TT-12: DER nodes decoded per token by the 10.7.5 checks, over every tree of that token
TOKEN_MAX_CHARS = 200_000      # TT-6
TOKEN_MAX_BYTES = 150_000      # TT-8
CERT_MAX_CHARS = 200_000       # 10.7.3 `cert`
MAX_TOKENS = 64                # TT-13
RSA_MIN, RSA_MAX = 1 << 2047, 1 << 4096   # TT-14: 2^2047 <= n < 2^4096
RSA_E = 65537
TOKEN_RE = re.compile(r"MI[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", re.ASCII)
_GENTIME_RE = re.compile(rb"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]+))?Z")
_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)
_PIN_ID_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{0,63}", re.ASCII)
_SPKI_HASH_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DOTTED_RE = re.compile(r"[0-2](\.(0|[1-9][0-9]*)){1,63}", re.ASCII)
_PIN_KEYS = frozenset({"id", "spki_sha256", "cert", "trusted_from", "trusted_until", "distrusted_after",
                       "policy_oids"})
_PIN_REQUIRED = _PIN_KEYS - {"cert"}
MAX_PINS = 16

CLASSES = ("malformed", "unpinned", "out_of_window", "invalid", "accepted")
HIGH_S_ADVISORY = "high_s (advisory)"


#: The node budget of the token being decoded: a one-element list (nodes decoded so far), or None otherwise. It covers
#: every tree `parse_token` decodes for one token (the 10.7.5 checks: the token, TSTInfo, the ECDSA signature value,
#: each certificate's SPKI), so an overrun is always `malformed`. A pin `cert` (read with the policy) and the B-step
#: re-reads of the selected certificate's SPKI (a subtree already counted, or a pin's) are outside it.
_NODE_BUDGET: contextvars.ContextVar[list[int] | None] = contextvars.ContextVar("_NODE_BUDGET", default=None)


class Malformed(Exception):
    """A failure of 10.7.2 or 10.7.5: the token is classed `malformed`."""


class _Invalid(Exception):
    """A failure of B1 to B6: the token is classed `invalid`."""


# --- strict DER (10.7.5.1, TT-16 to TT-18) -------------------------------------------------------------------------

class Node:
    """One TLV of a decoded tree. ``ident`` is the identifier octets, ``start``/``end`` bound the whole TLV and
    ``body`` is the offset of the contents in ``data``."""

    __slots__ = ("body", "children", "cls", "cons", "data", "end", "ident", "num", "start")

    def __init__(self, data, start, body, end, ident, cls, cons, num, children):
        self.data, self.start, self.body, self.end = data, start, body, end
        self.ident, self.cls, self.cons, self.num, self.children = ident, cls, cons, num, children

    @property
    def content(self) -> bytes:
        return self.data[self.body:self.end]

    @property
    def tlv(self) -> bytes:
        return self.data[self.start:self.end]

    @property
    def tag(self) -> int:
        """The first identifier octet (every tag this checker interprets uses the low-tag-number form)."""
        return self.data[self.start]


def parse_der(data: bytes, what: str = "token") -> Node:
    """Decode ``data`` as exactly one complete DER TLV tree (TT-16, TT-17), depth at most 32 (TT-12), descending into
    every constructed encoding. Raises Malformed."""
    if not data:
        raise Malformed(f"{what}: empty DER")
    node = _parse(data, 0, len(data), 1, what)
    if node.end != len(data):
        raise Malformed(f"{what}: {len(data) - node.end} byte(s) follow the outermost element (TT-17)")
    return node


def _parse(data: bytes, pos: int, end: int, depth: int, what: str) -> Node:
    if depth > MAX_DEPTH:
        raise Malformed(f"{what}: DER nesting deeper than {MAX_DEPTH} (TT-12)")
    budget = _NODE_BUDGET.get()
    if budget is not None:
        budget[0] += 1
        if budget[0] > MAX_NODES:
            raise Malformed(f"{what}: more than {MAX_NODES:,} DER nodes decoded for one token (TT-12)")
    if pos >= end:
        raise Malformed(f"{what}: truncated DER (no identifier)")
    first = data[pos]
    cls, cons, num = first >> 6, bool(first & 0x20), first & 0x1F
    p = pos + 1
    if num == 0x1F:                                   # high-tag-number form (X.690 8.1.2.4)
        num, lead = 0, True
        while True:
            if p >= end:
                raise Malformed(f"{what}: truncated high tag number")
            c = data[p]
            p += 1
            if lead and c == 0x80:
                raise Malformed(f"{what}: high tag number with a leading 0x80 octet is not minimal (TT-16 item 4)")
            lead = False
            num = (num << 7) | (c & 0x7F)
            if num >= 1 << 31:
                raise Malformed(f"{what}: tag number too large")
            if not c & 0x80:
                break
        if num < 31:
            raise Malformed(f"{what}: tag number {num} in the high-tag-number form is not minimal (TT-16 item 4)")
    ident_end = p
    if p >= end:
        raise Malformed(f"{what}: truncated DER (no length)")
    lb = data[p]
    p += 1
    if lb == 0x80:
        raise Malformed(f"{what}: indefinite length (TT-16 item 1)")
    if lb & 0x80:
        n = lb & 0x7F
        if n > 4:
            raise Malformed(f"{what}: a length of {n} octets (at most 4, TT-16 item 2)")
        if p + n > end:
            raise Malformed(f"{what}: truncated length")
        if data[p] == 0:
            raise Malformed(f"{what}: a long-form length with a leading 0x00 octet is not minimal (TT-16 item 2)")
        length = int.from_bytes(data[p:p + n], "big")
        p += n
        if length < 128:
            raise Malformed(f"{what}: a length below 128 in the long form is not minimal (TT-16 item 2)")
    else:
        length = lb
    if p + length > end:
        raise Malformed(f"{what}: contents overrun the enclosing element (TT-16 item 3)")
    if cls == 0 and num in (3, 4) and cons:
        raise Malformed(f"{what}: a constructed {'BIT' if num == 3 else 'OCTET'} STRING (TT-16 item 5)")
    children = None
    if cons:
        children = []
        q, stop = p, p + length
        while q < stop:
            child = _parse(data, q, stop, depth + 1, what)
            children.append(child)
            q = child.end
    return Node(data, pos, p, p + length, data[pos:ident_end], cls, cons, num, children)


def _need(node: Node | None, tag: int, what: str) -> Node:
    if node is None or node.ident != bytes([tag]):
        got = "nothing" if node is None else node.ident.hex()
        raise Malformed(f"{what}: expected tag {tag:02x}, got {got}")
    return node


def der_int(node: Node, what: str, *, nonneg: bool = False) -> int:
    """TT-18 INTEGER: minimal two's complement; ``nonneg`` refuses a negative value."""
    _need(node, 0x02, what)
    c = node.content
    if not c:
        raise Malformed(f"{what}: empty INTEGER")
    if len(c) > 1 and ((c[0] == 0 and not c[1] & 0x80) or (c[0] == 0xFF and c[1] & 0x80)):
        raise Malformed(f"{what}: INTEGER is not minimal (TT-18)")
    v = int.from_bytes(c, "big", signed=True)
    if nonneg and v < 0:
        raise Malformed(f"{what}: a negative INTEGER where a positive value is required (TT-18)")
    return v


def _int_contents_ok(c: bytes) -> bool:
    return bool(c) and not (len(c) > 1 and ((c[0] == 0 and not c[1] & 0x80) or (c[0] == 0xFF and c[1] & 0x80)))


#: Hostile-input limit of this verifier (SPEC 10.7.4 bounds total work; 10.7.5 names no OID size): a sub-identifier
#: of at most 20 octets (140 bits). The largest real arcs are the 128-bit UUID arcs under 2.25 (19 octets); a longer
#: one is malformed, refused while scanning, before any arc is decoded, so an oversized OID costs linear time only.
MAX_SUBID_OCTETS = 20


def der_oid(node: Node, what: str) -> bytes:
    """TT-18 OBJECT IDENTIFIER: minimal base-128 sub-identifiers, each at most MAX_SUBID_OCTETS octets. Returns the
    contents octets. One linear scan; no arc is decoded here."""
    _need(node, 0x06, what)
    c = node.content
    if not c or c[-1] & 0x80:
        raise Malformed(f"{what}: OBJECT IDENTIFIER is empty or truncated")
    lead, run = True, 0
    for b in c:
        if lead and b == 0x80:
            raise Malformed(f"{what}: OBJECT IDENTIFIER sub-identifier with a leading 0x80 octet (TT-18)")
        run += 1
        if run > MAX_SUBID_OCTETS:
            raise Malformed(f"{what}: OBJECT IDENTIFIER sub-identifier longer than {MAX_SUBID_OCTETS} octets "
                            "(verifier input limit)")
        lead = not b & 0x80
        if lead:
            run = 0
    return c


def dotted(oid: bytes) -> str:
    """The dotted form of OID contents that passed `der_oid` (every arc at most 20 octets, so each step below works
    on an integer of at most 140 bits: linear in the OID length)."""
    arcs, v, n = [], 0, 0
    for b in oid:
        v = (v << 7) | (b & 0x7F)
        n += 1
        if n > MAX_SUBID_OCTETS:          # a caller that skipped der_oid: never decode an oversized arc
            raise Malformed("an OBJECT IDENTIFIER arc is too large to represent")
        if not b & 0x80:
            arcs.append(v)
            v, n = 0, 0
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    try:
        return ".".join(str(a) for a in head + arcs[1:])
    except ValueError as exc:
        raise Malformed("an OBJECT IDENTIFIER arc is too large to represent") from exc


def der_bool(node: Node, what: str) -> bool:
    """TT-18 BOOLEAN: contents exactly 0x00 or 0xFF."""
    _need(node, 0x01, what)
    if node.content not in (b"\x00", b"\xff"):
        raise Malformed(f"{what}: BOOLEAN contents must be 00 or FF (TT-18)")
    return node.content == b"\xff"


def _is_null(node: Node, what: str) -> bool:
    """True for a NULL; a NULL with contents is malformed (TT-18). False for any other element."""
    if node.ident == b"\x05":
        if node.content:
            raise Malformed(f"{what}: NULL with contents (TT-18)")
        return True
    return False


def _octets(node: Node, what: str) -> bytes:
    return _need(node, 0x04, what).content


def _children(node: Node, tag: int, what: str) -> list[Node]:
    return list(_need(node, tag, what).children)


# --- algorithm identifiers (TT-26, TT-27) ---------------------------------------------------------------------------

def _algid(node: Node, what: str) -> tuple[bytes, str, Node | None]:
    """AlgorithmIdentifier: (OID contents, "absent" | "null" | "other", the parameters node)."""
    ch = _children(node, 0x30, what)
    if not 1 <= len(ch) <= 2:
        raise Malformed(f"{what}: AlgorithmIdentifier has {len(ch)} components")
    oid = der_oid(ch[0], what)
    if len(ch) == 1:
        return oid, "absent", None
    return oid, ("null" if _is_null(ch[1], what) else "other"), ch[1]


def _hash_algid(node: Node, what: str) -> tuple[bytes, str]:
    """TT-26: a hash AlgorithmIdentifier's parameters are absent or NULL, anything else is malformed."""
    oid, params, _ = _algid(node, what)
    if params == "other":
        raise Malformed(f"{what}: hash AlgorithmIdentifier parameters must be absent or NULL (TT-26)")
    return oid, params


# --- GeneralizedTime (TT-24) ----------------------------------------------------------------------------------------

def gentime(node: Node) -> tuple[tuple[int, str], str]:
    """TT-24: (the exact instant as (epoch seconds, fraction digits without trailing zeros), the report string)."""
    if node.ident != b"\x18":
        raise Malformed("genTime is not a GeneralizedTime (TT-24)")
    m = _GENTIME_RE.fullmatch(node.content)
    if not m:
        raise Malformed("genTime must be YYYYMMDDhhmmss[.f]Z with seconds and a final Z (TT-24)")
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    frac = (m.group(7) or b"").decode("ascii")
    if m.group(7) is not None and frac.endswith("0"):
        raise Malformed("genTime fraction has a trailing 0 (RFC 3161 2.4.2: 'MUST omit all trailing 0's', TT-24)")
    if not (y >= 1 and 1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and h <= 23 and mi <= 59
            and s <= 59):
        raise Malformed("genTime is not a real calendar date and time (TT-24)")
    secs = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    shown = f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}" + (f".{frac}" if frac else "") + "Z"
    return (secs, frac), shown


def utc_instant(s: str) -> tuple[int, str]:
    """A UTC timestamp of SPEC 2.3 as an instant comparable with `gentime` instants (fraction "" sorts first)."""
    return (calendar.timegm((int(s[0:4]), int(s[5:7]), int(s[8:10]), int(s[11:13]), int(s[14:16]),
                             int(s[17:19]), 0, 0, 0)), "")


# Instants are (seconds, fraction digits without trailing zeros): tuple order is time order, because for two digit
# strings with no trailing zeros, string order is the order of the decimal fractions they denote.


# --- Certificates (TT-32) --------------------------------------------------------------------------------------------

class Cert:
    __slots__ = ("der", "issuer", "serial", "spki", "validity")

    def __init__(self, der, issuer, serial, validity, spki):
        self.der, self.issuer, self.serial, self.validity, self.spki = der, issuer, serial, validity, spki

    @property
    def spki_sha256(self) -> str:
        return hashlib.sha256(self.spki).hexdigest()


def parse_cert(node: Node, what: str = "certificate") -> Cert:
    """TT-32: Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }, located to the SPKI.
    The SPKI contents are not decoded here, and the certificate signature is never checked."""
    ch = _children(node, 0x30, what)
    if len(ch) != 3:
        raise Malformed(f"{what}: a Certificate has 3 components, not {len(ch)}")
    tbs = _children(ch[0], 0x30, f"{what}.tbsCertificate")
    _need(ch[1], 0x30, f"{what}.signatureAlgorithm")
    _need(ch[2], 0x03, f"{what}.signatureValue")
    i = 0
    if i < len(tbs) and tbs[i].ident == b"\xa0":
        i += 1
    if len(tbs) < i + 6:
        raise Malformed(f"{what}: tbsCertificate is missing components")
    serial = _need(tbs[i], 0x02, f"{what}.serialNumber")
    if not _int_contents_ok(serial.content):
        raise Malformed(f"{what}: serialNumber INTEGER is not minimal (TT-18)")
    _need(tbs[i + 1], 0x30, f"{what}.signature")
    issuer = _need(tbs[i + 2], 0x30, f"{what}.issuer")
    validity = _need(tbs[i + 3], 0x30, f"{what}.validity")
    _need(tbs[i + 4], 0x30, f"{what}.subject")
    spki = _need(tbs[i + 5], 0x30, f"{what}.subjectPublicKeyInfo")
    rest = [t.ident for t in tbs[i + 6:]]
    allowed = [b"\x81", b"\xa1", b"\x82", b"\xa2", b"\xa3"]
    pos = 0
    for t in rest:                                    # optional [1], [2], [3] in order, each at most once
        while pos < len(allowed) and allowed[pos] != t:
            pos += 1
        if pos == len(allowed):
            raise Malformed(f"{what}: unexpected tbsCertificate component {t.hex()}")
        pos += 2 if t in (b"\x81", b"\x82") else 1
    return Cert(node.tlv, issuer.tlv, serial.content, validity, spki.tlv)


def _validity_text(v: Node) -> str | None:
    """TT-33 advisory: the validity window as text, or None if it does not read as two times."""
    try:
        out = []
        for t in v.children:
            c = t.content.decode("ascii")
            if t.ident == b"\x17" and re.fullmatch(r"[0-9]{12}Z", c):
                yy = int(c[:2])
                c = f"{1900 + yy if yy >= 50 else 2000 + yy}{c[2:]}"
            elif not (t.ident == b"\x18" and re.fullmatch(r"[0-9]{14}Z", c)):
                return None
            out.append(f"{c[0:4]}-{c[4:6]}-{c[6:8]}T{c[8:10]}:{c[10:12]}:{c[12:14]}Z")
        return f"{out[0]} to {out[1]}" if len(out) == 2 else None
    except (UnicodeDecodeError, TypeError, IndexError):
        return None


# --- strict base64 (TT-6 to TT-8) ------------------------------------------------------------------------------------

def strict_b64(s: Any, max_chars: int, what: str, max_bytes: int | None = None) -> bytes:
    if not isinstance(s, str):
        raise Malformed(f"{what} is not a string (TT-6)")
    if len(s) > max_chars:
        raise Malformed(f"{what} has {len(s)} characters (at most {max_chars:,}, TT-6)")
    if not TOKEN_RE.fullmatch(s):
        raise Malformed(f"{what} is not strict base64 of a DER SEQUENCE (TT-6)")
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Malformed(f"{what} is not strict base64 (TT-6)") from exc
    if base64.b64encode(raw).decode("ascii") != s:
        raise Malformed(f"{what} does not re-encode to itself: non-zero unused bits in its last character (TT-7)")
    if max_bytes is not None and len(raw) > max_bytes:
        raise Malformed(f"{what} decodes to {len(raw)} bytes (at most {max_bytes:,}, TT-8)")
    return raw


# --- TSA pins (10.7.3, TT-9, TT-10) ----------------------------------------------------------------------------------

def _utc_ok(v: Any) -> bool:
    if not (isinstance(v, str) and _UTC_RE.fullmatch(v)):
        return False
    y, mo, d, h, mi, s = int(v[0:4]), int(v[5:7]), int(v[8:10]), int(v[11:13]), int(v[14:16]), int(v[17:19])
    return y >= 1 and 1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and h <= 23 and mi <= 59 and s <= 59


def pin_problem(tsas: Any) -> str | None:
    """TT-9: the 10.7.3 table for `policy.tsas`. None == well-formed (the policy is refused otherwise)."""
    if not (isinstance(tsas, list) and len(tsas) <= MAX_PINS):
        return f"tsas must be an array of 0 to {MAX_PINS} TSA pin objects"
    ids, spkis = set(), set()
    for i, p in enumerate(tsas):
        w = f"tsas[{i}]"
        if not isinstance(p, dict):
            return f"{w} is not an object"
        if not (set(p) <= _PIN_KEYS and _PIN_REQUIRED <= set(p)):
            return f"{w} must have exactly the keys {sorted(_PIN_REQUIRED)} and optionally cert (TT-9)"
        if not (isinstance(p["id"], str) and _PIN_ID_RE.fullmatch(p["id"])):
            return f"{w}.id must match [a-z0-9][a-z0-9.-]{{0,63}}"
        if not (isinstance(p["spki_sha256"], str) and _SPKI_HASH_RE.fullmatch(p["spki_sha256"])):
            return f"{w}.spki_sha256 must be 64 lowercase hex"
        if p["id"] in ids or p["spki_sha256"] in spkis:
            return f"{w} repeats the id or the spki_sha256 of an earlier pin (unique within tsas, 10.7.3)"
        ids.add(p["id"])
        spkis.add(p["spki_sha256"])
        if not _utc_ok(p["trusted_from"]):
            return f"{w}.trusted_from must be a UTC timestamp (SPEC 2.3)"
        for k in ("trusted_until", "distrusted_after"):
            if p[k] is not None and not _utc_ok(p[k]):
                return f"{w}.{k} must be a UTC timestamp or null"
        if p["trusted_until"] is not None and p["trusted_until"] < p["trusted_from"]:
            return f"{w}.trusted_until is earlier than trusted_from"
        po = p["policy_oids"]
        if not (isinstance(po, list) and len(po) <= 16 and all(isinstance(x, str) for x in po)
                and len(set(po)) == len(po) and all(len(x) <= 128 and _DOTTED_RE.fullmatch(x) for x in po)):
            return f"{w}.policy_oids must be 0 to 16 unique dotted OIDs of at most 128 characters"
        if "cert" in p:
            try:
                cert = parse_cert(parse_der(strict_b64(p["cert"], CERT_MAX_CHARS, f"{w}.cert"), f"{w}.cert"),
                                  f"{w}.cert")
            except Malformed as exc:
                return f"{w}.cert does not decode to one DER Certificate: {exc}"
            if cert.spki_sha256 != p["spki_sha256"]:
                return f"{w}.cert: SHA-256 of its subjectPublicKeyInfo is not spki_sha256 (10.7.3)"
    return None


def pin_cert(pin: dict) -> Cert | None:
    """The parsed `cert` of a pin that passed `pin_problem` (None when it has none)."""
    if "cert" not in pin:
        return None
    raw = strict_b64(pin["cert"], CERT_MAX_CHARS, "cert")
    return parse_cert(parse_der(raw, "cert"), "cert")


# --- the token structure (10.7.5) -----------------------------------------------------------------------------------

class _Ess:
    __slots__ = ("cert_hash", "hash")

    def __init__(self, h, cert_hash):
        self.hash, self.cert_hash = h, cert_hash


class Token:
    """The parts of a token the classification reads, after every 10.7.5 rule passed."""

    __slots__ = (
        "accuracy",
        "certs",
        "ct_attr",
        "digest_oid",
        "ecdsa_rs",
        "econtent",
        "ess_v1",
        "ess_v2",
        "g",
        "gen_time",
        "imprint",
        "imprint_oid",
        "md_attr",
        "nonce",
        "ordering",
        "policy",
        "sa_bytes",
        "sid_issuer",
        "sid_serial",
        "sid_ski",
        "sig_oid",
        "sig_params",
        "signature",
        "token_id",
        "version",
    )


def parse_token(raw: bytes) -> Token:
    """Every rule of 10.7.5 (TT-16 to TT-32), checked before any pin lookup. Raises Malformed."""
    t = Token()
    root = parse_der(raw, "token")
    ci = _children(root, 0x30, "ContentInfo")
    if len(ci) != 2:
        raise Malformed("ContentInfo must have contentType and content")
    if der_oid(ci[0], "ContentInfo.contentType") != OID_SIGNED_DATA:
        raise Malformed("contentType is not id-signedData (TT-20)")
    wrap = _children(ci[1], 0xA0, "ContentInfo.content [0]")
    if len(wrap) != 1:
        raise Malformed("ContentInfo.content [0] must hold one SignedData (TT-20)")
    sd = _children(wrap[0], 0x30, "SignedData")
    it = iter(sd)
    nxt = next(it, None)
    der_int(_need(nxt, 0x02, "SignedData.version"), "SignedData.version")
    _need(next(it, None), 0x31, "SignedData.digestAlgorithms")
    eci = _children(next(it, None), 0x30, "encapContentInfo")
    if not eci or der_oid(eci[0], "eContentType") != OID_TSTINFO:
        raise Malformed("eContentType is not id-ct-TSTInfo (TT-21)")
    if len(eci) != 2:
        raise Malformed("eContent is absent (TT-21)")
    ec = _children(eci[1], 0xA0, "eContent [0]")
    if len(ec) != 1 or ec[0].ident != b"\x04":
        raise Malformed("eContent must be one primitive OCTET STRING (TT-21)")
    t.econtent = ec[0].content
    nxt = next(it, None)
    t.certs = []
    if nxt is not None and nxt.ident == b"\xa0":
        for j, c in enumerate(nxt.children):
            if c.ident == b"\x30":                       # TT-22: a candidate certificate
                t.certs.append(parse_cert(c, f"certificates[{j}]"))
        nxt = next(it, None)
    if nxt is not None and nxt.ident == b"\xa1":         # crls: walked (TT-16) and ignored
        nxt = next(it, None)
    sis = _children(nxt, 0x31, "SignedData.signerInfos")
    if next(it, None) is not None:
        raise Malformed("SignedData has components after signerInfos")
    if len(sis) != 1:
        raise Malformed(f"signerInfos holds {len(sis)} SignerInfo (exactly one: RFC 3161 2.4.2, TT-21)")
    _signer_info(sis[0], t)
    _tstinfo(t.econtent, t)
    return t


def _signer_info(node: Node, t: Token) -> None:
    """TT-25 to TT-31."""
    si = _children(node, 0x30, "SignerInfo")
    it = iter(si)
    der_int(_need(next(it, None), 0x02, "SignerInfo.version"), "SignerInfo.version")
    sid = next(it, None)
    t.sid_issuer = t.sid_serial = t.sid_ski = None
    if sid is not None and sid.ident == b"\x30":
        parts = sid.children
        if len(parts) != 2:
            raise Malformed("sid issuerAndSerialNumber must be issuer and serialNumber")
        _need(parts[0], 0x30, "sid.issuer")
        _need(parts[1], 0x02, "sid.serialNumber")
        if not _int_contents_ok(parts[1].content):
            raise Malformed("sid.serialNumber INTEGER is not minimal (TT-18)")
        t.sid_issuer, t.sid_serial = parts[0].tlv, parts[1].content
    elif sid is not None and sid.ident == b"\x80":
        t.sid_ski = sid.content
    else:
        raise Malformed("SignerInfo.sid is neither issuerAndSerialNumber nor [0] subjectKeyIdentifier (TT-25)")
    t.digest_oid, _ = _hash_algid(_need(next(it, None), 0x30, "SignerInfo.digestAlgorithm"), "digestAlgorithm")
    sa = next(it, None)
    if sa is None or sa.ident != b"\xa0":
        raise Malformed("SignerInfo.signedAttrs [0] is required (TT-25)")
    t.sa_bytes = b"\x31" + sa.tlv[1:]                   # the one-octet re-tag (RFC 5652 5.4), the only re-encoding
    t.token_id = "sha256:" + hashlib.sha256(t.sa_bytes).hexdigest()
    t.sig_oid, t.sig_params, _ = _algid(_need(next(it, None), 0x30, "SignerInfo.signatureAlgorithm"),
                                        "signatureAlgorithm")
    t.signature = _octets(next(it, None) or _missing("SignerInfo.signature"), "SignerInfo.signature")
    rest = list(it)
    if rest and rest[0].ident == b"\xa1":                # unsignedAttrs: walked and ignored
        rest = rest[1:]
    if rest:
        raise Malformed("SignerInfo has components out of order or extra (TT-25)")
    rule = SIG_ALGS.get(t.sig_oid)
    if rule is not None:                                  # TT-27 parameter rules on a listed OID
        want = rule[2]
        if (want == "null" and t.sig_params != "null") or (want == "absent" and t.sig_params != "absent") \
                or (want == "null_or_absent" and t.sig_params == "other"):
            raise Malformed(f"signatureAlgorithm {dotted(t.sig_oid)}: parameters must be "
                            f"{want.replace('_', ' ')} (TT-27)")
    t.ecdsa_rs = None
    if rule is not None and rule[0] == "ecdsa":            # TT-28
        sig = parse_der(t.signature, "ECDSA signature")
        rs = _children(sig, 0x30, "ECDSA signature")
        if len(rs) != 2:
            raise Malformed("ECDSA signature must be SEQUENCE { r, s } (TT-28)")
        t.ecdsa_rs = (der_int(rs[0], "ECDSA r", nonneg=True), der_int(rs[1], "ECDSA s", nonneg=True))
    _signed_attrs(sa, t)


def _missing(what: str) -> Node:
    raise Malformed(f"{what} is missing")


def _signed_attrs(sa: Node, t: Token) -> None:
    """TT-29 to TT-31."""
    if not sa.children:
        raise Malformed("signedAttrs is empty (TT-29)")
    seen: dict[bytes, Node] = {}
    for a in sa.children:
        parts = _children(a, 0x30, "Attribute")
        if len(parts) != 2:
            raise Malformed("an Attribute is SEQUENCE { attrType, attrValues } (TT-29)")
        typ = der_oid(parts[0], "attrType")
        _need(parts[1], 0x31, "attrValues")
        if typ in seen:
            raise Malformed(f"signedAttrs repeats the attribute type {dotted(typ)} (TT-29)")
        seen[typ] = parts[1]

    def one(oid: bytes, name: str) -> Node | None:
        vals = seen.get(oid)
        if vals is None:
            return None
        if len(vals.children) != 1:
            raise Malformed(f"the {name} attribute must have exactly one value (TT-29)")
        return vals.children[0]

    ct, md = one(OID_CONTENT_TYPE, "content-type"), one(OID_MESSAGE_DIGEST, "message-digest")
    if ct is None:
        raise Malformed("signedAttrs has no content-type attribute (TT-29)")
    if md is None:
        raise Malformed("signedAttrs has no message-digest attribute (TT-29)")
    t.ct_attr = der_oid(ct, "content-type value")
    t.md_attr = _octets(md, "message-digest value")
    v2, v1 = one(OID_SIGNING_CERT_V2, "signing-certificate-v2"), one(OID_SIGNING_CERT, "signing-certificate")
    if v2 is None and v1 is None:
        raise Malformed("signedAttrs has neither signing-certificate attribute (TT-29, RFC 5816 2.2.1)")
    t.ess_v2 = _ess_v2(v2) if v2 is not None else None
    t.ess_v1 = _ess_v1(v1) if v1 is not None else None    # well formed whenever present (TT-31)


def _ess_certs(value: Node, name: str) -> list[Node]:
    parts = _children(value, 0x30, name)
    if not 1 <= len(parts) <= 2:
        raise Malformed(f"{name} is SEQUENCE {{ certs, policies OPTIONAL }}")
    certs = _children(parts[0], 0x30, f"{name}.certs")
    if not certs:
        raise Malformed(f"{name}.certs is empty")
    if len(parts) == 2:
        _need(parts[1], 0x30, f"{name}.policies")
    return certs


def _ess_v2(value: Node) -> _Ess:
    """TT-30 (RFC 5035 4): only certs[0] identifies the certificate; later entries are parsed and ignored."""
    first = None
    for j, c in enumerate(_ess_certs(value, "SigningCertificateV2")):
        w = f"ESSCertIDv2[{j}]"
        ch = _children(c, 0x30, w)
        k, h = 0, "sha256"
        if ch and ch[0].ident == b"\x30":
            oid, _ = _hash_algid(ch[0], f"{w}.hashAlgorithm")
            if oid == OID_SHA256:
                raise Malformed(f"{w}.hashAlgorithm encodes its DEFAULT id-sha256 (X.690 11.5, TT-30)")
            h = HASHES.get(oid, "other")
            k = 1
        if len(ch) <= k:
            raise Malformed(f"{w} has no certHash")
        cert_hash = _octets(ch[k], f"{w}.certHash")
        if h == "sha256" and len(cert_hash) != 32:
            raise Malformed(f"{w}.certHash is {len(cert_hash)} octets (32 for SHA-256, TT-30)")
        if len(ch) > k + 2 or (len(ch) == k + 2 and ch[k + 1].ident != b"\x30"):
            raise Malformed(f"{w} has components other than certHash and issuerSerial")
        if first is None:
            first = _Ess(h, cert_hash)
    return first


def _ess_v1(value: Node) -> _Ess:
    """TT-31: ESSCertID ::= SEQUENCE { certHash OCTET STRING (20, SHA-1), issuerSerial OPTIONAL }."""
    first = None
    for j, c in enumerate(_ess_certs(value, "SigningCertificate")):
        w = f"ESSCertID[{j}]"
        ch = _children(c, 0x30, w)
        if not ch:
            raise Malformed(f"{w} has no certHash")
        cert_hash = _octets(ch[0], f"{w}.certHash")
        if len(cert_hash) != 20:
            raise Malformed(f"{w}.certHash is {len(cert_hash)} octets (20, SHA-1, TT-31)")
        if len(ch) > 2 or (len(ch) == 2 and ch[1].ident != b"\x30"):
            raise Malformed(f"{w} has components other than certHash and issuerSerial")
        if first is None:
            first = _Ess("sha1", cert_hash)
    return first


def _tstinfo(econtent: bytes, t: Token) -> None:
    """TT-23, TT-24: eContent decodes as TSTInfo (its own tree, depth from 1)."""
    root = parse_der(econtent, "TSTInfo")
    ch = _children(root, 0x30, "TSTInfo")
    it = iter(ch)
    v = next(it, None)
    t.version = der_int(_need(v, 0x02, "TSTInfo.version"), "TSTInfo.version")
    if t.version != 1:
        raise Malformed(f"TSTInfo.version is {t.version if abs(t.version) < 10**6 else 'not 1'} (MUST be 1, TT-23)")
    t.policy = dotted(der_oid(next(it, None) or _missing("TSTInfo.policy"), "TSTInfo.policy"))
    mi = _children(next(it, None), 0x30, "messageImprint")
    if len(mi) != 2:
        raise Malformed("messageImprint is SEQUENCE { hashAlgorithm, hashedMessage }")
    t.imprint_oid, _ = _hash_algid(mi[0], "messageImprint.hashAlgorithm")
    t.imprint = _octets(mi[1], "messageImprint.hashedMessage")
    der_int(next(it, None) or _missing("TSTInfo.serialNumber"), "TSTInfo.serialNumber")
    t.g, t.gen_time = gentime(next(it, None) or _missing("TSTInfo.genTime"))
    rest = list(it)
    t.accuracy, t.ordering, t.nonce = None, False, None
    k = 0
    if k < len(rest) and rest[k].ident == b"\x30":
        t.accuracy = _accuracy(rest[k])
        k += 1
    if k < len(rest) and rest[k].ident == b"\x01":
        t.ordering = der_bool(rest[k], "TSTInfo.ordering")
        if not t.ordering:
            raise Malformed("TSTInfo.ordering encodes its DEFAULT FALSE (X.690 11.5, TT-23)")
        k += 1
    if k < len(rest) and rest[k].ident == b"\x02":
        t.nonce = der_int(rest[k], "TSTInfo.nonce")
        k += 1
    if k < len(rest) and rest[k].ident == b"\xa0":
        k += 1
    if k < len(rest) and rest[k].ident == b"\xa1":
        k += 1
    if k != len(rest):
        raise Malformed("TSTInfo has a component that is not allowed or out of order (TT-23)")


def _accuracy(node: Node) -> dict:
    out = {"seconds": None, "millis": None, "micros": None}
    k = 0
    ch = node.children
    if k < len(ch) and ch[k].ident == b"\x02":
        out["seconds"] = der_int(ch[k], "accuracy.seconds")
        k += 1
    for tag, name in ((0x80, "millis"), (0x81, "micros")):
        if k < len(ch) and ch[k].ident == bytes([tag]):
            c = ch[k].content
            if not _int_contents_ok(c):
                raise Malformed(f"accuracy.{name} INTEGER is not minimal (TT-18)")
            out[name] = int.from_bytes(c, "big", signed=True)
            k += 1
    if k != len(ch):
        raise Malformed("accuracy has a component that is not allowed (TT-23)")
    # reported, never judged (TT-23 item 6): a value too large for a JSON number (beyond 2^53) is reported as null,
    # so a hostile accuracy can never break the report
    return {key: (v if v is None or abs(v) < 1 << 53 else None) for key, v in out.items()}


# --- keys (B5) ------------------------------------------------------------------------------------------------------

def _spki_key(spki: bytes) -> tuple[str, Any]:
    """B5: decode a selected certificate's SPKI (its own DER tree). ("rsa", (n, e)) or ("ecdsa", (x, y)). Any failure
    raises _Invalid (B5: "Any failure here MUST class the token invalid")."""
    from . import verify as v
    try:
        root = parse_der(spki, "SPKI")
        parts = _children(root, 0x30, "SPKI")
        if len(parts) != 2:
            raise Malformed("SPKI is SEQUENCE { algorithm, subjectPublicKey }")
        oid, params, pnode = _algid(parts[0], "SPKI.algorithm")
        bits = _need(parts[1], 0x03, "SPKI.subjectPublicKey").content
    except Malformed as exc:
        raise _Invalid(f"B5: {exc}") from exc
    if not bits or bits[0] != 0:
        raise _Invalid("B5: the SPKI BIT STRING must have 0 unused bits")
    key = bits[1:]
    if oid == OID_RSA:
        if params != "null":
            raise _Invalid("B5: an RSA SPKI must be rsaEncryption with NULL parameters (RFC 3279 2.3.1)")
        try:
            rk = _children(parse_der(key, "RSAPublicKey"), 0x30, "RSAPublicKey")
            if len(rk) != 2:
                raise Malformed("RSAPublicKey is SEQUENCE { modulus, publicExponent }")
            n, e = der_int(rk[0], "modulus", nonneg=True), der_int(rk[1], "publicExponent", nonneg=True)
        except Malformed as exc:
            raise _Invalid(f"B5: {exc}") from exc
        if not RSA_MIN <= n < RSA_MAX:
            raise _Invalid(f"B5: RSA modulus of {n.bit_length()} bits (2,048 to 4,096, TT-14)")
        if e != RSA_E:
            raise _Invalid("B5: RSA public exponent is not 65537 (TT-14)")
        return "rsa", (n, e)
    if oid == OID_EC_PUBLIC_KEY:
        if params != "other" or pnode.ident != b"\x06" or pnode.content != OID_SECP256R1:
            raise _Invalid("B5: the EC SPKI curve is not namedCurve secp256r1 (P-256 only, 10.7.9)")
        P = v._EC_P
        if len(key) == 65 and key[0] == 4:
            x, y = int.from_bytes(key[1:33], "big"), int.from_bytes(key[33:], "big")
            if x >= P or y >= P:
                raise _Invalid("B5: an EC point coordinate is not below p")
            if (y * y - (x * x * x + v._EC_A * x + v._EC_B)) % P:
                raise _Invalid("B5: the EC point is not on the P-256 curve")
            return "ecdsa", (x, y)
        if len(key) == 33 and key[0] in (2, 3):
            try:
                x, y, _ = v._p256_point(key)          # section 7.6 decompression (SEC 1 2.3.4)
            except ValueError as exc:
                raise _Invalid(f"B5: {exc}") from exc
            return "ecdsa", (x, y)
        raise _Invalid("B5: an EC public key must start 04 (65 octets) or 02/03 (33 octets) (RFC 5480 2.2)")
    raise _Invalid(f"B5: SPKI algorithm {_safe_dotted(oid)} is neither rsaEncryption nor id-ecPublicKey")


def _spki_family(spki: bytes) -> str | None:
    """B1: the key type of an SPKI from its algorithm OID alone ("rsa", "ecdsa" or None); no key is decoded."""
    try:
        parts = _children(parse_der(spki, "SPKI"), 0x30, "SPKI")
        oid = _algid(parts[0], "SPKI.algorithm")[0] if parts else None
    except Malformed:
        return None
    return {OID_RSA: "rsa", OID_EC_PUBLIC_KEY: "ecdsa"}.get(oid)


def _safe_dotted(oid: bytes) -> str:
    try:
        return dotted(oid)
    except Malformed:
        return "(unprintable OID)"


# --- the per-token check (10.7.6) ------------------------------------------------------------------------------------

def report(index: int, cls: str, problems: list[str], t: Token | None = None, tsa: str | None = None) -> dict:
    """TT-34: {tsa, gen_time, accuracy, policy, class, problems} (plus the token's index). ``_instant`` is internal
    (the exact genTime, for bounds) and is removed from library output by the caller."""
    out = {"index": index, "tsa": tsa, "gen_time": t.gen_time if t is not None else None,
           "accuracy": t.accuracy if t is not None else None, "policy": t.policy if t is not None else None,
           "class": cls, "problems": problems}
    if cls == "accepted":
        out["_instant"] = t.g
    return out


def classify_token(entry: Any, index: int, imprint: bytes, pins: list[dict], *, allow_ess_v1: bool,
                   aged: set[str] | None) -> dict:
    """10.7.6 for one `timestamps` entry against the expected ``imprint``.

    ``pins`` is the effective `policy.tsas`, in order, each with its parsed `cert` under ``"_cert"``; ``aged`` is the
    set of aged suite and hash names (`rsa-pkcs1v15`, `ecdsa-p256`, `sha256`, ...) for seal and attestation tokens,
    or None for an archive token (exempt, K2). Never raises."""
    try:
        return _classify(entry, index, imprint, pins, allow_ess_v1, aged)
    except (MemoryError, RecursionError) as exc:
        return report(index, "malformed", [f"resource limit while reading the token ({type(exc).__name__})"])


def _classify(entry, index, imprint, pins, allow_ess_v1, aged) -> dict:
    if not (isinstance(entry, dict) and set(entry) == {"format", "token"}):
        return report(index, "malformed", ["a timestamps entry is an object with exactly format and token (TT-2)"])
    if entry["format"] != "rfc3161":
        return report(index, "malformed", ["format must be 'rfc3161' (TT-2)"])
    try:
        raw = strict_b64(entry["token"], TOKEN_MAX_CHARS, "token", TOKEN_MAX_BYTES)
    except Malformed as exc:
        return report(index, "malformed", [str(exc)])
    budget = _NODE_BUDGET.set([0])          # TT-12: the 4,096-node limit covers the 10.7.5 decode of this token
    try:
        t = parse_token(raw)
    except Malformed as exc:
        return report(index, "malformed", [str(exc)])
    finally:
        _NODE_BUDGET.reset(budget)
    # K1: select the certificate, pin first (TT-11). No public-key operation before K1 and K2 pass.
    by_spki = {p["spki_sha256"]: p for p in pins}
    cands = list(t.certs) + [p["_cert"] for p in pins if p.get("_cert") is not None]

    def matches_sid(c: Cert) -> bool:
        return t.sid_issuer is not None and c.issuer == t.sid_issuer and c.serial == t.sid_serial

    ess_hash, ess_fn = None, None
    if t.ess_v2 is not None:
        if t.ess_v2.hash == "sha256":
            ess_hash, ess_fn = t.ess_v2.cert_hash, hashlib.sha256
    elif allow_ess_v1 and t.ess_v1 is not None:
        ess_hash, ess_fn = t.ess_v1.cert_hash, hashlib.sha1
    usable = [c for c in cands if matches_sid(c) and c.spki_sha256 in by_spki]
    sel = next((c for c in usable if ess_hash is not None and ess_fn(c.der).digest() == ess_hash), None)
    if sel is None and usable:
        sel = usable[0]
    if sel is None:
        why = ("the sid is a subjectKeyIdentifier, which matches no certificate in v4.0" if t.sid_ski is not None
               else "no candidate certificate matches the sid and a receiver TSA pin")
        return report(index, "unpinned", [f"unpinned (not checked): {why} (K1)"], t)
    pin = by_spki[sel.spki_sha256]
    tsa = pin["id"]
    problems: list[str] = []
    vt = _validity_text(sel.validity)                    # TT-33: advisory, never a class
    problems.append(f"advisory: the selected certificate's validity is {vt} (not checked, TT-33)" if vt
                    else "advisory: the selected certificate's validity window is not readable (not checked, TT-33)")
    # K2: window and policy (no public-key math)
    g = t.g
    rule = SIG_ALGS.get(t.sig_oid)
    digest = HASHES.get(t.digest_oid)
    if g < utc_instant(pin["trusted_from"]):
        return report(index, "out_of_window", [f"genTime {t.gen_time} is before the pin's trusted_from (K2)"], t, tsa)
    if pin["trusted_until"] is not None and g > utc_instant(pin["trusted_until"]):
        return report(index, "out_of_window", [f"genTime {t.gen_time} is after the pin's trusted_until (K2)"], t, tsa)
    if pin["distrusted_after"] is not None and not g < utc_instant(pin["distrusted_after"]):
        return report(index, "out_of_window", [f"genTime {t.gen_time} is not before the pin's distrusted_after (K2)"],
                      t, tsa)
    if pin["policy_oids"] and t.policy not in pin["policy_oids"]:
        return report(index, "out_of_window", [f"TSTInfo.policy {t.policy} is not in the pin's policy_oids (K2)"],
                      t, tsa)
    if aged is not None:
        suite = SUITE_OF.get(rule[0]) if rule is not None else None
        hit = sorted(x for x in (suite, digest) if x is not None and x in aged)
        if hit:
            why = f"the token's suite or digest hash {hit} has aged at as_of (K2, 7.13)"
            return report(index, "out_of_window", [why], t, tsa)
    try:
        _check_b(t, sel, rule, digest, imprint, allow_ess_v1, problems)
    except _Invalid as exc:
        return report(index, "invalid", [str(exc)] + problems, t, tsa)
    return report(index, "accepted", problems, t, tsa)


def _check_b(t: Token, sel: Cert, rule, digest: str | None, imprint: bytes, allow_ess_v1: bool,
             problems: list[str]) -> None:
    """B1 to B6. Raises _Invalid."""
    # B1. Algorithms
    if digest is None:
        raise _Invalid(f"B1: digestAlgorithm {_safe_dotted(t.digest_oid)} is not SHA-256, SHA-384 or SHA-512")
    if rule is None:
        raise _Invalid(f"B1: signatureAlgorithm {_safe_dotted(t.sig_oid)} is not one this verifier accepts (TT-27)")
    family, fixed, _ = rule
    if fixed is not None and fixed != digest:
        raise _Invalid(f"B1: signatureAlgorithm fixes {fixed} but digestAlgorithm is {digest}")
    if _spki_family(sel.spki) != family:
        raise _Invalid(f"B1: the selected certificate's key type does not fit the {family} signature algorithm")
    if family == "ecdsa" and digest != "sha256":
        raise _Invalid("B1: ecdsa-with-SHA256 requires digestAlgorithm SHA-256")
    # B2. Imprint
    if t.imprint_oid != OID_SHA256:
        raise _Invalid("B2: messageImprint.hashAlgorithm is not SHA-256 (SHA-384/512 imprints are reserved, 10.8.5)")
    if t.imprint != imprint:
        raise _Invalid("B2: messageImprint.hashedMessage is not the expected imprint")
    # B3. Signed attributes
    if t.ct_attr != OID_TSTINFO:
        raise _Invalid("B3: the content-type attribute is not id-ct-TSTInfo")
    if t.md_attr != _HASH_FN[digest](t.econtent).digest():
        raise _Invalid("B3: the message-digest attribute is not the digestAlgorithm hash of eContent")
    # B4. Signing-certificate binding
    if t.ess_v2 is not None:
        if t.ess_v2.hash != "sha256":
            raise _Invalid("B4: ESSCertIDv2 certs[0] hash is not SHA-256")
        if t.ess_v2.cert_hash != hashlib.sha256(sel.der).digest():
            raise _Invalid("B4: ESSCertIDv2 certHash is not SHA-256 of the selected certificate")
    elif not allow_ess_v1:
        raise _Invalid("B4: only the ESS v1 signing-certificate attribute is present and allow_ess_v1 is false")
    elif t.ess_v1.cert_hash != hashlib.sha1(sel.der).digest():
        raise _Invalid("B4: ESSCertID (v1) certHash is not SHA-1 of the selected certificate")
    # B5. Key
    kind, key = _spki_key(sel.spki)
    if kind != family:
        raise _Invalid("B5: the key does not fit the signature algorithm")
    # B6. Signature over the SA bytes (one unit of the work budget, TT-15)
    h = _HASH_FN[digest](t.sa_bytes).digest()
    if family == "rsa":
        _rsa_verify(key, t.signature, DIGEST_INFO[digest] + h)
    else:
        if _ecdsa_verify(key, t.ecdsa_rs, h):
            problems.append(HIGH_S_ADVISORY)


def _rsa_verify(key: tuple[int, int], sig: bytes, tail: bytes) -> None:
    """B6 RSASSA-PKCS1-v1_5 (RFC 8017 8.2.2): the full EM is compared, the DigestInfo is never parsed."""
    n, e = key
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        raise _Invalid(f"B6: the RSA signature is {len(sig)} octets, not k = {k} (RFC 8017 8.2.2 step 1)")
    s = int.from_bytes(sig, "big")
    if s >= n:
        raise _Invalid("B6: the RSA signature representative is not below n (RFC 8017 5.2.2)")
    em = pow(s, e, n).to_bytes(k, "big")
    if k < len(tail) + 11:
        raise _Invalid("B6: the modulus is too short for the encoding")
    want = b"\x00\x01" + b"\xff" * (k - len(tail) - 3) + b"\x00" + tail
    if em != want:
        raise _Invalid("B6: the RSA signature does not verify (EM differs from EMSA-PKCS1-v1_5)")


def _ecdsa_verify(q: tuple[int, int], rs: tuple[int, int], h: bytes) -> bool:
    """B6 ECDSA P-256 (FIPS 186-5 6.4.2) with this verifier's own K2 arithmetic. Returns True when s is high (an
    advisory, accepted). Raises _Invalid."""
    from . import verify as v
    r, s = rs
    n = v._EC_N
    if not (1 <= r < n and 1 <= s < n):
        raise _Invalid("B6: ECDSA r and s must lie in [1, n - 1]")
    e = int.from_bytes(h, "big")
    w = pow(s, -1, n)
    R = v._ec_sum(v._ec_mul_g(e * w % n), v._ec_mul((q[0], q[1], 1), r * w % n))
    if not R[2]:
        raise _Invalid("B6: R is the point at infinity")
    zinv = pow(R[2], -1, v._EC_P)
    if R[0] * zinv * zinv % v._EC_P % n != r:
        raise _Invalid("B6: the ECDSA signature does not verify")
    return s > v._EC_HALF_N


# --- scopes (10.7.7, 10.7.8) ------------------------------------------------------------------------------------------

def bound_of(reports: list[dict]) -> tuple[tuple[int, str] | None, str | None, int]:
    """TT-38: (the latest genTime instant in A, its report string, distinct pin ids in A)."""
    acc = [r for r in reports if r["class"] == "accepted"]
    if not acc:
        return None, None, 0
    best = max(acc, key=lambda r: r["_instant"])
    return best["_instant"], best["gen_time"], len({r["tsa"] for r in acc})


def earliest_of(reports: list[dict]) -> tuple[tuple[int, str] | None, str | None]:
    """10.3.8 step 11 / TT-42: (the EARLIEST genTime instant among the accepted reports, its report string)."""
    acc = [r for r in reports if r["class"] == "accepted"]
    if not acc:
        return None, None
    best = min(acc, key=lambda r: r["_instant"])
    return best["_instant"], best["gen_time"]


def public(reports: list[dict]) -> list[dict]:
    """The reports without internal members."""
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in reports]


def count_tokens(bundle: Any) -> int:
    """TT-13: tokens over `timestamps`, every attestation entry's `timestamps` and every archive `tokens` array."""
    b = bundle if isinstance(bundle, dict) else {}
    n = len(b["timestamps"]) if isinstance(b.get("timestamps"), list) else 0
    for e in b["attestations"] if isinstance(b.get("attestations"), list) else []:
        if isinstance(e, dict) and isinstance(e.get("timestamps"), list):
            n += len(e["timestamps"])
    ar = b.get("archive")
    for ch in (ar.get("chains") if isinstance(ar, dict) and isinstance(ar.get("chains"), list) else []):
        for st in (ch.get("stamps") if isinstance(ch, dict) and isinstance(ch.get("stamps"), list) else []):
            if isinstance(st, dict) and isinstance(st.get("tokens"), list):
                n += len(st["tokens"])
    return n
