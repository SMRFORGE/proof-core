"""Producer side of trusted time (SPEC v4 10.7.10, 10.3.7): the imprints a producer asks a TSA to stamp, and attaching
the tokens it gets back.

proof-core never talks to a TSA: the caller sends the imprint to the time-stamping authority of its choice (an RFC
3161 request is out of scope here) and passes the DER tokens back. SPEC 10.7.10: "A producer MUST request seal tokens
only after every block in E is final, because the seal datum includes every signature." `seal_imprint` is computed
from the bundle as it stands, and `add_seal_timestamps` refuses a token whose imprint is not the CURRENT seal
imprint, so a token requested before the last signature was added (or for another bundle) is never attached.
"""
from __future__ import annotations

import base64
import copy
import hashlib

from .envelope import canon

TIMESTAMP_SUBJECT = "evidence.timestamp.subject.v1"
_MAX_SEAL_TOKENS = 16


def seal_datum(bundle: dict) -> bytes:
    """SPEC 10.7.2 "What a seal token covers": canon_1({schema, bundle_sha256: S, signatures: [every E signature hex,
    in E order]}). Raises ValueError for a bundle that has no seal signature yet."""
    if not isinstance(bundle.get("signature"), dict) or "signature" not in bundle["signature"]:
        raise ValueError("the bundle has no seal signature yet: request seal tokens only after every signature in E "
                         "is final (SPEC 10.7.10)")
    sigs = [bundle["signature"]["signature"]] + [b["signature"] for b in bundle.get("signatures", [])]
    return canon({"schema": TIMESTAMP_SUBJECT, "bundle_sha256": bundle["bundle_sha256"], "signatures": sigs})


def seal_imprint(bundle: dict) -> bytes:
    """The 32-byte SHA-256 imprint a seal token must carry (TT-5): send it to the TSA."""
    return hashlib.sha256(seal_datum(bundle)).digest()


def signoff_imprint(bundle: dict, entry: dict) -> bytes:
    """SPEC 10.3.7 "Token imprint" of a sign-off entry over ``bundle``'s seal."""
    from .attest import _SIGNED_MEMBERS  # the 13 signed members
    o = {k: entry[k] for k in _SIGNED_MEMBERS}
    o["attests"] = bundle["bundle_sha256"]
    m = canon(o) + bytes.fromhex(entry["signature"])
    return hashlib.sha256(canon({"schema": TIMESTAMP_SUBJECT,
                                 "attestation": "sha256:" + hashlib.sha256(m).hexdigest()})).digest()


def _token_imprint(der: bytes) -> bytes:
    from proof_verify import tsp
    return tsp.parse_token(der).imprint


def add_seal_timestamps(bundle: dict, tokens: list[bytes]) -> dict:
    """Return a COPY of the v4 ``bundle`` with ``tokens`` (DER RFC 3161 TimeStampTokens) as its `timestamps` block,
    after any it already holds. Each token must be well formed (SPEC 10.7.5) and carry the bundle's CURRENT seal
    imprint; anything else raises ValueError. The seal and its signatures are untouched (`timestamps` is unsigned)."""
    want = seal_imprint(bundle)
    entries = list(bundle.get("timestamps", []))
    for i, der in enumerate(tokens):
        try:
            got = _token_imprint(bytes(der))
        except Exception as exc:          # the verifier's Malformed, or a non-bytes value
            raise ValueError(f"token {i} is not a well-formed RFC 3161 token: {exc}") from exc
        if got != want:
            raise ValueError(f"token {i} does not carry this bundle's current seal imprint: it was requested before "
                             "every seal signature was final, or for another bundle (SPEC 10.7.10)")
        entries.append({"format": "rfc3161", "token": base64.b64encode(bytes(der)).decode("ascii")})
    if not 1 <= len(entries) <= _MAX_SEAL_TOKENS:
        raise ValueError(f"a bundle carries 1 to {_MAX_SEAL_TOKENS} seal tokens (SPEC 10.7.2 TT-1)")
    b = copy.deepcopy(bundle)
    b["timestamps"] = entries
    return b
