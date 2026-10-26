"""Human sign-off: a countersignature on a sealed decision.

The bundle `signature` is the PRODUCER's seal -- it proves the record came from the producing system and was
not edited. It does not say a *named person* approved the decision. In many settings (a credit adjudication, a
model-risk validation, a supervisory approval, deploying an AI agent whose conduct the deployer answers for) the
accountable human must sign to own the call.

An attestation is that sign-off: the approver signs over the sealed bundle digest TOGETHER WITH their role,
name and timestamp, so none of those can be changed without breaking the sign-off, and it is appended to the
bundle's `attestations` list WITHOUT touching the decision seal. The independent verifier (proof_verify) checks
each attestation's signature; whether a signing key really belongs to the named person is an identity question
(a pinned approver registry / hardware-key attestation / SSO binding), the same way the producer's origin is a
property of the pinned key -- stated honestly, not asserted by a label.

    bundle = produce(...)                      # system seals the decision
    bundle = attest_bundle(bundle, "adjudicator", "A. Officer", officer_sk)   # the human signs off
    verify_bundle(bundle)                       # decision seal unchanged; proof_verify also reports the sign-off
"""
from __future__ import annotations

import copy
import datetime

from . import signing
from .envelope import canon

ATTESTATION_SCHEMA = "evidence.attestation.v1"
#: the message label an approver signs under; bound INTO the signed bytes (mirrors the producer signature's
#: S2 `message`), so it names what was signed and cannot be swapped or the schema relabelled after the fact.
ATTESTATION_MESSAGE = "attests:v1"


def _attestation_message(bundle_sha256: str, role: str, name: str, timestamp: str) -> bytes:
    """The exact bytes an approver signs: the sealed decision digest bound to the attestation SCHEMA and
    message label AND to WHO signed off, as WHAT, and WHEN. Canonical JSON (sorted keys) so the independent
    verifier re-derives identical bytes. Binding the schema, label, role, name and timestamp into the signed
    message is what stops any of them being swapped after the fact (a sign-off cannot be lifted onto a
    different schema, relabelled, or re-attributed)."""
    return canon({"attests": bundle_sha256, "schema": ATTESTATION_SCHEMA, "message": ATTESTATION_MESSAGE,
                  "role": role, "name": name, "timestamp": timestamp})


def make_attestation(bundle_sha256: str, role: str, name: str, sk: bytes, *, timestamp: str | None = None) -> dict:
    """Build a single sign-off over `bundle_sha256` under the approver's private key `sk`."""
    ts = timestamp or datetime.datetime.now(datetime.UTC).isoformat()
    pk = signing.publickey(sk)
    sig = signing.sign(_attestation_message(bundle_sha256, role, name, ts), sk, pk)
    return {
        "schema": ATTESTATION_SCHEMA,
        "role": role,
        "name": name,
        "public_key": pk.hex(),
        "timestamp": ts,
        "message": ATTESTATION_MESSAGE,   # bound into the signed bytes (with schema, role, name, timestamp)
        "signature": sig.hex(),
    }


def attest_bundle(bundle: dict, role: str, name: str, sk: bytes, *, timestamp: str | None = None) -> dict:
    """Return a COPY of `bundle` with a human approver's sign-off appended to `attestations`.

    The approver signs the sealed bundle digest together with their role, name and timestamp. The decision
    seal (the producer `signature`) is left untouched, so the sign-off is additive: several approvers can
    countersign the same sealed decision (maker-checker), and `verify_bundle`'s integrity+origin verdict over
    the decision is unchanged. Raises if the bundle carries no `bundle_sha256` to sign."""
    digest = bundle.get("bundle_sha256")
    if not isinstance(digest, str) or not digest:
        raise ValueError("cannot attest a bundle with no bundle_sha256 (seal it first)")
    b = copy.deepcopy(bundle)
    b.setdefault("attestations", []).append(make_attestation(digest, role, name, sk, timestamp=timestamp))
    return b
