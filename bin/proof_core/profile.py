"""Emission / verification PROFILE -- the single seam that lets one spine mint and verify more than one
on-disk envelope dialect without any domain code leaking into the spine.

A `Profile` is a frozen bag of the shape constants that a *producer* is free to brand -- the schema
namespace tags, the open-engine sentinel, the default `reproduce` phrasing, the unpinned-data marker,
the attestation-scope prose, whether a diagnostic `host` block is emitted -- plus the one *verifier*
knob a dialect needs (which public key the origin check pins). EVERYTHING that makes a bundle
tamper-evident -- canonicalization, SHA-256, the Ed25519 math, the signature-block shape, the
redaction / derived_from / frontier SHAPES -- is deliberately NOT here: it is profile-invariant and
must stay byte-identical across every dialect, so a profile can never weaken the seal.

DOMAIN-NEUTRALITY CONTRACT (do not break): this module, and every default below, names NOTHING about
any particular producer -- no product, no discipline, no domain. The neutral `Profile()` reproduces the
spine's CURRENT bytes exactly (its defaults ARE the module constants the mint reads today), so threading
`profile=` changes nothing unless a caller passes a non-default profile. A producer that wants a branded
dialect constructs its OWN `Profile(...)` in ITS OWN tree and passes it in; the spine never ships that
object. See `build_bundle(..., profile=)` and `proof_verify.verify.classify_bundle(..., profile=)`.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from . import provenance as prov

#: The default `reproduce` phrasing a minted bundle carries when the caller passes none. Kept here as the
#: single neutral source of truth (the mint reads it through the profile). NOTE the exact spacing -- it is
#: byte-significant: the sealed provenance digest is taken over this string verbatim.
NEUTRAL_REPRODUCE_DEFAULT = (
    "proof-reproduce <bundle.json> --runner <your ReproduceRunner>"
    "  (re-runs the producer on the sealed inputs)"
)


@dataclass(frozen=True)
class Profile:
    """The brandable shape constants of one envelope dialect. Defaults = the spine's own neutral
    ``evidence.*`` dialect; a non-default profile is supplied by a producer, never by the spine."""

    # --- shape tags (mint + verify) -------------------------------------------------------------- #
    #: top-level bundle `schema` literal (mint) / the only accepted envelope schema (verify). ADR-049
    #: bumped this v1 -> v2 with the one-time shape change (no host, machine axis, binding chain, prose-free
    #: redaction): the neutral envelope shape genuinely moved, so its tag moves with it.
    envelope_schema: str = "evidence.envelope.v2"
    #: embedded result-core `schema` literal and its integer `schema_version` (mint).
    result_schema: str = "evidence.result.v1"
    result_schema_version: int = 1
    #: the result-core fields a verifier requires to be present (verify).
    result_required_fields: tuple[str, ...] = (
        "schema", "schema_version", "result", "fidelity", "verdict")
    #: the (unsigned) redaction-record `schema` literal (mint-side producers / verify-side shape check).
    redaction_schema: str = "evidence.envelope.redaction.v1"

    # --- provenance sentinels (mint) ------------------------------------------------------------- #
    #: the `produced_by` sentinel meaning "the open engine produced/reproduced this".
    produced_by_open: str = prov.PRODUCED_BY_OPEN
    #: the unambiguous alternative prefix a packaged external result must carry.
    produced_by_external_prefix: str = "external:"
    #: the default `reproduce` string, and the accepted open-engine `reproduce` prefixes (the honesty
    #: belt requires an open-engine bundle's `reproduce` to start with one of these).
    reproduce_default: str = NEUTRAL_REPRODUCE_DEFAULT
    reproduce_open_prefixes: tuple[str, ...] = ("reproduce", "proof-reproduce")
    #: the honest "no data library pinned" marker id + its (real, well-formed) content digest, and the
    #: placeholder RNG seed. A branded dialect namespaces the marker preimage, so its digest differs.
    data_library_unpinned_id: str = prov.DATA_LIBRARY
    data_library_unpinned_sha256: str = prov.DATA_LIBRARY_SHA256
    rng_seed_placeholder: int = prov.RNG_SEED
    #: the signed claim-boundary object (a read-only `MappingProxyType` view at runtime, see `__post_init__`;
    #: the mint coerces it back to a plain dict before sealing); defaulted through a factory so the neutral
    #: profile seals the spine's own `ATTESTATION_SCOPE` object unchanged.
    attestation_scope: Mapping[str, Any] = field(default_factory=lambda: dict(prov.ATTESTATION_SCOPE))

    # --- reproduce/certify data (consumer-brandable; defaults = the neutral constants) ------------- #
    #: the `schema` literal of the (unsigned) certification record `certify_bundle` emits. A branded
    #: consumer sets its own; the neutral default is the spine's own tag.
    certification_schema: str = "evidence.certification.v1"
    #: sealed `data` pins compared INFORMATIONALLY (a difference is a note, never a hard environment block) --
    #: e.g. a path-sensitive library INDEX hash. A dialect whose informational pin has a different name
    #: (a reactor consumer's `cross_sections_sha256`, say) replaces this tuple.
    env_informational: tuple[str, ...] = ("data_index_sha256",)
    #: sealed `data` run controls a genuine reproduction must have re-used (compared HARD, alongside every
    #: `*_sha256`). A dialect whose run is parameterized differently (particle counts, batches) replaces this.
    env_run_controls: tuple[str, ...] = ("samples", "iterations", "warmup", "batch_seed", "rng_seed", "seed")

    #: the allowed KEY SET for each sealed `derived_from` link (a verify-side allowlist, data only). ADR-049
    #: made the BINDING invariant (consumed.sha256 == sha of the named input, the consumed-triple shape,
    #: self-consistency, verdict-token rejection) the ONE and only chain shape, so the neutral default is the
    #: binding key set. A dialect may still REPLACE this allowlist with its own closed set (e.g. a different
    #: `role` vocabulary), but every dialect's link is binding -- there is no decoration mode to toggle.
    derived_from_keys: frozenset[str] = frozenset({"bundle_sha256", "sha256sums", "consumed", "role"})

    # --- verify-side trust root ------------------------------------------------------------------ #
    #: the public key the ORIGIN check pins, as 64 lowercase hex (no ``ed25519:`` prefix). None = use the
    #: verifier's module-global pin unchanged (the neutral default; keeps the single-pin design intact).
    pinned_pubkey: str | None = None
    #: VERIFY: declare that the pinned key is a DEMO / test identity, so origin can NEVER be established
    #: under this profile even if the signature validates under the pin -- the honest verdict is integrity
    #: only. Default False = unchanged: the verifier decides demo-ness solely by the literal match against
    #: its own well-known demo key (the Stage-1 behaviour; a dialect that pins its OWN demo/test key, not
    #: the spine's, would otherwise get a full origin verdict -- this flag closes that hole). A dialect that
    #: pins a REAL production trust root leaves this False and origin is established. A dialect CUTS OVER
    #: from a demo pin to its production trust root purely consumer-side -- supply the production
    #: ``pinned_pubkey`` and leave ``pin_is_demo=False`` -- with no change here: a bundle signed under that
    #: pin then reads integrity+origin.
    pin_is_demo: bool = False

    # ADR-049 (one strict dialect): the eight Stage-2/3/4 behavior flags that used to live here --
    # enforce_derived_binding, reject_stray_host, emit_host, emit_toolchain_machine, prose_free_redaction,
    # strict_timestamp, strict_signature_hex, strict_redaction -- are GONE. Each was a migration scaffold
    # defaulting to the lenient/legacy value so the neutral spine stayed byte-identical while the seam was
    # built; every strict value is now the kernel's ONLY behavior (binding derived_from is the one chain
    # shape; host is retired and rejected if stapled; the toolchain always carries `machine`; redaction is
    # prose-free and strictly shaped; the timestamp and signature-hex checks are always strict). A dialect
    # now brands DATA only -- there is no behavior switch left to document or defend.

    def __post_init__(self) -> None:
        # Deep-immutability belt: wrap `attestation_scope` in a read-only view so a caller's
        # `profile.attestation_scope["k"] = v` raises TypeError instead of silently mutating this
        # frozen profile's shared, sealed-at-mint object. A fresh dict() copy is taken first, so a later
        # mutation of the dict the caller passed in cannot reach through either. The mint coerces the view
        # back to a plain dict before sealing (see build_bundle), so the SEALED BYTES are unchanged -- this
        # is a guard on the in-memory object only, never on the wire.
        object.__setattr__(self, "attestation_scope", MappingProxyType(dict(self.attestation_scope)))
        # Fail fast on a malformed origin pin: a `pinned_pubkey` that is not 64 lowercase hex can never
        # match a bare-hex `signer` at verify, so it would silently degrade EVERY origin verdict to a
        # mismatch instead of raising. None (the neutral default and every unpinned profile) is allowed.
        pin = self.pinned_pubkey
        if pin is not None and not (isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin)):
            raise ValueError("Profile.pinned_pubkey must be 64 lowercase hex characters (an Ed25519 "
                             f"public key, no 'ed25519:' prefix) or None; got {pin!r}")


#: The neutral profile singleton. `build_bundle(profile=None)` resolves to THIS, and its emitted bytes
#: are identical to the pre-seam mint -- the additive guarantee.
NEUTRAL = Profile()
