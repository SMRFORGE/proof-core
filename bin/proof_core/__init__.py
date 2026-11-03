"""proof_core: the domain-agnostic evidence spine -- seal any computed output, prove it later.

This is the *producer* half of an evidence layer for computed results: it wraps ANY computed output (an
equipment-reliability score, a simulation's output, an AI pipeline's answer, a QA pre-screen, a
risk number) so it is defensible. It imports zero domain code (no models, no presets, no integrations):
a producer describes its output as a ``Case`` + ``Result`` and gets back a sealed, signed, tamper-evident
bundle whose numbers a skeptic can re-derive.

The five verbs:
  * SEAL      -- ``build_bundle(case, result, ...)``  content-hash + sign every section into one bundle.
  * SIGN      -- ``signing.sign_bundle_digest``       Ed25519 over the bundle digest (public demo key by
                                                      default; a consumer injects its own real key with
                                                      ``use_signer`` -- the kernel stays keyless).
  * REDACT    -- ``redact_bundle``                    withhold a section's value while keeping its seal valid.
  * REPRODUCE -- ``reproduce_bundle(bundle_bytes, runner)`` re-derive the numbers via a consumer-injected runner.
  * PROVENANCE-- ``provenance.*``                     git/toolchain/data-library pins folded into the seal.

The independent *checker* (integrity + origin, importing nothing from this package) lives in the
sibling ``proof_verify`` package -- keep it separate so verification never trusts the producer.

The on-disk schema carries a domain-neutral ``evidence.*`` namespace (e.g. ``evidence.envelope.v3``);
the spine is domain-agnostic and names nothing about any particular producer.
"""
from .adapter import Adapter
from .attest import ATTESTATION_SCHEMA, add_signoff, attest_bundle, make_attestation, make_signoff
from .certify import (
    REPRODUCTION_CAPABILITY,
    ReproduceError,
    certify_bundle,
    reproduce_bundle,
    seal_certification,
)
from .contract import (
    Case,
    Fidelity,
    ReproduceRunner,
    Result,
    Verdict,
)
from .envelope import build_bundle, canon, sha
from .profile import NEUTRAL, Profile
from .redaction import redact_bundle
from .result import build_result_core, stat_tolerance
from .seal import SealedFunction, sealed
from .signing import use_signer
from .testing import assert_integration

#: Single source of truth for the version. pyproject derives the dist version from this
#: (see [tool.setuptools.dynamic]). Independent of any consumer's version line.
__version__ = "0.25.0"

__all__ = [
    "ATTESTATION_SCHEMA",
    "NEUTRAL",
    "REPRODUCTION_CAPABILITY",
    "Adapter",
    "Case",
    "Fidelity",
    "Profile",
    "ReproduceError",
    "ReproduceRunner",
    "Result",
    "SealedFunction",
    "Verdict",
    "__version__",
    "add_signoff",
    "assert_integration",
    "attest_bundle",
    "build_bundle",
    "build_result_core",
    "canon",
    "certify_bundle",
    "make_attestation",
    "make_signoff",
    "redact_bundle",
    "reproduce_bundle",
    "seal_certification",
    "sealed",
    "sha",
    "stat_tolerance",
    "use_signer",
]
