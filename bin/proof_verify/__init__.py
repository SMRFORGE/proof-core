"""proof-verify: the standalone evidence verifier. A vendorable, standard-library-only package that imports
nothing from the producer or any domain engine -- so a reviewer verifies a bundle with a checker that has
none of the code that produced it, enforced by packaging, not promised."""
from .conformance import run_conformance
from .verify import (
    STATE_FAIL,
    STATE_INTEGRITY_ONLY,
    STATE_INTEGRITY_ONLY_DEMO,
    STATE_VERIFIED,
    classify_bundle,
    derived_from_problems,
    index_upstreams,
    integrity_ok,
    pin_demo_key,
    pin_key,
    pin_production_key,
    pinned_key_is_demo,
    resolve_pointer,
    verify_bundle,
    verify_chain,
)

__all__ = [
    "STATE_FAIL",
    "STATE_INTEGRITY_ONLY",
    "STATE_INTEGRITY_ONLY_DEMO",
    "STATE_VERIFIED",
    "classify_bundle",
    "derived_from_problems",
    "index_upstreams",
    "integrity_ok",
    "pin_demo_key",
    "pin_key",
    "pin_production_key",
    "pinned_key_is_demo",
    "resolve_pointer",
    "run_conformance",
    "verify_bundle",
    "verify_chain",
]
