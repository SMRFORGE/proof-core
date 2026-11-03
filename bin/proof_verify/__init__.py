"""proof-verify: the standalone evidence verifier. A vendorable, standard-library-only package that imports
nothing from the producer or any domain engine -- so a reviewer verifies a bundle with a checker that has
none of the code that produced it, enforced by packaging, not promised."""
from .verify import (
    DEMO_KEY_ID,
    DEMO_KEY_IDS,
    P256_DEMO_KEY_ID,
    STATE_FAIL,
    STATE_INTEGRITY_ONLY,
    STATE_INTEGRITY_ONLY_DEMO,
    STATE_VERIFIED,
    WORK_BUDGET_LIMIT,
    PolicyError,
    WorkBudget,
    WorkBudgetExceeded,
    classify_bundle,
    derived_from_problems,
    index_upstreams,
    integrity_ok,
    key_id,
    pin_demo_key,
    pin_key,
    pin_production_key,
    pinned_key_is_demo,
    policy_pins,
    resolve_pins,
    resolve_pointer,
    verify_bundle,
    verify_chain,
    verify_signature,
)

__all__ = [
    "DEMO_KEY_ID",
    "DEMO_KEY_IDS",
    "P256_DEMO_KEY_ID",
    "STATE_FAIL",
    "STATE_INTEGRITY_ONLY",
    "STATE_INTEGRITY_ONLY_DEMO",
    "STATE_VERIFIED",
    "WORK_BUDGET_LIMIT",
    "PolicyError",
    "WorkBudget",
    "WorkBudgetExceeded",
    "classify_bundle",
    "derived_from_problems",
    "index_upstreams",
    "integrity_ok",
    "key_id",
    "pin_demo_key",
    "pin_key",
    "pin_production_key",
    "pinned_key_is_demo",
    "policy_pins",
    "resolve_pins",
    "resolve_pointer",
    "run_conformance",
    "verify_bundle",
    "verify_chain",
    "verify_signature",
]


def __getattr__(name):
    # `run_conformance` loads on first use, so `python -m proof_verify.conformance` runs a module the package has
    # not already imported (an eager import here makes runpy warn before the summary).
    if name == "run_conformance":
        from .conformance import run_conformance
        return run_conformance
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
