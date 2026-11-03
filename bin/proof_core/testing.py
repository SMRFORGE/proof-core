"""``assert_integration`` -- the one call a CONSUMER runs to prove it wired proof-core up correctly.

A third party sits on top of proof-core by sealing its own results, verifying them with the independent
checker, and reproducing them through its own runner -- optionally all under its OWN on-disk dialect
(a ``proof_core.profile.Profile``). The failure that is easy to ship and hard to notice is a dialect
that seals and verifies but does NOT reproduce (the profile was threaded into the mint and the verify
but not the re-derivation). This helper exercises all three verbs end to end, under the consumer's
profile, and raises a pointed error on the first gap -- so a consumer drops it into its own test suite
and gets a single green/red signal that the integration holds.

It imports the checker from ``proof_verify`` (which imports no producer code), never re-implementing
verification inside the producer, and defaults to the neutral dialect so it is byte-neutral to the core.
"""
from __future__ import annotations

from collections.abc import Callable

from .certify import reproduce_bundle
from .profile import NEUTRAL


class IntegrationError(AssertionError):
    """Raised when a consumer's seal -> verify -> reproduce round-trip does not hold."""


def assert_integration(produce: Callable[[], dict], runner, *, profile=NEUTRAL) -> dict:
    """Prove the three verbs hold end to end for a consumer's integration, under its own dialect.

    ``produce`` is a zero-arg callable that returns a freshly SEALED bundle (e.g. a ``@sealed`` function
    called on a sample input, or a thin wrapper over ``build_bundle(...)``). ``runner`` is the consumer's
    ``ReproduceRunner`` (a ``@sealed`` function doubles as one). ``profile`` is the consumer's dialect; it
    defaults to the neutral one, so the plain ``assert_integration(produce, runner)`` checks a neutral
    integration.

    Checks, in order, raising ``IntegrationError`` with a pointed message on the first failure:
      1. ``produce()`` returns a dict carrying a ``bundle_sha256`` (it actually sealed).
      2. the INDEPENDENT verifier (``proof_verify``, importing no producer code) finds ``integrity_ok``
         under ``profile`` -- i.e. the bundle verifies in the consumer's own dialect.
      3. ``reproduce_bundle`` re-derives it under ``profile``: ``reproduced`` is True AND the re-run used
         the sealed inputs (``inputs_identical``).

    Returns a small report ``{bundle_sha256, integrity_ok, origin_ok, reproduced, inputs_identical}`` on
    success. Origin is reported, never required: a demo-pinned dialect is integrity-only, and that is fine
    for an integration check."""
    from proof_verify.verify import classify_bundle  # the INDEPENDENT checker (never the producer)

    from .envelope import bundle_bytes, received_bundle
    bundle = produce()
    if isinstance(bundle, dict):
        data = bundle_bytes(bundle)        # a bundle the consumer's producer just minted: serialized losslessly
    else:
        data, bundle = received_bundle(bundle, "assert_integration")   # its bytes or text (SPEC 4)
    if not isinstance(bundle, dict) or not bundle.get("bundle_sha256"):
        raise IntegrationError(
            "produce() must return a sealed bundle (a dict, or its bytes) carrying a 'bundle_sha256'; "
            f"got {type(bundle).__name__}")
    ver = classify_bundle(data, profile=profile)     # the verifier reads bytes (SPEC 4)
    if not ver["integrity_ok"]:
        raise IntegrationError(
            "the sealed bundle does not verify under this profile (integrity_ok is False): the dialect the "
            "verifier was given does not match the one the bundle was minted under. "
            f"Problems: {ver['problems']}")
    rep = reproduce_bundle(data, runner, profile=profile)
    if rep.get("reproduced") is not True:
        raise IntegrationError(
            f"the bundle did not reproduce under this profile (reproduced is {rep.get('reproduced')!r}): "
            "the runner did not re-derive the sealed result core. This is the classic 'seals and verifies "
            f"but will not reproduce' dialect gap. detail: {rep.get('reproduce_detail')}")
    if not rep.get("inputs_identical"):
        raise IntegrationError(
            "the re-run did not use the sealed inputs (inputs_identical is False): the runner substituted "
            "or ignored an input, so this is not a reproduction of the sealed case")
    return {
        "bundle_sha256": bundle.get("bundle_sha256"),
        "integrity_ok": ver["integrity_ok"],
        "origin_ok": ver["origin_ok"],
        "reproduced": rep["reproduced"],
        "inputs_identical": rep["inputs_identical"],
    }
