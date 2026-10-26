"""Reproducibility provenance -- the facts a bundle needs so someone else can re-derive it.

A number is only defensible if you can say WHAT produced it: which code, which data, which random
seed. These fields are stamped into every bundle and folded into the signed manifest, so they are
tamper-evident, not just informational.

The **data library** is whatever data the run actually read, pinned by content digest: an analytics
pipeline records the plant data snapshot it scored; a producer with an in-tree reference table records
THAT (a real digest of the bundled table -- no download, air-gap-safe). A run that records none leaves
`unpinned` (see below) rather than claiming a library it never pinned. The set is threaded explicitly
into the bundle by the caller -- the envelope reads no process-global, so a recording in one place can
never leak into an unrelated bundle's signed claim. Nothing here stores or ships the data itself --
only its fingerprint travels. `code_version` reads the producing tree's git SHA once at import (via
`git -C <tree>`, so the process CWD can never substitute an unrelated repo; a wheel with no `.git` falls
back to the packaged release, `release:<version>`); the seed is the run's RNG seed.
"""
from __future__ import annotations

import functools
import hashlib
import os
import platform
import re
import subprocess

# ---- consumer configuration -------------------------------------------------------------------- #
# A consumer (an analytics pipeline, a modeling engine, any producer) anchors provenance on ITS OWN source tree and
# version via configure(), so code_version / engine_version describe the code that produced the number
# -- not proof_core, which merely provides the sealing machinery. Used standalone (no configure call)
# these anchor on proof_core itself. Set-once-at-import, before any mint.
_CFG_TREE_ROOT = None
_CFG_BASE_VERSION: str | None = None
_CFG_IMAGE_DIGEST_ENV: str | None = None


def configure(*, tree_root=None, base_version=None, image_digest_env=None) -> None:
    """Anchor provenance on the CONSUMER's source tree and package version. Call once at import, before
    the first mint, so a signed bundle's `code_version`/`engine_version` name the consumer's code.

    `image_digest_env` names the environment variable the consumer's containerized runtime sets to declare
    its immutable engine-image digest (a consumer may use its own, e.g. `ACME_ENGINE_IMAGE_DIGEST`,
    instead of the neutral `PROOF_ENGINE_IMAGE_DIGEST`). None keeps the neutral default, byte-unchanged."""
    from pathlib import Path
    global _CFG_TREE_ROOT, _CFG_BASE_VERSION, _CFG_IMAGE_DIGEST_ENV
    if tree_root is not None:
        _CFG_TREE_ROOT = Path(tree_root)
    if base_version is not None:
        _CFG_BASE_VERSION = str(base_version)
    if image_digest_env is not None:
        _CFG_IMAGE_DIGEST_ENV = str(image_digest_env)
    engine_version.cache_clear()   # re-anchor possibly-cached version strings
    code_version.cache_clear()


def _base_version() -> str:
    """The configured consumer version, else proof_core's own -- the honest `release:` fallback basis."""
    if _CFG_BASE_VERSION is not None:
        return _CFG_BASE_VERSION
    try:
        from proof_core import __version__
        return __version__
    except Exception:  # noqa: BLE001 -- provenance must never crash a run; degrade honestly
        return "unknown"


#: Honest default for a run that recorded NO data library. It means exactly "no library was pinned by
#: this run" -- NOT the stronger "read no data" (a producer may carry its own in-tree constants and not
#: yet record them; that is an under-claim to close, never a false claim). What it is not: a fabricated
#: library name, and not a zero hash -- the marker digest is real (and well-formed, so the verifier's S6
#: rule accepts an honest unpinned mint), so the old all-zero placeholder pattern is greppable and can
#: never be mistaken for an unfilled field.
DATA_LIBRARY = "unpinned"
DATA_LIBRARY_SHA256 = "sha256:" + hashlib.sha256(b"evidence:data-library:unpinned").hexdigest()
RNG_SEED = 0

#: Honest default for `produced_by`: the number was produced/reproduced by the open engine,
#: so `reproduce` re-derives it from the bundle's recorded inputs. A bundle whose result was
#: computed by an EXTERNAL code (a vendor model, an out-of-tree simulation run, a third-party service) and merely PACKAGED here must
#: override this via `Result.provenance["produced_by"] = "external:<code>"`, so the seal names the true
#: producer. This is the anti-false-attestation field: without it an externally-supplied number could be
#: sealed as if the open engine derived it -- integrity intact, ORIGIN misread. It is a plain constant (no
#: zero/placeholder ambiguity) and greppable, exactly like the DATA_LIBRARY marker above.
PRODUCED_BY_OPEN = "open-engine"

#: env var by which a containerized runtime declares its own immutable engine-image digest (e.g. an OCI
#: `repo@sha256:...`). Set by the reproduce/CE container so the sealed toolchain names the real image, not
#: just the interpreter. Absent on a bare host -> the toolchain records the build fingerprint alone.
_ENGINE_IMAGE_ENV = "PROOF_ENGINE_IMAGE_DIGEST"
#: a declared engine image must be an immutable OCI digest ref `<name>@sha256:<64 hex>` -- a mutable tag or
#: free text is NOT a pin and must never be sealed as if it named a specific image. Validated at capture
#: (fail closed), so a misleading `image_digest` (e.g. a vendor name with no real digest) cannot ride the
#: signed provenance and read as authoritative to a human.
_IMAGE_DIGEST_RE = re.compile(r"\S+@sha256:[0-9a-f]{64}")


#: The keys a sealed `toolchain.solver` record may carry. `name`/`version` are required; `build` is the
#: solver's OWN self-report (a version line, a git SHA, compile options) and is OMITTED when the solver does
#: not report one. Never populated from a human-typed value. A MINT-side helper only; emitted into the signed
#: `toolchain` when a profile-driven caller threads a solver record in. (Domain-neutral: generic
#: {name, version, build} strings, no product or discipline named.)
SOLVER_KEYS = ("name", "version", "build")


def solver_record(name: str, version: str, build: str | None = None) -> dict:
    """The `toolchain.solver` object for a run in which a plugin invoked an EXTERNAL solver: ``{"name",
    "version"}`` plus ``"build"`` only when the solver self-reported one. Every value must be a non-empty
    string captured from the solver itself (its version attribute / its own `-v` output); the invoking
    plugin passes them through, never types them. Fails closed on a malformed value so a misleading solver
    claim cannot ride the signed provenance."""
    rec = {"name": name, "version": version}
    if build is not None:
        rec["build"] = build
    for key, val in rec.items():
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"toolchain.solver.{key} must be a non-empty string (got {val!r})")
    return rec


def toolchain(*, solver: dict | None = None) -> dict:
    """The runtime toolchain fingerprint folded into the SIGNED provenance -- so `reproduced-exact` is
    honest BELOW the version string: a reviewer can see whether their Python/platform/engine-image match the
    one that minted the bundle. ADVISORY by contract (certify surfaces a diff as a note, never a hard block),
    because a reviewer on a different toolchain is expected and the result CORE re-derives regardless. This
    is the signed complement to the (now retired) diagnostic `host` block. `image_digest` appears only when
    the containerized runtime declares it via ``PROOF_ENGINE_IMAGE_DIGEST``.

    The ``machine`` axis -- the CPU instruction set, via ``platform.machine()``, which with libm is what can
    move a last-bit float on the pure-Python engine -- is ALWAYS emitted (ADR-049: one strict dialect; there
    is no leaner toolchain shape). ``solver`` (default None) adds a ``solver`` record when a caller threads
    one in (see `solver_record`); a run with no external solver carries none."""
    tc = {
        "python_version": platform.python_version(),
        "python_impl": platform.python_implementation(),
        "platform": platform.system(),
        "machine": platform.machine(),
    }
    image = os.environ.get(_CFG_IMAGE_DIGEST_ENV or _ENGINE_IMAGE_ENV)
    if image:
        if not _IMAGE_DIGEST_RE.fullmatch(image):
            raise ValueError(
                f"{_CFG_IMAGE_DIGEST_ENV or _ENGINE_IMAGE_ENV}={image!r} is not a well-formed OCI image "
                "digest (expected '<ref>@sha256:<64 hex>'); refusing to seal a misleading engine-image pin")
        tc["image_digest"] = image
    if solver is not None:
        if not isinstance(solver, dict) or set(solver) - set(SOLVER_KEYS):
            raise ValueError(f"toolchain.solver must be a solver_record() dict, got {solver!r}")
        tc["solver"] = solver_record(solver.get("name"), solver.get("version"), solver.get("build"))
    return tc


#: The signed CLAIM BOUNDARY of the seal -- what a passing signature does and does NOT attest -- folded into
#: the signed provenance so the scope is tamper-evident, not implied. This is the "seal what ran" honesty
#: belt made cryptographic: a reader cannot mistake an INTEGRITY seal for proof that the number came from
#: the pinned signer, that the computation ran, or that it is correct. Deliberately STATIC and general.
#: It does NOT restate origin as attested-by-the-seal: origin is a property the VERIFIER decides by comparing
#: the signing key to its PINNED key, never a field in the bundle (signing.py / docs/TRUST_ROOT.md) -- the
#: `origin` entry below points at that check rather than claiming origin here, honoring the same principle
#: that keeps a self-asserted origin label out of the bundle.
ATTESTATION_SCOPE = {
    "attests": "integrity of the sealed inputs/result/provenance -- that they are unaltered since signing",
    "origin": "NOT asserted here; origin is decided by the VERIFIER comparing the signing key to its pinned "
              "production key (docs/TRUST_ROOT.md), never by a field in the bundle",
    "does_not_attest": "that the computation was executed, that the result is correct, or who "
                       "computed it beyond the signed `produced_by` field",
    # The reality->snapshot boundary, stated in the SIGNED scope so every bundle carries it (not only an
    # adapter's own caveats): the seal binds the result to the SEALED inputs, never those inputs to external
    # reality. For ops analytics this is the line between "the score re-derives from this snapshot" and "this
    # snapshot is the real plant data"; for a retrieval answer, between "grounded in these sealed passages"
    # and "these passages are the authentic, current source documents". An upstream data-source signature or
    # independent anchor is a SEPARATE attestation this seal does not make.
    "input_authenticity": "NOT attested -- the seal binds the result to the SEALED inputs; it does not attest "
                          "that those inputs reflect external reality (that a data snapshot is the real source "
                          "data, or that grounding sources are authentic/current). An upstream data-source "
                          "signature or independent anchor is a SEPARATE attestation.",
    "for_execution": "reproduce -- re-runs the open engine on the sealed inputs (see `reproduce`)",
    "for_correctness": "the benchmark/closure evidence and the result's own `fidelity` tier and tolerance",
}


def _fallback_version() -> str:
    """Honest `code_version` for a run with no readable git SHA -- a wheel/sdist install (no `.git`), or
    a tree we refuse to trust (see `is_tree_root`). Reports the PACKAGED release with a `release:` prefix
    (e.g. `release:0.7.0`, from the single source of truth `proof_core.__version__`), so it (a) states a
    true fact -- the build's declared version -- (b) can never be mistaken for a git commit SHA, and (c)
    never reads as the bogus `0.0.1` claim the old placeholder did. Two wheels of the same release share
    it: no per-commit SHA is embedded at build time, so the exact-commit pin exists only in a checkout.
    Reports the CONSUMER's version when configured (see `configure`), else proof_core's own."""
    return f"release:{_base_version()}"


def tree_root():
    """The source tree every git provenance read anchors on -- NOT the process CWD. The consumer's tree
    when configure(tree_root=...) was called (so the engine's bundles pin the engine's code), else the
    tree this module lives in (repo root in a checkout; site-packages dir in a wheel)."""
    from pathlib import Path
    if _CFG_TREE_ROOT is not None:
        return _CFG_TREE_ROOT
    return Path(__file__).resolve().parents[1]


def git_env():
    """A subprocess environment with git's location-override variables scrubbed. `GIT_DIR`,
    `GIT_WORK_TREE`, etc. are exported by git hooks (and can be set by a caller); left in place they
    redirect even a `git -C <tree>` read to an UNRELATED repo, silently stamping the wrong SHA into a
    signed bundle. Scrubbing them makes `-C <tree>` mean what it says."""
    import os
    env = os.environ.copy()
    for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                "GIT_OBJECT_DIRECTORY", "GIT_CEILING_DIRECTORIES"):
        env.pop(var, None)
    return env


def is_tree_root(root, env) -> bool:
    """True only when `root` is the TOP of the git repo it sits in. Guards the venv/site-packages case:
    a tree installed *inside* an unrelated repo (e.g. `<plugin-repo>/.venv/.../site-packages`) would let
    `git -C root` walk up and report that enclosing repo. If the discovered toplevel is not `root`
    itself, the SHA does not describe our code -- refuse it and fall back."""
    from pathlib import Path
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=3, check=True, env=env,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 -- no git / not a repo -> not our tree
        return False
    return bool(top) and Path(top).resolve() == Path(root).resolve()


def _detect_code_version() -> str:
    # Pin to the producing tree this module lives in, NOT the process CWD, NOT an env-redirected repo,
    # NOT an unrelated repo we merely sit inside: a signed `code_version` must describe the code that
    # produced the number or say nothing. `tree_root` + `git_env` + `is_tree_root` together close the
    # CWD, GIT_DIR, and nested-venv substitution paths (mirrored in `engine_version`). An out-of-tree
    # card that wants to record ITS own version overrides via `provenance["code_version"]` (build_bundle).
    root = tree_root()
    env = git_env()
    if not is_tree_root(root, env):
        return _fallback_version()
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short=12", "HEAD"],
            capture_output=True, text=True, timeout=3, check=True, env=env,
        )
        return out.stdout.strip() or _fallback_version()
    except Exception:  # noqa: BLE001 -- provenance must never crash a run; degrade honestly
        return _fallback_version()


@functools.lru_cache(maxsize=1)
def code_version() -> str:
    """The producing tree's git SHA (or honest `release:` fallback). Resolved LAZILY on first use and
    cached for the run -- not at import, so a consumer's configure() has taken effect before it anchors."""
    return _detect_code_version()


@functools.lru_cache(maxsize=1)
def engine_version(base_version: str | None = None) -> str:
    """Real, code-distinguishing producer version: base + git short SHA (+'-dirty') when in a repo, so two
    bundles that ran different code never share a version string. Falls back to the base version.

    `base_version` defaults to the installed proof_core version; a consumer (an analytics pipeline, a
    modeling engine, any producer) passes its OWN package version so the sealed `engine_version` names the code that ran. Same
    substitution guard as `code_version`: anchor on the tree, scrub git's env overrides, and trust the SHA
    only when the tree IS the repo top -- never the CWD, a GIT_DIR redirect, or an unrelated repo a
    venv/site-packages install happens to sit inside."""
    if base_version is None:
        base_version = _base_version()   # the configured consumer version, else proof_core's own
    root = tree_root()
    env = git_env()
    if not is_tree_root(root, env):
        return base_version
    try:
        sha = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=3, check=True, env=env).stdout.strip()
        # '-dirty' must reflect uncommitted CODE + closure INPUTS, not the GENERATED artifacts themselves.
        # A consuming engine may exclude its own generated outputs; the core makes no such assumption.
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                               capture_output=True, text=True, timeout=3, check=False, env=env).stdout.strip()
        return f"{base_version}+{sha}{'-dirty' if dirty else ''}" if sha else base_version
    except (subprocess.SubprocessError, OSError):
        return base_version
