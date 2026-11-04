"""Which receiver policy `proof-verify` evaluates under, and the proof that it was that one.

Selection only: this module picks the policy object handed to the unchanged decision (`classify_bundle`); it never
changes a verdict rule, state, reason code or exit code. Precedence, first match wins:

1. ``--policy FILE``          the file named on the command line.
2. ``--policy preset:NAME``   a preset shipped in ``proof_verify/presets``, only if it validates as shipped, with no
                              slot to fill. Every shipped preset has slots (the key it trusts, the people who sign
                              off), so today this always refuses (exit 2) and points to ``proof-policy init``.
                              (A file whose name starts with ``preset:`` is named ``./preset:...``.)
3. ``PROOF_POLICY``           an environment variable naming a policy file by an ABSOLUTE path (empty = unset;
                              a relative path is refused, exit 2, since it would be read from the working
                              directory).
4. none                       the built-in default policy, exactly as before discovery existed.

Step 3 is the only *discovery*. ``--no-policy-discovery`` (or ``PROOF_NO_POLICY_DISCOVERY=1``; only ``1``, ``0``
and empty are accepted, anything else exits 2) turns it off, so only an explicit ``--policy`` is used; a PROOF_POLICY
it ignores is reported (``ignored_env``) and noted on stderr. A ``PROOF_POLICY`` file that cannot be read or is malformed is refused (exit 2, no
verdict), never skipped in favor of the default.

No folder is searched, not even the working directory: a ``.proof-policy.json`` there is never read. A policy file
next to the bundle can come from the sender (an archive can carry one pinning the sender's own key), and a policy
the sender chooses would let the sender's bundle pass. The receiver names its policy itself: on the command line or
in its own environment.

Every verdict names its source (``policy_source`` in --json, one ``policy:`` line in text). ``--expect-policy
sha256:<64 hex>`` refuses (exit 2, no verdict) unless the effective policy's ``policy_sha256`` is that value: how a
receiver proves the decision was made under the policy it meant.
"""
from __future__ import annotations

import os
import re

from .verify import PolicyError, loads

ENV_POLICY = "PROOF_POLICY"
ENV_NO_DISCOVERY = "PROOF_NO_POLICY_DISCOVERY"
PRESET_PREFIX = "preset:"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)


class PolicyMismatch(PolicyError):
    """--expect-policy names a policy_sha256 other than the effective policy's."""

    kind = "policy_mismatch"


class PolicyUsageError(PolicyError):
    """A discovery setting this CLI will not guess at (exit 2, no verdict)."""

    kind = "usage"


def discovery_disabled(flag: bool) -> bool:
    """``--no-policy-discovery``, or ``PROOF_NO_POLICY_DISCOVERY``: exactly ``1`` is off, ``0`` or empty is on.
    Anything else ("false", "no", "true", " ") is refused: guessing either way could drop the receiver's policy."""
    raw = os.environ.get(ENV_NO_DISCOVERY, "")
    if raw not in ("", "0", "1"):
        raise PolicyUsageError(f"{ENV_NO_DISCOVERY} must be 1 (ignore {ENV_POLICY}) or 0 / empty (read it): got "
                               f"{raw!r}")
    return flag or raw == "1"


def check_expect(value: str | None) -> str | None:
    """None when ``value`` is a usable --expect-policy (or absent), else the usage error."""
    if value is not None and not _DIGEST_RE.fullmatch(value):
        return f"--expect-policy must be sha256:<64 lowercase hex> (a policy_sha256): {value!r}"
    return None


def _read(path: str, source: dict):
    try:
        with open(path, "rb") as handle:
            return loads(handle.read().decode("utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        err = PolicyError(f"cannot read policy {path!r}: {type(exc).__name__}: {exc}")
        err.source = source
        raise err from exc


def _preset(name: str):
    from .policy_cli import find_placeholders, load_preset, preset_names  # lazy: only for preset:NAME
    if name not in preset_names():
        raise _sourced(PolicyError(f"unknown preset; available: {', '.join(preset_names())}"), name)
    preset = load_preset(name)
    slots = [s["name"] for s in preset.get("slots", [])]
    if slots or find_placeholders(preset["policy"]):
        raise _sourced(PolicyError(
            f"preset {name!r} holds {len(slots)} slot(s) only you can fill "
            f"({', '.join(slots)}), so it cannot be used as shipped; write a policy from it with "
            f"`proof-policy init --preset {name} --fill SLOT=VALUE ... -o policy.json` and pass --policy policy.json"),
            name)
    return preset["policy"]


def _sourced(err: PolicyError, name: str) -> PolicyError:
    err.source = {"kind": "preset", "name": name}
    return err


def resolve(flag_value: str | None, *, no_discovery: bool = False):
    """(policy object or None, source). ``source`` is ``{"kind": "flag"|"preset"|"env"|"default", ...}`` with
    ``path`` (flag, env; for env the absolute path read) or ``name`` (preset), and ``ignored_env`` when discovery is
    off while PROOF_POLICY is set. Never reads a file the command line or the environment did not name, and never a
    relative PROOF_POLICY. Raises PolicyError (exit 2) for a policy that cannot be read or parsed and for an unusable
    PROOF_POLICY or PROOF_NO_POLICY_DISCOVERY; the caller validates the policy as before (the same
    `classify_bundle` refusal)."""
    off = discovery_disabled(no_discovery)          # a malformed PROOF_NO_POLICY_DISCOVERY is refused whatever follows
    env = os.environ.get(ENV_POLICY, "")
    # say so when discovery is off: a receiver who set PROOF_POLICY must see that it was not used
    ignored = {"ignored_env": env} if off and env else {}
    if flag_value is not None:
        if flag_value.startswith(PRESET_PREFIX):
            name = flag_value[len(PRESET_PREFIX):]
            return _preset(name), {"kind": "preset", "name": name, **ignored}
        source = {"kind": "flag", "path": flag_value}
        return _read(flag_value, source), {**source, **ignored}
    if off:
        return None, {"kind": "default", **ignored}
    if env:
        if not os.path.isabs(env):
            # a relative path resolves against the working directory, which may be an unpacked archive whose
            # sender planted the file: that would bring back the folder lookup this module refuses
            err = PolicyUsageError(f"{ENV_POLICY} must be an absolute path (a relative one would be read from the "
                                   f"working directory, which a bundle's sender can fill): got {env!r}")
            err.source = {"kind": "env", "path": env}
            raise err
        source = {"kind": "env", "path": os.path.abspath(env)}
        return _read(source["path"], source), source
    return None, {"kind": "default"}


def describe(source: dict) -> str:
    text = _describe(source)
    if source.get("ignored_env"):
        text += f" ({ENV_POLICY}={source['ignored_env']} ignored: policy discovery is off)"
    return text


def ignored_note(source: dict) -> str | None:
    """The stderr notice when discovery is off and PROOF_POLICY is set, else None."""
    if not source.get("ignored_env"):
        return None
    return (f"note: {ENV_POLICY}={source['ignored_env']} is ignored because policy discovery is off "
            f"(--no-policy-discovery or {ENV_NO_DISCOVERY}=1)")


def _describe(source: dict) -> str:
    kind = source["kind"]
    if kind == "flag":
        return f"--policy {source['path']}"
    if kind == "preset":
        return f"--policy preset:{source['name']}"
    if kind == "env":
        return f"discovered: {ENV_POLICY}={source['path']}"
    return "none given: the built-in default policy"

