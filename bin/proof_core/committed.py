"""Committed items (SPEC evidence.envelope.v4 draft 6.6): a value inside ``inputs`` or below the capability slot of
the result, sealed as a salted HMAC-SHA256 commitment, that can later be WITHHELD without changing the seal.

A committed item is an object with the reserved member ``$committed``:

- disclosed form ``{"$committed": 1, "marks": [...], "salt": "<64 hex>", "value": <JSON>}``;
- withheld form ``{"$committed": 1, "commitment": "hmac-sha256:<64 hex>", "marks": [...]}``.

Canon 3 (5.6) digests a section after the projection T, which maps both forms of an item to the same bytes, so a
holder can withhold the item (``redact_bundle(..., withhold_items=[path])``) and the original signature still
verifies. A disclosure package (10.5) puts the plaintext back.

The rules (form, fields, the commitment construction, the projection) are the VERIFIER's own
(``proof_verify.verify``), imported here rather than copied, so the producer can never mint an item the verifier
reads differently. Marks are producer claims fixed at mint; the kernel defines no mark vocabulary.
"""
from __future__ import annotations

import copy
import secrets
from collections.abc import Iterable
from typing import Any

from proof_verify.verify import (
    _COMMITTED,
    _INDEX_RE,
    _MARK_RE,
    _MAX_INDEX_DIGITS,
    commit,
    committed_objects,
    count_committed,
    item_problems,
)

DISCLOSURE_SCHEMA = "evidence.disclosure.v1"


def _salt_hex(salt: bytes | None) -> str:
    # SPEC 6.6.4 item 1 (producer obligation): "Each salt MUST be 32 bytes drawn fresh from the operating system's
    # cryptographically secure random generator at mint ... A deterministic salt source is allowed only in tests,
    # through an explicit mint parameter that is never the default."
    if salt is None:
        return secrets.token_bytes(32).hex()
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 32:
        raise ValueError("salt must be exactly 32 bytes (tests only; omit it to draw a fresh CSPRNG salt)")
    return bytes(salt).hex()


def committed_item(value: Any, marks: Iterable[str] = (), *, salt: bytes | None = None) -> dict:
    """A committed item in DISCLOSED form, to place inside ``Case.inputs`` or a capability's outputs of a canon-3
    bundle. ``marks`` are sorted; each must match ``[a-z0-9][a-z0-9.\\-]{0,63}`` (at most 16). ``salt`` is for tests
    only: by default a fresh 32-byte salt is drawn from the OS CSPRNG (``secrets.token_bytes``)."""
    marks = sorted(set(marks))
    bad = [m for m in marks if not (isinstance(m, str) and _MARK_RE.fullmatch(m))]
    if bad or len(marks) > 16:
        raise ValueError(f"marks must be at most 16 tokens matching [a-z0-9][a-z0-9.\\-]{{0,63}}: {bad or marks}")
    item = {_COMMITTED: 1, "marks": marks, "salt": _salt_hex(salt), "value": copy.deepcopy(value)}
    problems = item_problems(item)
    if problems:
        raise ValueError(f"cannot commit this value: {problems}")
    return item


def withheld_form(item: dict) -> dict:
    """The withheld form of a well-formed item: its commitment (recomputed for a disclosed item) and its marks."""
    problems = item_problems(item)
    if problems:
        raise ValueError(f"not a well-formed committed item: {problems}")
    c = item["commitment"] if "commitment" in item else commit(item["salt"], item["value"])
    return {_COMMITTED: 1, "commitment": c, "marks": list(item["marks"])}


def withheld_items(value: Any) -> list[str]:
    """Pointers (within ``value``) of every withheld-form item in ``value``."""
    return [ptr for ptr, _t, obj in committed_objects(value) if isinstance(obj, dict) and "commitment" in obj]


def disclosed_values(value: Any) -> Any:
    """``value`` after FULL DISCLOSURE: every disclosed committed item replaced by its plain ``value`` (a deep copy).
    This is what an engine computes on and what a re-run is compared by (SPEC v4 draft 15 step 3: "Under canon 3 a
    fresh bundle has fresh salts, so the comparison is made on the disclosed values"). A withheld item cannot be
    disclosed: raises ValueError ("N items withheld; reproduce not possible here", 10.6)."""
    refuse_withheld_items(value)          # once, at the top (not at every level: that was quadratic)
    return _disclosed(value)


def _disclosed(value: Any) -> Any:
    if isinstance(value, dict):
        if _COMMITTED in value:
            return copy.deepcopy(value.get("value"))
        return {k: _disclosed(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_disclosed(v) for v in value]
    return value


def canon_disclosed(value: Any) -> bytes:
    """The canon-3 re-run comparison: canon 2 over the fully disclosed value (marks and salts do not take part)."""
    from .envelope import canon_v2
    return canon_v2(disclosed_values(value))


def refuse_withheld_items(value: Any, what: str = "value") -> None:
    """SPEC 10.6: "Kernel tools that pass section values to an engine (reproduce, certify, adapters) MUST refuse a
    value that contains a withheld-form item. They MUST report "N items withheld; reproduce not possible here"."
    Raises ValueError with exactly that report."""
    n = count_committed(value, withheld_only=True)      # a count: no pointer string is built
    if n:
        raise ValueError(f"{n} items withheld; reproduce not possible here ({what})")


def _tokens(path: str) -> list[str]:
    if not path.startswith("/"):
        raise ValueError(f"item path must start with '/': {path!r}")
    return [t.replace("~1", "/").replace("~0", "~") for t in path[1:].split("/")]


def _resolve(doc: Any, tokens: list[str]) -> tuple[Any, Any]:
    """(container, key) for the LAST token; raises ValueError when the path does not resolve."""
    cur = doc
    for i, tok in enumerate(tokens):
        last = i == len(tokens) - 1
        if isinstance(cur, dict) and tok in cur:
            if last:
                return cur, tok
            cur = cur[tok]
        elif isinstance(cur, list) and len(tok) <= _MAX_INDEX_DIGITS and _INDEX_RE.fullmatch(tok) \
                and int(tok) < len(cur):
            if last:
                return cur, int(tok)
            cur = cur[int(tok)]
        else:
            break
    raise ValueError("path does not resolve")


def item_at(bundle: dict, path: str) -> dict:
    """The item object at an item path (``"/" + section + pointer``) in ``bundle``'s manifest copy."""
    toks = _tokens(path)
    if not toks or toks[0] not in ("inputs", "result", "provenance"):
        raise ValueError(f"item path must name a section: {path!r}")
    block = bundle["manifest"][toks[0]]
    if "value" not in block:
        raise ValueError(f"item path {path!r} lies in a withheld section")
    if len(toks) == 1:
        raise ValueError(f"a section root is never an item: {path!r}")
    try:
        container, key = _resolve(block["value"], toks[1:])
    except ValueError:
        raise ValueError(f"item path {path!r} does not resolve") from None
    obj = container[key]
    if not (isinstance(obj, dict) and _COMMITTED in obj):
        raise ValueError(f"item path {path!r} does not name a committed item")
    return obj


def set_item(bundle: dict, path: str, new_item: dict) -> None:
    """Replace the item at ``path`` in the manifest copy and, for a result item, in the readable ``result`` copy
    (6.6.5 item 4: "The same path names the corresponding item in the top-level `result` copy")."""
    toks = _tokens(path)
    targets = [bundle["manifest"][toks[0]]["value"]]
    if toks[0] == "result" and isinstance(bundle.get("result"), dict):
        targets.append(bundle["result"])
    for doc in targets:
        container, key = _resolve(doc, toks[1:])
        container[key] = copy.deepcopy(new_item)


def disclosure_package(bundle: dict, paths: Iterable[str]) -> dict:
    """SPEC 10.5 (informative tool format): ``{"schema": "evidence.disclosure.v1", "parent_bundle_sha256": <seal>,
    "items": [{"path", "salt", "value"}]}`` for the DISCLOSED items at ``paths`` in ``bundle`` (typically the
    holder's full copy). A package is as sensitive as the plaintext it carries."""
    items = []
    for path in sorted(set(paths)):
        obj = item_at(bundle, path)
        if "salt" not in obj:
            raise ValueError(f"the item at {path!r} is withheld in this copy; it cannot be disclosed from it")
        items.append({"path": path, "salt": obj["salt"], "value": copy.deepcopy(obj["value"])})
    return {"schema": DISCLOSURE_SCHEMA, "parent_bundle_sha256": bundle["bundle_sha256"], "items": items}


def merge_disclosure(bundle: dict, package: dict) -> dict:
    """See `_merge_disclosure`. Any malformed bundle or package raises ValueError (never KeyError/TypeError)."""
    try:
        return _merge_disclosure(bundle, package)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ValueError(f"malformed bundle or disclosure package ({type(exc).__name__}: {exc})") from None


def _merge_disclosure(bundle: dict, package: dict) -> dict:
    """SPEC 10.5: "Merging a package does three things: it rewrites each listed item into disclosed form; it removes
    those paths from `withheld_items`; it removes the whole record if both lists become empty (R2)." The merged copy
    verifies, or not, by 5.6.2 item 4: a value that does not match its sealed commitment changes the digest. The
    merge refuses a package for another seal, and an item whose (salt, value) does not open its commitment."""
    if not isinstance(package, dict) or package.get("schema") != DISCLOSURE_SCHEMA:
        raise ValueError(f"not a disclosure package ({DISCLOSURE_SCHEMA})")
    if not isinstance(bundle, dict) or not isinstance(package.get("items", []), list):
        raise ValueError("merge_disclosure needs a bundle object and a package whose items is an array")  # noqa: TRY004
    if package.get("parent_bundle_sha256") != bundle.get("bundle_sha256"):
        raise ValueError("the disclosure package is for a different seal")
    out = copy.deepcopy(bundle)
    merged = set()
    for entry in package.get("items", []):
        path = entry["path"]
        obj = item_at(out, path)
        disclosed = {_COMMITTED: 1, "marks": list(obj["marks"]), "salt": entry["salt"],
                     "value": copy.deepcopy(entry["value"])}
        if item_problems(disclosed):
            raise ValueError(f"the disclosed item at {path!r} is malformed: {item_problems(disclosed)}")
        if withheld_form(disclosed)["commitment"] != withheld_form(obj)["commitment"]:
            raise ValueError(f"the disclosed (salt, value) at {path!r} does not open its sealed commitment")
        set_item(out, path, disclosed)
        merged.add(path)
    red = out.get("redaction")
    if isinstance(red, dict) and isinstance(red.get("withheld_items"), list):
        red["withheld_items"] = [p for p in red["withheld_items"] if p not in merged]
        if not red["withheld_items"] and not red.get("withheld_sections"):
            del out["redaction"]
    return out


__all__ = ["DISCLOSURE_SCHEMA", "committed_item", "disclosure_package", "item_at", "merge_disclosure",
           "refuse_withheld_items", "set_item", "withheld_form", "withheld_items"]
