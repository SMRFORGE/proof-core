"""Human-readable rendering of sign-offs and seal signers (SPEC v4 13.5 headline, 13.6 rendering).

Every string taken from a bundle or a policy is shown through the fixed escape function `E` (13.6 "Escaping"), so a
bundle can never drive the reader's terminal or spoof a line, and the same bundle renders the same text on every
platform. The render states only what the format shows (10.3.9): a valid sign-off shows that the holder of a key
signed this text over this seal. It never says who the person is, and the signing time it shows is the time the
signer stated. The JSON output is not rendered: it keeps the original strings.

Standard library only; imports nothing from the producer.
"""
from __future__ import annotations

from typing import Any

#: SPEC 13.6: "A render that shows at least one attestation MUST show this sentence once".
CAVEAT = ("A sign-off shows only that the holder of the key signed this text over this seal. It does not show who "
          "the person is, or when, except \"existed no later than\" for an accepted timestamp.")
#: Advisory line for an accepted token whose genTime is later than the check time (`as_of`).
TSA_LATE = "TSA time is later than the check time (as_of); a TSA clock error or key misuse is the likely cause"
#: SPEC 13.4.1 "Derived default": the advisory note `signoff_timestamps_not_required` and its text line.
NOTE_SIGNOFF_TS = "signoff_timestamps_not_required"
SIGNOFF_TS_NOT_REQUIRED = ("the policy pins TSAs but sets require_signoff_timestamps false: a sign-off without an "
                           "accepted timestamp token is not rejected")
#: SPEC 13.6: shown when a `verifier` or `approver` entry is present and the roster is empty.
DISTINCTNESS_KEY_ID_ONLY = "distinctness checked by key and id only"
_STATUS_TEXT = {"demo_key": "demo key (anyone can sign)", "pinned_key": "pinned key", "unpinned_key": "unpinned key"}
#: SPEC 13.5 "Human-readable headline": the sign-off policy codes (13.4.3 rows 4 to 12).
_SIGNOFF_POLICY_CODES = frozenset({"self_verified", "signed_rejection", "name_mismatch_roster",
                                   "signer_id_mismatch_roster", "role_not_held", "signoff_time_inconsistent",
                                   "role_unsatisfied", "order_unsatisfied", "signoff_timestamp_missing"})


class RenderError(ValueError):
    """SPEC 13.6: "A renderer that cannot show a required field MUST refuse to render and say so. It MUST NOT drop
    the field." Raised instead of a partial render."""


def E(s: str) -> str:
    """SPEC 13.6 escape function E. U+0020 to U+007E pass through except `\\` (written `\\\\`); LF, CR and TAB are
    written `\\n`, `\\r`, `\\t`; every other code point c is `\\xNN` (c < U+0100), `\\uNNNN` (c < U+10000) or
    `\\UNNNNNNNN`, lowercase hex. A fixed rule, never the runtime's idea of "printable"."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif 0x20 <= o <= 0x7E:
            out.append(ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        else:
            out.append(f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}")
    return "".join(out)


def Q(s: str) -> str:
    """SPEC 13.6: the quoted form, `"` + E(s) with each `"` written `\\"` + `"`."""
    return '"' + E(s).replace('"', '\\"') + '"'


def _claimed(v: Any) -> str:
    """A claimed string of an INVALID entry: quoted, or `(not a string)` (13.6 item 6)."""
    return Q(v) if isinstance(v, str) else "(not a string)"


def headline(reasons: list[str]) -> str | None:
    """SPEC 13.5: when the decision turns the exit into 1, the headline names the first reason other than
    `state_not_accepted`. None when no such reason exists."""
    rest = [r for r in reasons if r != "state_not_accepted"]
    if not rest:
        return None
    code = rest[0]
    if code == "signoffs_invalid":
        return "fail (invalid sign-off)"
    if code in _SIGNOFF_POLICY_CODES:
        return f"fail (sign-off policy: {code})"
    if code in ("time_invalid", "time_malformed"):
        return "fail (invalid timestamp)"
    return f"fail (policy: {code})"


def seal_signer_lines(rep: dict) -> list[str]:
    """SPEC 13.6: "A seal signer MUST be shown as `sealed by key <key_id>` and never as a person's sign-off". One
    line per verified seal signature (v4 input, or v3 with a verified signature)."""
    seen, out = set(), []
    for e in rep.get("signers") or []:
        if isinstance(e, dict) and e.get("checked") and e.get("valid") and e.get("key_id") not in seen:
            seen.add(e["key_id"])
            out.append(f"sealed by key {E(str(e['key_id']))}")
    return out


def _copy_line(rc: Any, strict: bool = False) -> str:
    """The reviewed-copy line. A value that is not a well-typed record (an invalid entry's claim) is shown as the
    claimed JSON value, escaped."""
    n, ws = (rc.get("withheld_items_count"), rc.get("withheld_sections")) if isinstance(rc, dict) else (None, None)
    exact = not strict or (isinstance(rc, dict) and set(rc) == {"withheld_sections", "withheld_items_count",
                                                               "withheld_items_sha256"})
    if not (exact and isinstance(rc, dict) and isinstance(n, (int, float)) and not isinstance(n, bool)
            and isinstance(ws, list)
            and all(isinstance(x, str) for x in ws)):
        import json
        if rc is None:
            return "(no reviewed_copy)"
        return f"claimed value {E(json.dumps(rc, sort_keys=True, ensure_ascii=False))}"
    if not ws and n == 0:
        return "viewed the full copy"
    secs = ", ".join(E(str(x)) for x in ws)
    return f"viewed a copy with {int(n)} items withheld" + (f" (withheld sections: {secs})" if ws else "")


def _entry_lines(x: dict, by_digest: dict[str, dict], roster: dict[str, dict]) -> list[str]:
    """The six items of 13.6 "Per entry" for one entry, each on its own line."""
    i, state = x.get("index"), x.get("state")
    role, meaning, alg = x.get("role"), x.get("meaning"), x.get("alg")
    if state == "invalid":
        # 13.6 item 6: "An invalid entry MUST NOT be shown as a signature, an approval or a review anywhere in the
        # render": every field is labelled as a claim of an entry that is not a valid signature.
        banner = f"NOT A VALID SIGNATURE (claimed name: {_claimed(x.get('printed_name'))})"
        kid = E(x["key_id"]) if isinstance(x.get("key_id"), str) else "(none)"
        what = f"{_claimed(role)} {_claimed(meaning)}, statement {_claimed(x.get('statement'))}"
        lines = [f"sign-off #{i}: {banner}",
                 f"  claimed role and meaning code (not a valid signature): {what}",
                 f"  claimed printed name: {_claimed(x.get('printed_name'))}",
                 f"  claimed signer id: {_claimed(x.get('signer_id'))}; key id: {kid}",
                 f"  claimed time: {_claimed(x.get('signed_at'))} (time stated by the signer)",
                 f"  claimed copy: {_copy_line(x.get('reviewed_copy'), strict=True)}"]
        lines += [f"  problem: {E(str(p))}" for p in (x.get("problems") or [])[:4]]
        lines.append(f"  validity: {banner}")
        return lines
    for field in ("role", "meaning", "statement", "printed_name", "signer_id", "signed_at", "key_id", "alg"):
        if not isinstance(x.get(field), str):
            raise RenderError(f"sign-off #{i}: the required field {field!r} cannot be shown (not a string); refusing "
                              "to render rather than drop it")
    if not isinstance(x.get("prior"), list) or not isinstance(x.get("reviewed_copy"), dict):
        raise RenderError(f"sign-off #{i}: the required fields prior and reviewed_copy cannot be shown; refusing to "
                          "render rather than drop them")
    ext = ", extension meaning" if meaning.startswith("x-") else ""
    if state == "valid":
        head = f"sign-off #{i}: signed by the holder of key {E(x['key_id'])} as {E(role)} ({E(meaning)}{ext})"
    else:
        head = (f"sign-off #{i}: not checked, suite {E(alg)} (claimed role and meaning code: {E(role)} "
                f"{E(meaning)}{ext})")
    lines = [head, f"  statement: {Q(x['statement'])}"]
    ro = x.get("roster") or {}
    name = f"  printed name: {Q(x['printed_name'])}"
    if ro.get("status") == "pinned_person" and ro.get("name_differs"):
        person = roster.get(ro.get("person_id"), {})
        name += f" (roster name: {Q(str(person.get('printed_name', '')))}; name differs from roster)"
    lines.append(name)
    status = (f"pinned person {E(str(ro.get('person_id')))}" if ro.get("status") == "pinned_person"
              else _STATUS_TEXT.get(ro.get("status"), "key not matched (entry not checked)"))
    lines.append(f"  signer id: {E(x['signer_id'])}; key id: {E(x['key_id'])}; {status}")
    lines.append(f"  claimed signing time: {E(x['signed_at'])} (time stated by the signer)")
    for t in x.get("tokens") or []:
        if t.get("class") == "accepted":                         # 13.6 item 4 / TT-40 wording
            lines.append(f"  existed no later than {E(str(t.get('gen_time')))} per TSA {E(str(t.get('tsa')))}")
            if any("TSA time is later than the check time" in str(p) for p in t.get("problems") or []):
                lines.append(f"  note: {TSA_LATE}")
        else:
            lines.append(f"  timestamp token {t.get('index')}: {E(str(t.get('class')))} (gives no time bound)")
    lines.append(f"  {_copy_line(x['reviewed_copy'])}")
    for ref in x["prior"]:
        tgt = by_digest.get(ref)
        if tgt is not None and tgt.get("state") == "invalid":
            lines.append(f"  follows {tgt['index']} (NOT A VALID SIGNATURE)")
        elif tgt is not None and tgt.get("state") == "not_checked":
            lines.append(f"  follows {tgt['index']} (NOT CHECKED, not counted as a signature)")
        elif tgt is not None:
            lines.append(f"  follows {tgt['index']} ({E(str(tgt.get('role')))} {E(str(tgt.get('meaning')))})")
        else:
            lines.append(f"  follows an entry not in this bundle ({E(ref)})")
    if state == "valid":
        lines.append("  validity: valid")
    else:
        lines.append(f"  validity: not checked (suite {E(alg)} not supported by this verifier)")
    return lines


def time_lines(rep: dict) -> list[str]:
    """SPEC 10.7.7 TT-40 for the `time` dimension: an accepted time is stated as "existed no later than <T> per TSA
    <id>", or "existed no later than <T> (latest of N TSAs)" for several TSAs; never "signed at", "created at" or
    "made at". Each token that gives no bound is named with its class. [] when the bundle has no seal tokens."""
    t = rep.get("time") if isinstance(rep.get("time"), dict) else {}
    tokens = [x for x in t.get("tokens") or [] if isinstance(x, dict)]
    state = t.get("state")
    if state in (None, "none") or (not tokens and state == "not_checked"):
        return []
    out = []
    if state == "valid":
        tsas = sorted({str(x.get("tsa")) for x in tokens if x.get("class") == "accepted"})
        if t.get("distinct_tsas") == 1:
            out.append(f"time: existed no later than {E(str(t.get('bound')))} per TSA {E(tsas[0])}")
        else:
            out.append(f"time: existed no later than {E(str(t.get('bound')))} (latest of {t.get('distinct_tsas')} "
                       "TSAs)")
    else:
        out.append(f"time: {E(str(state))} (this record shows no time)")
    if "tsa_time_after_as_of" in (t.get("notes") or []):
        out.append(f"  note: {TSA_LATE}")
    for x in tokens:
        if x.get("class") != "accepted":
            out.append(f"  timestamp token {x.get('index')}: {E(str(x.get('class')))} (gives no time bound)")
    return out


def signoff_lines(rep: dict, roster: list | None = None) -> list[str]:
    """SPEC 13.6 for the `signoffs` of a v4 verdict: the block problem (if any), each entry's six items, the
    distinctness line and the caveat sentence. ``roster`` is the effective policy's roster (for the roster name of a
    `name differs` line). Raises RenderError rather than drop a required field. [] when there is nothing to show."""
    so = rep.get("signoffs") or {}
    entries = [x for x in so.get("entries") or [] if isinstance(x, dict)]
    out = [f"sign-offs: NOT VALID: {E(str(p))}" for p in so.get("problems") or []] if so.get("state") == "invalid" \
        else []
    waived = NOTE_SIGNOFF_TS in (rep.get("notes") or [])
    if not entries and not out:
        return [f"note: {SIGNOFF_TS_NOT_REQUIRED}"] if waived else []
    by_digest: dict[str, dict] = {}
    for x in entries:
        if isinstance(x.get("entry_sha256"), str):
            by_digest.setdefault(x["entry_sha256"], x)
    persons = {p["person_id"]: p for p in roster or [] if isinstance(p, dict) and "person_id" in p}
    if entries:
        out.append(f"sign-offs ({len(entries)}), outside the seal:")
    for x in entries:
        out += _entry_lines(x, by_digest, persons)
    if not persons and any(x.get("role") in ("verifier", "approver") for x in entries):
        out.append(DISTINCTNESS_KEY_ID_ONLY)
    if entries:
        out.append(CAVEAT)
    if waived:
        out.append(f"note: {SIGNOFF_TS_NOT_REQUIRED}")
    return out
