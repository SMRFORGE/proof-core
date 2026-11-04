---
name: proof-core
description: Seal a computed result into a tamper-evident, independently re-runnable evidence bundle, and verify or reproduce one. Use when an agent produces a result (a number, a decision, a test or evaluation outcome, a file digest) that someone downstream has to trust and may need to re-run or audit later. Seals the result with its inputs so a neutral party can re-derive it offline, with no account and no network. Not a correctness check and not a logger; it makes a result re-runnable and tamper-evident, nothing more.
license: MIT
metadata:
  wraps: proof-core 0.28.0 (vendored, MIT)
  offline: true
---

# proof-core: seal, verify, reproduce

proof-core turns a computed result into an **evidence bundle**: a signed, canonical
JSON record of the result and the inputs it came from. Anyone can later **verify** the
bundle is unaltered and **reproduce** it by re-running the work on its sealed inputs.
It is vendored into this plugin and runs offline, standard-library only, no install.

All three verbs run from the vendored copy. Put the plugin's `bin/` on `PYTHONPATH`:

```
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core <seal|verify|reproduce> ...
```

**Never drop `-P`.** Without it, `python -m` puts the current folder ahead of `PYTHONPATH`, so a
`proof_verify/` or `hashlib.py` in the folder being checked runs instead of the vendored verifier and
can fake a pass. `reproduce` itself never imports a `--runner` from the current folder either (see
reproduce below).

## When to use it

- **seal**: right after producing a result the agent will hand off, or that a
  reviewer, a teammate, or a future reader must be able to trust and re-check.
- **verify**: to confirm a bundle you were handed is unaltered (and, under a real
  pinned key, that it came from the expected signer).
- **reproduce**: to re-run the work on the bundle's own sealed inputs and confirm the
  result comes out the same.

## seal

Write the inputs and outputs you want sealed as two JSON files, then:

```
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core seal \
  --capability "my:task" \
  --engine "my-tool" --engine-version "1.2.3" \
  --inputs inputs.json --outputs outputs.json \
  -o bundle.json
```

Required: `--capability`, `--engine`, `--engine-version`, `--inputs`, `--outputs`.
Optional: `--verdict pass|advisory|fail` (default pass), `--fidelity screening|reference`
(default screening), `--caveat "..."` (repeatable), `--provenance prov.json`,
`--data-label ID --data-sha sha256:HEX` (pin the data set, both together),
`--tolerance tol.json` (how the result reproduces: `{"kind": "exact"}`, or a stochastic
producer's statistical band), `--envelope v4|v3` (default `v4`), `-o bundle.json`
(default stdout). Add `--json` to print a machine summary (requires `-o`); without it a
short note goes to stderr. The producer sets `--verdict`/`--fidelity` as its own claims;
they are not vouched for by verify. Flags are spelled out in full: an abbreviation such as
`--env` or `--tol` is refused (exit 2).

**`seal` makes a v4 bundle (`evidence.envelope.v4`) by default**, the envelope both shipped
policy presets (`calc-package`, `two-person-review`) require. `--envelope v3` makes the frozen
legacy envelope, which either preset refuses (reason `envelope_below_minimum`). `calc-package` also
requires the bundle to declare how it reproduces: for a deterministic result pass `--tolerance
tol.json` with `tol.json` exactly `{"kind": "exact"}`; for a stochastic one, a statistical band.
Declare `exact` only when a re-run really gives the same result. `two-person-review` also needs two
human sign-offs, which `seal` does not add.

A seal plus `policy init --fill` passes `calc-package`. The key must be a production key, injected
out of band as `PROOF_SIGNING_SEED` (never the demo key: `init` refuses it, exit 2), and the key id
you fill in must be one you confirmed with its holder:

```
echo '{"kind": "exact"}' > exact.json
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core seal \
  --capability "my:task" --engine "my-tool" --engine-version "1.2.3" \
  --inputs inputs.json --outputs outputs.json --tolerance exact.json -o bundle.json
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core policy init --preset calc-package \
  --fill originator-key=ed25519:sha256:<64 hex> -o policy.json
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core verify bundle.json --policy policy.json --json
# exit 0: integrity + origin, decision accept
```

## verify

```
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core verify bundle.json --json
```

`--json` prints one object. **Gate on `exit_code` and `production_origin_pass`, never on
the `state` string.** Keys include `kind`, `exit_code`, `integrity_ok`, `state`,
`production_origin_pass`, `not_a_production_pass`.

Exit codes:

| code | meaning |
|---|---|
| 0 | integrity + origin: a production origin pass (`production_origin_pass: true`) |
| 1 | FAIL: edited, forged, malformed, an invalid human sign-off, a receiver policy that rejects the bundle for another reason, or a failed chain walk |
| 2 | the bundle could not be read, or a usage error |
| 3 | integrity-only: unaltered since signing, but origin NOT established (verify does not re-run anything) |
| 4 | unsupported canon: sealed under an encoding this verifier does not know; NOT a pass, use a newer verifier |
| 5 | chain incomplete or unknown, only with `--upstream`: an earlier bundle this one cites is missing or could not be checked; NOT a pass |
| 6 | unsupported signature suite (`unsupported-alg`): NOT a pass, use a newer verifier |

**Exit 3 is the normal result for the public build**, which pins a demo key anyone can
sign under. It proves integrity, not origin; `production_origin_pass` is `false`. An
automated origin gate MUST reject exit 3; it is not a production pass. Exit 0 is reachable
only when a real production trust root is pinned (`--pubkey HEX` / a dialect profile).

A bundle that cites earlier bundles (`derived_from`) is reported as `chain: not_checked`
unless you pass them: `--upstream PATH` (a file or a folder of `*.json`, repeatable) walks the
chain offline, and exit 5 means a link is missing or could not be checked.

## policy (receiver policy)

A receiver policy says which keys, sign-offs and timestamps the receiver trusts; `verify --policy FILE` decides
under it. The vendored `policy` verb (proof-core's `proof-policy`) writes and reads one:

```
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core policy init --list
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core policy explain policy.json
```

`init --preset NAME --fill SLOT=VALUE` writes a starter policy, `explain` prints its `policy_sha256` and what a
bundle must show to be accepted, and `add-pin` / `add-person` edit one. `add-pin --from-bundle` is not
authentication: the bundle's integrity says nothing about whose key signed it, so confirm the key id with its
holder and pass `--expect-key-id ID`. Without `--policy`, `verify` uses the file an absolute `PROOF_POLICY` names
(no folder is searched); every verdict reports `policy_source`, and `--expect-policy sha256:HEX` refuses (exit 2)
any other policy.

## reproduce

Re-runs the work on the bundle's sealed inputs and checks the result re-derives.

```
# with your own tool as a subprocess (the tool reads the two env vars itself):
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core reproduce bundle.json \
  --command "python /abs/path/to/recompute.py" --json
# on Windows (cmd.exe runs it, even from Git Bash) the path is C:\abs\path\to\recompute.py or C:/abs/...

# or with a Python ReproduceRunner / @sealed function:
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -P -m proof_core reproduce bundle.json \
  --runner mypkg.module:RunnerClass --json
```

The `--command` contract: proof-core writes the sealed case `{capability, inputs}` as JSON
to a temp path given in the env var **`PROOF_INPUTS`**; your command reads it, recomputes,
and writes the recomputed outputs as a JSON object to the path in **`PROOF_OUTPUT`**. Have
the command read those two variables from the environment itself (e.g. Python
`os.environ["PROOF_INPUTS"]` / `["PROOF_OUTPUT"]`), not by interpolating them into the
command string. `--command` runs under the OS default shell (`/bin/sh` on POSIX; `cmd.exe`
on Windows, even when you invoked proof-core from Git Bash or PowerShell), so `$PROOF_INPUTS`
expands on POSIX but NOT on Windows (there it is `%PROOF_INPUTS%`); reading from the
environment works on both. The command runs in a fresh temporary working directory, so reference your
tool by an ABSOLUTE path (or have it on PATH); a bare relative script name will not be
found. The runner/command is ALWAYS supplied here on the command line, never read from
the bundle.

**Using your own Python runner (`--runner`).** `reproduce` never imports a runner from the current
folder, and `-P` keeps `python -m` from doing so either: the folder you run in is often the sender's
unpacked bundle, and a planted `mypkg/module.py` there could replace your runner with one that just
hands back the sealed value. Name your runner one of two ways.

- As a module: put the folder that contains your package on `PYTHONPATH` next to the plugin,
  absolute paths only (`:` separates on POSIX, `;` on Windows).
- As a file: give its absolute path, `--runner /abs/path/to/your/project/mypkg/module.py:RunnerClass`
  (on Windows `C:\path\to\module.py:RunnerClass`; the spec splits at the last `:`). A relative
  file path is refused (exit 2). Under Git Bash, write the `C:\...` (or `C:/...`) form: a
  `/c/...` path is not absolute to Windows Python and is refused as relative.

```
# POSIX (Linux, macOS): entries separated by ':'
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin:/abs/path/to/your/project" python -P -m proof_core \
  reproduce bundle.json --runner mypkg.module:RunnerClass --json

# Windows (Git Bash shown): entries separated by ';', C:\ paths
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin;C:\abs\path\to\your\project" python -P -m proof_core \
  reproduce bundle.json --runner mypkg.module:RunnerClass --json
```

Never point at a runner inside the bundle's folder. If `--runner mypkg.module:...` says
`No module named 'mypkg'`, your project isn't on `PYTHONPATH`: add its absolute path. Don't `cd` into
the bundle folder to make it resolve.

Exit codes: `0` reproduced (`--runner`: the numbers and the sealed claim re-derive), `1` not
reproduced (or integrity failed, so it was never re-run), `2` usage / unreadable bundle, `3`
outputs reproduced but the sealed claims NOT re-derived (`--command` only; a partial result,
never a pass). `--json` emits a parseable verdict with the same
`kind`/`exit_code`/`state` fields.

## The honest boundary (state this plainly)

A seal proves the record is **unaltered** since it was signed. Sealing runs nothing, so it
does not show the result re-derives; `reproduce` is what shows it re-derives from its sealed
inputs (exit 0 only). It does **not** prove the result is correct, and it does **not**
prove the agent ran what it claims to have run. Closing that gap takes **independent
reproduction** by a party the producer does not control. When you hand off a claim, carry
the bundle's `bundle_sha256` with it so the record can be found and checked.

## Notes

- Runs fully offline: standard library only, no third-party dependencies, no network, no
  account.
- Needs Python 3.11+ on PATH. If `python` is not 3.11+ on this host, use `py -3.11 -P` (Windows)
  or `python3.11 -P`. `PYTHONPATH` must be the ABSOLUTE plugin path; the host supplies
  `${CLAUDE_PLUGIN_ROOT}` for you, so prefer it over a relative `bin/`.
- proof-core is MIT and not on PyPI; the source is vendored under this plugin's `bin/`.
