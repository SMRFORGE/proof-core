---
name: proof-core
description: Seal a computed result into a tamper-evident, independently re-runnable evidence bundle, and verify or reproduce one. Use when an agent produces a result (a number, a decision, a test or evaluation outcome, a file digest) that someone downstream has to trust and may need to re-run or audit later. Seals the result with its inputs so a neutral party can re-derive it offline, with no account and no network. Not a correctness check and not a logger; it makes a result re-runnable and tamper-evident, nothing more.
license: MIT
metadata:
  wraps: proof-core 0.25.0 (vendored, MIT)
  offline: true
---

# proof-core: seal, verify, reproduce

proof-core turns a computed result into an **evidence bundle**: a signed, canonical
JSON record of the result and the inputs it came from. Anyone can later **verify** the
bundle is unaltered and **reproduce** it by re-running the work on its sealed inputs.
It is vendored into this plugin and runs offline, standard-library only, no install.

All three verbs run from the vendored copy. Put the plugin's `bin/` on `PYTHONPATH`:

```
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -m proof_core <seal|verify|reproduce> ...
```

## When to use it

- **seal** — right after producing a result the agent will hand off, or that a
  reviewer, a teammate, or a future reader must be able to trust and re-check.
- **verify** — to confirm a bundle you were handed is unaltered (and, under a real
  pinned key, that it came from the expected signer).
- **reproduce** — to re-run the work on the bundle's own sealed inputs and confirm the
  result comes out the same.

## seal

Write the inputs and outputs you want sealed as two JSON files, then:

```
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -m proof_core seal \
  --capability "my:task" \
  --engine "my-tool" --engine-version "1.2.3" \
  --inputs inputs.json --outputs outputs.json \
  -o bundle.json
```

Required: `--capability`, `--engine`, `--engine-version`, `--inputs`, `--outputs`.
Optional: `--verdict pass|advisory|fail` (default pass), `--fidelity screening|reference`
(default screening), `--caveat "..."` (repeatable), `--provenance prov.json`,
`--data-label ID --data-sha sha256:HEX` (pin the data set, both together),
`--tolerance tol.json` (a stochastic producer's statistical band), `-o bundle.json`
(default stdout). Add `--json` to print a machine summary (requires `-o`); without it a
short note goes to stderr. The producer sets `--verdict`/`--fidelity` as its own claims;
they are not vouched for by verify.

## verify

```
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -m proof_core verify bundle.json --json
```

`--json` prints one object. **Gate on `exit_code` and `production_origin_pass`, never on
the `state` string.** Keys include `kind`, `exit_code`, `integrity_ok`, `state`,
`production_origin_pass`, `not_a_production_pass`.

Exit codes:

| code | meaning |
|---|---|
| 0 | integrity + origin — a production origin pass (`production_origin_pass: true`) |
| 1 | FAIL — edited, forged, malformed, or an invalid human sign-off |
| 2 | the bundle could not be read, or a usage error |
| 3 | integrity-only — unaltered and re-derivable, but origin NOT established |
| 4 | unsupported canon — sealed under an encoding this verifier does not know; NOT a pass, use a newer verifier |
| 6 | unsupported signature suite (`unsupported-alg`) — NOT a pass, use a newer verifier |

**Exit 3 is the normal result for the public build**, which pins a demo key anyone can
sign under. It proves integrity, not origin — `production_origin_pass` is `false`. An
automated origin gate MUST reject exit 3; it is not a production pass. Exit 0 is reachable
only when a real production trust root is pinned (`--pubkey HEX` / a dialect profile).

## reproduce

Re-runs the work on the bundle's sealed inputs and checks the result re-derives.

```
# with your own tool as a subprocess (the tool reads the two env vars itself):
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -m proof_core reproduce bundle.json \
  --command "python recompute.py" --json

# or with a Python ReproduceRunner / @sealed function:
PYTHONPATH="${CLAUDE_PLUGIN_ROOT}/bin" python -m proof_core reproduce bundle.json \
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

Exit codes: `0` reproduced, `1` not reproduced (or integrity failed, so it was never
re-run), `2` usage / unreadable bundle. `--json` emits a parseable verdict with the same
`kind`/`exit_code`/`state` fields.

## The honest boundary (state this plainly)

A seal proves the record is **unaltered** since it was signed and that it **re-derives**
from its sealed inputs. It does **not** prove the result is correct, and it does **not**
prove the agent ran what it claims to have run. Closing that gap takes **independent
reproduction** by a party the producer does not control. When you hand off a claim, carry
the bundle's `bundle_sha256` with it so the record can be found and checked.

## Notes

- Runs fully offline: standard library only, no third-party dependencies, no network, no
  account.
- Needs Python 3.11+ on PATH. If `python` is not 3.11+ on this host, use `py -3.11` (Windows)
  or `python3.11`. `PYTHONPATH` must be the ABSOLUTE plugin path; the host supplies
  `${CLAUDE_PLUGIN_ROOT}` for you, so prefer it over a relative `bin/`.
- proof-core is MIT and not on PyPI; the source is vendored under this plugin's `bin/`.
