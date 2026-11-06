"""Pin the vendored proof-core's behaviour that SKILL.md and README.md describe, so a re-vendor that changes it fails CI.

    python -P tools/check_behaviour.py

Runs from the vendored bin/ with no install and no network, in a scratch folder. Checks:
  1. `seal` (the CLI) mints evidence.envelope.v4 by default and v3 with --envelope v3.
  2. `reproduce --command` under the public demo key: the numbers re-derive but the gate does not pass, so it is
     exit 7 (`state: partial`, `reproduced: false`, `outputs_reproduced: true`, shortfall `gate_not_passed`),
     never exit 0. A drifted re-run is exit 1.
  3. The Python API (build_bundle, Adapter.seal) mints v4 by default; canon_version=1 gives v3; attest_bundle
     refuses a v4 bundle.
  4. Adapter.reproduce with a run that returns only the outcome is `outcome_reproduced`, never `reproduced`; a
     Rerun without a declared data_library is `environment_unverifiable`, never `reproduced`.
Exit 0 when every check holds, 1 (with the failing check named) otherwise.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

FAILURES = []
#: the vendored packages; the CLIs run in a scratch folder, so the path is absolute and set for every subprocess
BIN = pathlib.Path(__file__).resolve().parents[1] / "bin"
sys.path.insert(0, str(BIN))


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + (f" ({detail})" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def cli(*args, cwd):
    env = dict(os.environ)
    env.pop("PROOF_POLICY", None)              # the default trust inputs: the public demo pin
    env.pop("PROOF_SIGNING_SEED", None)
    env["PYTHONPATH"] = str(BIN)
    return subprocess.run([sys.executable, "-P", "-m", "proof_core", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, check=False)


def main():
    os.environ.pop("PROOF_POLICY", None)
    os.environ.pop("PROOF_SIGNING_SEED", None)
    with tempfile.TemporaryDirectory() as tmp:
        d = pathlib.Path(tmp)
        (d / "inputs.json").write_text('{"a": 2, "b": 3}', encoding="ascii")
        (d / "outputs.json").write_text('{"total": 5}', encoding="ascii")
        base = ["seal", "--capability", "arith:add", "--engine", "t", "--engine-version", "1",
                "--inputs", "inputs.json", "--outputs", "outputs.json"]

        # 1. seal CLI envelopes
        for extra, want, name in (([], "evidence.envelope.v4", "v4.json"),
                                  (["--envelope", "v3"], "evidence.envelope.v3", "v3.json")):
            r = cli(*base, *extra, "-o", name, cwd=d)
            kind = json.loads((d / name).read_text())["schema"] if r.returncode == 0 else None
            check(f"seal {' '.join(extra) or '(default)'} mints {want}", kind == want, r.stderr or kind)

        # 2. reproduce --command under the demo key: partial (7), never reproduced (0)
        for drift, want_code in ((0, 7), (1, 1)):
            script = d / f"recompute{drift}.py"
            script.write_text(
                "import json, os\n"
                "case = json.load(open(os.environ['PROOF_INPUTS']))\n"
                f"i = case['inputs']\njson.dump({{'total': i['a'] + i['b'] + {drift}}}, open(os.environ['PROOF_OUTPUT'], 'w'))\n",
                encoding="ascii")
            r = cli("reproduce", "v4.json", "--command", f'"{sys.executable}" "{script}"', "--json", cwd=d)
            try:
                v = json.loads(r.stdout)
            except ValueError:
                v = {}
            if want_code == 7:
                ok = (r.returncode == 7 and v.get("state") == "partial" and v.get("reproduced") is False
                      and v.get("outputs_reproduced") is True and "gate_not_passed" in (v.get("shortfalls") or []))
                check("reproduce --command, demo key, numbers match: exit 7 partial, not reproduced", ok,
                      f"exit {r.returncode}: {r.stdout[:300]} {r.stderr[:300]}")
            else:
                check("reproduce --command, drifted re-run: exit 1, not reproduced",
                      r.returncode == 1 and v.get("reproduced") is False,
                      f"exit {r.returncode}: {r.stdout[:300]} {r.stderr[:300]}")

    # 3. the Python API mints v4 by default
    import proof_core
    check("the Python API is the vendored copy", pathlib.Path(proof_core.__file__).resolve().parent == BIN / "proof_core",
          proof_core.__file__)
    from proof_core import Adapter, Case, Fidelity, Rerun, Result, Verdict, attest_bundle, build_bundle

    case = Case(capability="arith:add", inputs={"a": 2, "b": 3})
    result = Result(capability="arith:add", fidelity=Fidelity.SCREENING, verdict=Verdict.PASS,
                    outputs={"total": 5}, caveats=(), provenance={})
    v4 = build_bundle(case, result, engine="t", engine_version="1")
    v3 = build_bundle(case, result, engine="t", engine_version="1", canon_version=1)
    check("build_bundle mints v4 by default", v4.get("schema") == "evidence.envelope.v4", v4.get("schema"))
    check("build_bundle(canon_version=1) mints v3", v3.get("schema") == "evidence.envelope.v3", v3.get("schema"))
    adapter = Adapter(capability="arith:add", engine="t", engine_version="1")
    a4, raw4 = adapter.seal(inputs={"a": 2, "b": 3}, outcome={"total": 5}, verdict=Verdict.PASS, data_label="d")
    a3, _raw3 = adapter.seal(inputs={"a": 2, "b": 3}, outcome={"total": 5}, verdict=Verdict.PASS, data_label="d",
                             canon_version=1)
    check("Adapter.seal mints v4 by default", a4.get("schema") == "evidence.envelope.v4", a4.get("schema"))
    check("Adapter.seal(canon_version=1) mints v3", a3.get("schema") == "evidence.envelope.v3", a3.get("schema"))
    try:
        attest_bundle(v4, "reviewer", "R", b"\x01" * 32)
        refused = False
    except Exception:  # noqa: BLE001 -- any refusal will do; what matters is that no v1 sign-off is added
        refused = True
    check("attest_bundle refuses a v4 bundle", refused)

    # 4. Adapter.reproduce: a bare outcome is outcome_reproduced only; an undeclared environment is never reproduced
    bare = adapter.reproduce(raw4, lambda inp: {"total": inp["a"] + inp["b"]})
    check("Adapter.reproduce, bare outcome: outcome_reproduced, not reproduced",
          bare["outcome_reproduced"] is True and bare["reproduced"] is False, bare)
    full = adapter.reproduce(raw4, lambda inp: Rerun({"total": inp["a"] + inp["b"]}, Verdict.PASS))
    check("Adapter.reproduce, Rerun without data_library: environment_unverifiable, not reproduced",
          full["reproduced"] is False and "environment_unverifiable" in full["shortfalls"], full)

    if FAILURES:
        print(f"{len(FAILURES)} behaviour check(s) failed", file=sys.stderr)
        return 1
    print("all behaviour checks hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
