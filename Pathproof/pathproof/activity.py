from pathlib import Path

from .fixtures import baseline, snapshot, toggle
from .io import read_snapshot, state_lock, write_json
from .replay import measure, plan, proof
from .reports import exports, scan


def read_lab(path: Path) -> dict:
    import json
    state = json.loads(path.read_text(encoding="utf-8"))
    template = baseline()
    if not isinstance(state, dict) or set(state) != set(template):
        raise ValueError("This file is not a PathProof lab state.")
    for key in ("bucket_statements", "trust", "identity"):
        if not isinstance(state[key], list) or not all(isinstance(s, dict) for s in state[key]):
            raise ValueError("Invalid lab statement list.")
    if state["tokens"] not in ("required", "optional") or type(state["multi_region"]) is not bool:
        raise ValueError("Invalid lab configuration.")
    return state


def change(path: Path, key: str, broken: bool) -> dict:
    with state_lock(path):
        state = read_lab(path)
        next_state, patch = toggle(state, key, broken)
        if patch["changed"]:
            write_json(path, next_state)
        return patch


def repair(path: Path, key: str, backend: str, out: Path, risk: Path | None) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    with state_lock(path):
        state = read_lab(path)
        next_state, report = proof(state, key, backend, risk)
        write_json(out / "proof.json", report)
        write_json(out / "before.json", snapshot(state))
        if report["outcome"] == "unresolved":
            write_json(out / "retained-state.json", snapshot(state))
            candidate, _ = toggle(state, key, False)
            write_json(out / "after.json", snapshot(candidate))
        else:
            write_json(out / "after.json", snapshot(next_state))
        exports(out, scan(snapshot(next_state), "LOW", None, risk), [report])
        if report["outcome"] == "verified":
            write_json(path, next_state)
    return report


def demo(out: Path, backend: str, narrate: bool, risk: Path | None = None) -> list:
    out.mkdir(parents=True, exist_ok=False)
    state = baseline()
    for key in ("T1", "T2", "T3", "T4", "T5"):
        state, _ = toggle(state, key, True)
    start = snapshot(state)
    write_json(out / "before.json", start)
    report = scan(read_snapshot(out / "before.json"), "LOW", None, risk)
    if narrate:
        print("I planted one harmless file and saved the settings of the classroom lab.")
        print("I scanned the saved inventory and connected the related findings.")
    proofs = []
    words = {"T1": "The anonymous reader got the file before the fix. Afterward only the intended reader did.",
             "T2": "The trust decision now refuses the student and still accepts the approved principal.",
             "T3": "The policy decision now refuses the student's self-management permission.",
             "T4": "Requiring metadata tokens removed one premise of the modeled exposure.",
             "T5": "Restoring the multi-region trail removed the detection-gap multiplier."}
    for key in ("T1", "T5", "T2", "T3", "T4"):
        line = words[key]
        state, result = proof(state, key, backend, risk)
        proofs.append(result)
        before, after = result["before"], result["after"]
        print(f'{key} {before["verdict"] or before["state"]} -> {after["verdict"] or after["state"]} | {result["outcome"]}')
        if narrate:
            print(line if result["outcome"] == "verified" else "The experiment was inconclusive.")
    write_json(out / "after.json", snapshot(state))
    write_json(out / "proofs.json", proofs)
    exports(out, report, proofs)
    if narrate:
        print("The report records the original requests, the fixes, and the intended reader's access.")
    return proofs
