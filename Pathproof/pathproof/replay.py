from copy import deepcopy
from dataclasses import dataclass, asdict

from .analysis import analyze, statuses, techniques
from .fixtures import BUCKET, LAB, OBJECT, READER, ROLE, USER, snapshot, toggle
from .io import digest
from .policy import evaluate
from .sandbox import read, sandbox


@dataclass(frozen=True)
class Step:
    scenario: str
    actor: str
    target: str
    operation: str


def plan(key: str) -> dict:
    args = {"T1": ("Internet", OBJECT), "T2": (USER, ROLE), "T3": (USER, USER),
            "T4": ("Internet", LAB["instance"]), "T5": ("audit", LAB["trail"])}
    step = asdict(Step(key, *args[key], techniques()[key]["proof"]))
    steps = [step]
    if key in ("T2", "T4"):
        steps.append(asdict(Step(key, ROLE, OBJECT, "inspect_role_canary_grant")))
    return {"steps": steps, "plan_hash": digest(steps)}


def offline(snap: dict, key: str) -> dict:
    present = statuses(snap["inventory"], techniques())[key]
    state = {True: "present", False: "absent", None: "unknown"}[present]
    saved = plan(key)
    steps = [{"operation": saved["steps"][0]["operation"], "state": state}]
    if len(saved["steps"]) == 2:
        grants = [r["facts"].get("read_object") for r in snap["inventory"]["resources"] if r["id"] == ROLE]
        downstream = "supported_by_fixture" if grants == [OBJECT] else "unconfirmed"
        steps.append({"operation": "inspect_role_canary_grant",
                      "state": downstream if present is True else "not_reached"})
    return {"plan": saved, "step_observations": steps, "snapshot_id": snap["snapshot_id"], "mode": "snapshot",
            "state": state, "verdict": "THEORETICAL" if present is True and key != "T5" else None,
            "control": None, "observed": present}


def measure(state: dict, saved: dict, backend: str) -> dict:
    key = saved["steps"][0]["scenario"]
    if saved != plan(key):
        raise ValueError("The saved request differs from the registered lab plan.")
    snap = snapshot(state)
    result = offline(snap, key)
    result["mode"] = "lab"
    if key == "T1":
        with sandbox(state, backend) as (port, token):
            evidence = read(port, token, "Internet", backend)
            legitimate = read(port, token, READER, backend)
        result.update(verdict=evidence["verdict"], control=evidence["control"], evidence=evidence)
    else:
        with sandbox(state, backend) as (port, token):
            legitimate = read(port, token, READER, backend)
    if key in ("T2", "T3"):
        if key == "T2":
            answers = {"caller permission": evaluate(state["identity"], "sts:AssumeRole", ROLE),
                       "target trust": evaluate(state["trust"], "sts:AssumeRole", ROLE, USER, True)}
        else:
            answers = {"self-management permission": evaluate(state["identity"], "iam:PutUserPolicy", USER)}
        result["decisions"] = answers
        denied = [name for name, value in answers.items() if value in ("EXPLICIT_DENY", "IMPLICIT_DENY")]
        if denied:
            result.update(verdict="BLOCKED", control="local policy evaluator: " + ", ".join(denied))
    checks = {"reader_can_read_canary": legitimate["verdict"] == "PROVEN",
              "approved_principal_is_trusted": evaluate(state["trust"], "sts:AssumeRole", ROLE, READER, True) == "ALLOW",
              "instance_keeps_role": state["role_attachment"] == ROLE}
    result["must_still_work"] = {name: checks[name] for name in LAB["must_still_work"]}
    result["authorized_read"] = legitimate
    return result


def proof(state: dict, key: str, backend: str, risk=None) -> tuple[dict, dict]:
    saved = plan(key)
    before = measure(state, saved, backend)
    after_state, patch = toggle(deepcopy(state), key, False)
    if patch["field"] != techniques()[key]["fix"]:
        raise ValueError("Technique and patch disagree.")
    after = measure(after_state, saved, backend)
    healthy = all(before["must_still_work"].values()) and all(after["must_still_work"].values())
    expected_before = {"T1": "PROVEN", "T2": "THEORETICAL", "T3": "THEORETICAL",
                       "T4": "THEORETICAL", "T5": None}[key]
    after_ok = after["verdict"] == "BLOCKED" if key in ("T1", "T2", "T3") else after["state"] == "absent"
    before_ok = before["state"] == "present" and before["verdict"] == expected_before
    verified = healthy and after_ok and before_ok and patch["changed"]
    already = not patch["changed"] and healthy and after_ok
    outcome = "verified" if verified else "already_fixed" if already else "unresolved"
    report = {"scenario": key, "outcome": outcome, "patch": patch, "before": before, "after": after,
              "before_graph": analyze(snapshot(state), risk), "after_graph": analyze(snapshot(after_state), risk)}
    return (after_state if verified or already else state), report
