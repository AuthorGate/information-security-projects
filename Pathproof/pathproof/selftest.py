from .checks.core import catalogue, findings
from .io import ASSETS, load_yaml
from .reference import reference_snapshot


def score(rows: list, truth: dict) -> dict:
    found = {(r["check_id"], r["resource"]): r["status"] for r in rows}
    results = {}
    for check, labels in truth.items():
        tp = fp = tn = fn = abstain = 0
        for label in ("good", "bad"):
            observed = found.get((check, labels[label]))
            positive = observed == "FAIL"
            abstain += observed not in ("FAIL", "PASS")
            if label == "bad":
                tp += positive
                fn += not positive
            else:
                fp += positive
                tn += observed == "PASS"
        results[check] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "abstained_labeled": abstain,
                          "precision": tp / (tp + fp) if tp + fp else None,
                          "recall": tp / (tp + fn) if tp + fn else None,
                          "coverage": (2 - abstain) / 2,
                          "unknown_is_manual": found.get((check, labels["unknown"])) == "MANUAL"}
    return results


def selftest() -> dict:
    truth = load_yaml(ASSETS / "truth.yaml")
    if set(truth) != {meta["id"] for meta, _ in catalogue()}:
        raise ValueError("Check catalogue and truth labels disagree.")
    return score(findings(reference_snapshot()), truth)
