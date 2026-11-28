from dataclasses import dataclass, asdict
from functools import lru_cache
from importlib import import_module

from ..io import ASSETS, load_yaml


@dataclass(frozen=True)
class Finding:
    check_id: str
    service: str
    severity: str
    resource: str
    region: str
    status: str
    evidence: dict
    cis: str | None


def assess(item: dict, meta: dict, field: str) -> Finding:
    value = item["facts"].get(field)
    status = "MANUAL"
    if type(value) is bool:
        status = "PASS" if value else "FAIL"
    evidence = {"field": field, "observed": value}
    return Finding(meta["id"], meta["service"], meta["severity"], item["id"], item["region"],
                   status, evidence, meta["cis"])


@lru_cache
def catalogue() -> tuple:
    plugins = []
    for path in sorted((ASSETS / "checks").glob("*.yaml")):
        meta = load_yaml(path)
        if meta["id"] != path.stem or not meta["remediation"]:
            raise ValueError(f"Invalid metadata in {path.name}")
        module = import_module(f'pathproof.checks.{meta["service"]}')
        plugins.append((meta, getattr(module, path.stem.lower())))
    return tuple(plugins)


def findings(snapshot: dict) -> list[dict]:
    inv = snapshot["inventory"]
    results = []
    for meta, check in catalogue():
        for pos, item in enumerate(inv["resources"]):
            if item["type"] == meta["kind"]:
                finding = asdict(check(item, meta))
                finding["evidence"]["pointer"] = f'/inventory/resources/{pos}/facts/{meta["fact"]}'
                results.append(finding)
        for gap in inv["coverage"]:
            if gap["service"] == meta["service"] and gap["state"] != "complete":
                item = {"id": "coverage/" + gap["scope"], "region": gap["scope"], "facts": {}}
                row = asdict(check(item, meta))
                row["evidence"] = {"operation": gap["operation"], "error": gap["state"]}
                results.append(row)
    return sorted(results, key=lambda r: (r["check_id"], r["resource"], str(r["evidence"])))
