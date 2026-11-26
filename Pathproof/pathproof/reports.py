from collections import Counter, defaultdict
import csv
from io import StringIO
from pathlib import Path
import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .analysis import analyze
from .diagram import svg
from .checks.core import catalogue, findings
from .io import ASSETS, load_yaml, write_json, write_text

LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def compliance(rows: list) -> list:
    grouped = defaultdict(list)
    for row in rows:
        if row["cis"]:
            grouped[row["cis"]].append(row["status"])
    out = []
    for control in sorted({m["cis"] for m, _ in catalogue() if m["cis"]}):
        values = grouped[control]
        result = ("FAIL" if "FAIL" in values else "MANUAL" if "MANUAL" in values
                  else "PASS" if values else "NO_EVIDENCE")
        out.append({"control": control, "tested_subset": result, "counts": dict(Counter(values))})
    return out


def rules(path: Path | None) -> list:
    data = load_yaml(path or ASSETS / "mutelist.yaml")
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("Mutelist must contain a rules list.")
    for rule in data["rules"]:
        if not isinstance(rule, dict) or set(rule) != {"check_id", "resource", "reason"} or not all(
                isinstance(v, str) and v.strip() for v in rule.values()):
            raise ValueError("Each mute needs an exact check_id, resource and reason.")
    return data["rules"]


def scan(snap: dict, severity: str, mute: Path | None, risk: Path | None) -> dict:
    raw = findings(snap)
    muted = {(r["check_id"], r["resource"]): r["reason"] for r in rules(mute)}
    for row in raw:
        row["mute_reason"] = muted.get((row["check_id"], row["resource"]))
        row["visible"] = not row["mute_reason"] and LEVELS.index(row["severity"]) >= LEVELS.index(severity)
    return {"snapshot_id": snap["snapshot_id"], "findings": raw, "compliance": compliance(raw),
            "graph": analyze(snap, risk), "coverage": snap["inventory"]["coverage"]}


def cell(value: str) -> str:
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def exports(out: Path, report: dict, proofs: list | None = None) -> None:
    out.mkdir(parents=True, exist_ok=True)
    report = {**report, "proofs": proofs or []}
    visible = [r for r in report["findings"] if r["visible"]]
    write_json(out / "report.json", report)
    data = StringIO(newline="")
    writer = csv.writer(data)
    columns = ("check_id", "status", "severity", "resource", "region", "cis", "evidence")
    writer.writerow(columns)
    for row in visible:
        writer.writerow([cell(json.dumps(row[k], sort_keys=True) if k == "evidence" else str(row[k] or ""))
                         for k in columns])
    write_text(out / "report.csv", data.getvalue())
    env = Environment(loader=FileSystemLoader(ASSETS), autoescape=select_autoescape(["html"]))
    env.filters["graph_svg"] = svg
    script = ""
    try:
        import pyvis
    except ImportError:
        pass
    else:
        matches = sorted(Path(pyvis.__file__).parent.glob("templates/lib/vis-*/vis-network.min.js"))
        if matches:
            script = matches[-1].read_text(encoding="utf-8")
    html = env.get_template("report.html").render(report=report, visible=visible, script=script)
    write_text(out / "report.html", html)
