from itertools import islice
from pathlib import Path
import math

from .fixtures import BUCKET, LAB, OBJECT, ROLE, USER
from .io import ASSETS, load_yaml
from .policy import evaluate


def techniques() -> dict:
    return {p.stem: load_yaml(p) for p in sorted((ASSETS / "techniques").glob("*.yaml"))}


def conjunction(values: list) -> bool | None:
    return False if False in values else None if None in values else True


def decision(value: str) -> bool | None:
    return None if value == "UNKNOWN" else value == "ALLOW"


def observations(inv: dict) -> dict:
    rows = {r["id"]: r["facts"] for r in inv["resources"]}
    def facts(key: str) -> dict:
        return rows.get(key, {})
    local = inv.get("source") == "lab"
    scope = [r["facts"].get("active_multi") for r in inv["resources"] if r["type"] == "trail_scope"]
    gap = None if not scope or None in scope else not all(scope)
    if False in scope:
        gap = True
    found = {"missing_active_multiregion": gap}
    if local:
        user, bucket, role = facts(USER), facts(BUCKET), facts(ROLE)
        instance = facts(LAB["instance"])
        found.update(registered_canary=bucket.get("policy") is not None,
            anonymous_grant=decision(evaluate(bucket.get("policy"), "s3:GetObject", OBJECT, "Internet")),
            student_permission=decision(evaluate(user.get("identity"), "sts:AssumeRole", ROLE)),
            role_trust=decision(evaluate(role.get("trust"), "sts:AssumeRole", ROLE, USER, True)),
            self_management_permission=decision(evaluate(user.get("identity"), "iam:PutUserPolicy", USER)),
            public_ingress=instance.get("public_ingress"),
            optional_tokens=None if instance.get("imds_safe") is None else not instance["imds_safe"],
            attached_role=None if "role_attachment" not in instance else instance["role_attachment"] == ROLE)
    return found


def statuses(inv: dict, library: dict) -> dict:
    obs = observations(inv)
    return {key: conjunction([obs.get(p) for p in t["preconditions"]]) for key, t in library.items()}


def settings(path: Path | None) -> dict:
    config = load_yaml(path or ASSETS / "risk.yaml")
    for key, upper in (("impact", 5), ("covered", 100), ("gap", 100)):
        number = config[key]
        if type(number) not in (float, int) or not math.isfinite(number) or not 0 < number <= upper:
            raise ValueError("Invalid risk setting " + key)
    if config["gap"] < config["covered"]:
        raise ValueError("Gap multiplier must be at least the covered multiplier.")
    for key in ("T1", "T2", "T3", "T4"):
        if type(config["ease"][key]) is not int or not 1 <= config["ease"][key] <= 5:
            raise ValueError("Ease must be an integer from 1 through 5.")
    return config


def routes(nodes: list, edges: list, start: str, end: str, graph=None) -> list:
    if graph is not None:
        import networkx as nx
        return list(islice(nx.all_simple_paths(graph, start, end, cutoff=6), 100))
    paths = []
    def visit(path: list) -> None:
        if path[-1] == end:
            paths.append(path)
        elif len(path) <= 6 and len(paths) < 100:
            for edge in edges:
                if edge["source"] == path[-1] and edge["target"] not in path:
                    visit(path + [edge["target"]])
    visit([start])
    return paths


def analyze(snapshot: dict, risk: Path | None = None) -> dict:
    inv = snapshot["inventory"]
    library, config = techniques(), settings(risk)
    flags = statuses(inv, library)
    types = {"user", "role", "bucket", "instance", "database"}
    nodes = [{"id": "Internet", "type": "origin"}] + [
        {"id": r["id"], "type": r["type"]} for r in inv["resources"] if r["type"] in types]
    ids = {n["id"] for n in nodes}
    edges = []
    def edge(a: str, b: str, label: str, technique: str, evidence: str) -> None:
        if a in ids and b in ids:
            edges.append(dict(source=a, target=b, relation=label, technique=technique, evidence=evidence))
    for key, a, b, evidence in (("T1", "Internet", BUCKET, "registered canary policy"),
                                ("T2", USER, ROLE, "caller policy and target trust"),
                                ("T3", USER, USER, "self-management permission"),
                                ("T4", LAB["instance"], ROLE, "metadata setting and attached role")):
        if flags[key] is True:
            edge(a, b, library[key]["effect"], key, evidence)
    if flags["T4"] is True:
        edge("Internet", LAB["instance"], "public_ingress_configured", "T4", "modeled ingress")
    if inv["source"] == "lab" and any(r["id"] == ROLE and r["facts"].get("read_object") == OBJECT
                                        for r in inv["resources"]):
        edge(ROLE, BUCKET, "can_read", "", "role grant scoped to registered canary")
    if inv["source"] == "aws":
        for item in inv["resources"]:
            if item["type"] == "bucket" and item["facts"].get("private_canary") is False:
                edge("Internet", item["id"], "bucket_policy_allows_read", "",
                     "canary.txt policy statement; effective access unassessed")
    try:
        import networkx as nx
    except ModuleNotFoundError as exc:
        if exc.name != "networkx":
            raise
        graph, engine = None, "stdlib rehearsal"
    else:
        graph, engine = nx.DiGraph(), "networkx"
        graph.add_nodes_from(sorted(ids))
        graph.add_edges_from((e["source"], e["target"], e) for e in edges)
    starts = ["Internet"] + [r["id"] for r in inv["resources"] if r.get("labels", {}).get("low_privilege")]
    goals = [r["id"] for r in inv["resources"] if r.get("labels", {}).get("crown_jewel")]
    pairs = []
    lookup = {(e["source"], e["target"]): e for e in edges}
    for a in starts:
        for b in goals:
            if a not in ids or b not in ids:
                continue
            paths = []
            for chain in routes(nodes, edges, a, b, graph):
                steps = [lookup[p]["technique"] for p in zip(chain, chain[1:]) if lookup[p]["technique"]]
                if not steps:
                    continue
                base = config["impact"] * min(config["ease"][t] for t in steps)
                coverage = flags["T5"]
                low = config["gap"] if coverage is True else config["covered"]
                high = config["covered"] if coverage is False else config["gap"]
                paths.append({"nodes": chain, "techniques": list(dict.fromkeys(steps)),
                              "score_range": [base * low, base * high]})
            pairs.append({"start": a, "goal": b, "paths": paths})
    return {"engine": engine, "nodes": nodes, "edges": edges, "pairs": pairs, "conditions": flags,
            "scope": "classroom fixtures" if inv["source"] == "lab" else "inventory; identity reachability unassessed"}
