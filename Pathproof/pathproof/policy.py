import re
from typing import Literal

Decision = Literal["ALLOW", "EXPLICIT_DENY", "IMPLICIT_DENY", "UNKNOWN"]
ACTIONS = {"s3:getobject": "arn:aws:s3:::", "sts:assumerole": "arn:aws:iam::",
           "iam:putuserpolicy": "arn:aws:iam::"}


def match(patterns: object, value: str, fold: bool = False) -> bool | None:
    items = patterns if isinstance(patterns, list) else [patterns]
    if not items or any(not isinstance(p, str) or not p or "${" in p for p in items):
        return None
    flags = re.IGNORECASE if fold else 0
    for item in items:
        regex = re.escape(item).replace(r"\*", ".*").replace(r"\?", ".")
        if re.fullmatch(regex, value, flags):
            return True
    return False


def principal_match(principal: object, actor: str) -> bool | None:
    if principal == "*":
        return True
    if not isinstance(principal, dict) or set(principal) != {"AWS"}:
        return None
    names = principal["AWS"]
    names = names if isinstance(names, list) else [names]
    if not names or any(not isinstance(n, str) for n in names):
        return None
    if actor in names or "*" in names:
        return True
    if any(n.endswith(":root") or n.isdigit() or "*" in n or "?" in n for n in names):
        return None
    return False


def evaluate(statements: object, action: str, target: str,
             actor: str | None = None, trust: bool = False) -> Decision:
    prefix = ACTIONS.get(action.lower())
    if not prefix or not target.startswith(prefix) or not isinstance(statements, list):
        return "UNKNOWN"
    if action.lower() == "s3:getobject" and "/" not in target[len(prefix):]:
        return "UNKNOWN"
    kind = {"sts:assumerole": ":role/", "iam:putuserpolicy": ":user/"}.get(action.lower())
    if kind and kind not in target:
        return "UNKNOWN"
    allowed = False
    uncertain = False
    for stmt in statements:
        if not isinstance(stmt, dict):
            uncertain = True
            continue
        if ("Action" in stmt) == ("NotAction" in stmt):
            uncertain = True
            continue
        action_hit = match(stmt.get("Action", stmt.get("NotAction")), action, True)
        if "NotAction" in stmt and action_hit is not None:
            action_hit = not action_hit
        resource_hit = True if trust and "Resource" not in stmt else match(stmt.get("Resource"), target)
        who = principal_match(stmt.get("Principal"), actor) if actor is not None else True
        hits = (action_hit, resource_hit, who)
        if False in hits:
            continue
        supported = {"Sid", "Effect", "Resource", "Action", "NotAction"}
        if actor is not None:
            supported.add("Principal")
        if None in hits or set(stmt) - supported or stmt.get("Effect") not in ("Allow", "Deny"):
            uncertain = True
        elif stmt["Effect"] == "Deny":
            return "EXPLICIT_DENY"
        else:
            allowed = True
    if uncertain:
        return "UNKNOWN"
    return "ALLOW" if allowed else "IMPLICIT_DENY"
