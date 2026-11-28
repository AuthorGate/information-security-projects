import json

from ..policy import evaluate


def statements(doc: object) -> list | None:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return None
    if not isinstance(doc, dict):
        return None
    raw = doc.get("Statement")
    if isinstance(raw, dict):
        raw = [raw]
    return raw if isinstance(raw, list) else None


def public_canary(page: dict | None, bucket: str) -> bool | None:
    if page == {}:
        return True
    doc = statements((page or {}).get("Policy"))
    result = evaluate(doc, "s3:GetObject", bucket + "/canary.txt", "Internet")
    return None if result == "UNKNOWN" else result != "ALLOW"


def trust_scope(doc: object, role: str, students: list[str]) -> bool | None:
    if not students:
        return None
    answers = [evaluate(statements(doc), "sts:AssumeRole", role, p, True) for p in students]
    if "ALLOW" in answers:
        return False
    return None if "UNKNOWN" in answers else True


def inline_self(reader, user: str, arn: str) -> bool | None:
    names = list(reader.rows("list_user_policies", "PolicyNames", UserName=user))
    combined = []
    for name in names:
        page = reader.call("get_user_policy", UserName=user, PolicyName=name)
        doc = statements((page or {}).get("PolicyDocument"))
        if doc is None:
            return None
        combined.extend(doc)
    value = evaluate(combined, "iam:PutUserPolicy", arn)
    return False if value == "ALLOW" else None
