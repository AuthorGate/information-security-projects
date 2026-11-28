from copy import deepcopy

from .io import ASSETS, load_yaml, resource, seal
from .policy import evaluate

LAB = load_yaml(ASSETS / "lab.yaml")
USER, READER, ROLE = (LAB[k] for k in ("student", "reader", "role"))
BUCKET = LAB["bucket"]
OBJECT = BUCKET + "/" + LAB["canary"]
SERVICES = ("iam", "s3", "ec2", "cloudtrail", "kms", "rds")


def grant(sid: str, action: str, target: str, actor: str | None = None) -> dict:
    statement = {"Sid": sid, "Effect": "Allow", "Action": action, "Resource": target}
    if actor:
        statement["Principal"] = "*" if actor == "*" else {"AWS": actor}
    return statement


def trust(sid: str, actor: str) -> dict:
    return {"Sid": sid, "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": actor}}


BAD = {"T1": grant("PublicCanary", "s3:GetObject", OBJECT, "*"),
       "T2": trust("UnexpectedStudent", USER),
       "T3": grant("SelfManagement", "iam:PutUserPolicy", USER)}


def baseline() -> dict:
    return {"bucket_statements": [grant("KeepAnalyst", "s3:GetObject", OBJECT, READER)],
            "trust": [trust("KeepAnalyst", READER)],
            "identity": [grant("TrustCandidate", "sts:AssumeRole", ROLE)],
            "tokens": "required", "multi_region": True, "role_attachment": ROLE}


def toggle(state: dict, scenario: str, broken: bool) -> tuple[dict, dict]:
    new = deepcopy(state)
    keys = {"T1": "bucket_statements", "T2": "trust", "T3": "identity",
            "T4": "tokens", "T5": "multi_region"}
    key = keys[scenario]
    if scenario in BAD:
        statement = BAD[scenario]
        matches = [s for s in state[key] if s.get("Sid") == statement["Sid"]]
        if matches and matches != [statement]:
            raise ValueError("Ambiguous or edited grant. Automatic patch refused.")
        if broken and not matches:
            new[key].append(deepcopy(statement))
        elif not broken and matches:
            new[key].remove(statement)
    else:
        if scenario == "T4" and state[key] not in ("optional", "required"):
            raise ValueError("Unknown token configuration.")
        if scenario == "T5" and type(state[key]) is not bool:
            raise ValueError("Unknown trail configuration.")
        new[key] = ("optional" if broken else "required") if scenario == "T4" else not broken
    return new, {"field": key, "changed": new[key] != state[key], "old": state[key], "new": new[key]}


def permitted(result: str) -> bool | None:
    return None if result == "UNKNOWN" else result == "ALLOW"


def safe(result: str) -> bool | None:
    return None if result == "UNKNOWN" else result != "ALLOW"


def snapshot(state: dict) -> dict:
    public = evaluate(state["bucket_statements"], "s3:GetObject", OBJECT, "Internet")
    assume = evaluate(state["trust"], "sts:AssumeRole", ROLE, USER, trust=True)
    manage = evaluate(state["identity"], "iam:PutUserPolicy", USER)
    rows = [
        resource("account", "classroom", dict(root_mfa=True, no_root_key=True, password_length=True,
                 password_reuse=True, account_bpa=False)),
        resource("user", USER, dict(console_mfa=True, self_scoped=safe(manage),
                 identity=state["identity"]), low_privilege=True),
        resource("user", READER, dict(console_mfa=True, self_scoped=True)),
        resource("role", ROLE, dict(trust_scoped=safe(assume), trust=state["trust"],
                 read_object=OBJECT)),
        resource("bucket", BUCKET, dict(bucket_bpa=False, private_canary=safe(public), versioning=True,
                 access_logging=True, policy=state["bucket_statements"]), crown_jewel=True),
        resource("instance", LAB["instance"], dict(imds_safe=state["tokens"] == "required",
                 public_ingress=True, role_attachment=state["role_attachment"])),
        resource("sg", "web-sg", dict(ipv4_admin=True, ipv6_admin=True)),
        resource("default_sg", "default-sg", dict(empty=True)),
        resource("ec2_region", "ec2/us-east-1", dict(ebs_default=True)),
        resource("volume", "vol-classroom", dict(encrypted=True)),
        resource("trail_scope", "trails/us-east-1", dict(logging=True, multi_mgmt=state["multi_region"],
                 active_multi=state["multi_region"])),
        resource("trail", LAB["trail"], dict(validation=True, kms=True)),
        resource("key", "key-classroom", dict(enabled=True, no_deletion=True)),
        resource("rotation_key", "rotation/key-classroom", dict(rotation=True)),
        resource("database", LAB["database"], dict(encrypted=True, private=True, minor_upgrade=True,
                 backups=True, deletion_protection=True), crown_jewel=True)]
    coverage = [{"service": s, "scope": "classroom", "state": "complete", "operation": "seed"} for s in SERVICES]
    return seal({"provider": "aws", "source": "lab", "regions": ["us-east-1"],
                 "coverage": coverage, "resources": rows})
