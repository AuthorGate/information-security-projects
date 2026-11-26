from contextlib import closing
from importlib.resources import files
import json
import re
from typing import Any

import yaml

from .policy import evaluate

AWS_DECISIONS = {"allowed": "ALLOW", "explicitDeny": "EXPLICIT_DENY", "implicitDeny": "IMPLICIT_DENY"}
USER_ARN = re.compile(r"arn:aws:iam::[0-9]{12}:user/([\w+=,.@/-]+)")


def cases() -> dict:
    return yaml.safe_load(files("pathproof").joinpath("assets/policy_cases.yaml").read_text("utf-8"))


def check_subject(client: Any, arn: str) -> None:
    if not USER_ARN.fullmatch(arn):
        raise ValueError("Use the ARN of a dedicated, empty sandbox IAM user.")
    name = arn.rsplit("/", 1)[-1]
    identity = client.get_user(UserName=name)["User"]
    if identity.get("Arn") != arn or identity.get("PermissionsBoundary"):
        raise ValueError("The simulator subject must match exactly and have no boundary.")
    for list_items, field in [(client.list_user_policies, "PolicyNames"),
                              (client.list_attached_user_policies, "AttachedPolicies"),
                              (client.list_groups_for_user, "Groups")]:
        page = list_items(UserName=name, MaxItems=1)
        if page.get(field) != [] or page.get("IsTruncated"):
            raise ValueError("The sandbox subject already has policies or groups.")


def simulate(client: Any, arn: str, action: str, target: str, statements: list[dict]) -> str:
    policy = json.dumps({"Version": "2012-10-17", "Statement": statements})
    response = client.simulate_principal_policy(PolicySourceArn=arn, ActionNames=[action],
                                               ResourceArns=[target], PolicyInputList=[policy])
    results = response.get("EvaluationResults", [])
    if len(results) != 1 or response.get("IsTruncated"):
        return "UNKNOWN"
    row = results[0]
    if (row.get("EvalActionName"), row.get("EvalResourceName")) != (action, target):
        return "UNKNOWN"
    if row.get("MissingContextValues") or row.get("OrganizationsDecisionDetail", {}).get(
            "AllowedByOrganizations") is False:
        return "UNKNOWN"
    return AWS_DECISIONS.get(row.get("EvalDecision"), "UNKNOWN")


def compare(client: Any = None, arn: str | None = None) -> dict:
    config = cases()
    if client is not None:
        if arn is None:
            raise ValueError("Missing simulator subject.")
        check_subject(client, arn)
    rows = []
    for case in config["cases"]:
        local = evaluate(case["statements"], config["action"], config["target"])
        remote = None
        if client is not None and arn is not None:
            remote = simulate(client, arn, config["action"], config["target"], case["statements"])
        comparable = remote is not None and "UNKNOWN" not in (local, remote)
        rows.append({"id": case["id"], "expected": case["expected"], "local": local, "aws": remote,
                     "fixture_match": local == case["expected"],
                     "agreement": local == remote if comparable else None})
    compared = sum(row["agreement"] is not None for row in rows)
    agreed = sum(row["agreement"] is True for row in rows)
    return {"cases": rows, "local_matches": sum(row["fixture_match"] for row in rows),
            "aws_agreed": agreed, "aws_compared": compared, "aws_excluded": len(rows) - compared,
            "aws_mode": "live simulation" if client is not None else "skipped",
            "agreement_fraction": agreed / compared if compared else None}


def online(arn: str) -> dict:
    if not USER_ARN.fullmatch(arn):
        raise ValueError("Use the ARN of a dedicated, empty sandbox IAM user.")
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        client = boto3.client("iam", region_name="us-east-1",
                              endpoint_url="https://iam.amazonaws.com")
        with closing(client):
            return compare(client, arn)
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"AWS conformance incomplete ({type(exc).__name__}).") from None
