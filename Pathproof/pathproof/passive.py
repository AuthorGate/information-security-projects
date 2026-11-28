from contextlib import closing
import re

from .conformance import AWS_DECISIONS


def permission(client, arn: str, target: str) -> dict:
    if not re.fullmatch(r"arn:aws:iam::[0-9]{12}:(user|role)/[\w+=,.@/-]+", arn):
        raise ValueError("Supply an exact IAM user or role ARN.")
    if not re.fullmatch(r"arn:aws:s3:::[a-z0-9.-]+/[a-zA-Z0-9._/-]+", target):
        raise ValueError("Supply one exact S3 object ARN.")
    action = "s3:GetObject"
    reply = client.simulate_principal_policy(PolicySourceArn=arn, ActionNames=[action], ResourceArns=[target])
    rows = reply.get("EvaluationResults", [])
    result = {"mode": "AWS policy simulation", "principal": arn, "action": action, "target": target,
              "verdict": None, "control": None, "decision": "UNKNOWN"}
    if len(rows) != 1 or reply.get("IsTruncated"):
        return result
    row = rows[0]
    if row.get("EvalActionName") != action or row.get("EvalResourceName") != target or row.get("MissingContextValues"):
        return result
    value = AWS_DECISIONS.get(row.get("EvalDecision"), "UNKNOWN")
    result["decision"] = value
    if value == "ALLOW":
        result["verdict"] = "POLICY-VERIFIED"
    if value in ("IMPLICIT_DENY", "EXPLICIT_DENY"):
        result.update(verdict="BLOCKED", control="AWS simulator: " + value)
    return result


def live(arn: str, target: str) -> dict:
    import boto3
    with closing(boto3.client("iam", region_name="us-east-1", endpoint_url="https://iam.amazonaws.com")) as client:
        return permission(client, arn, target)
