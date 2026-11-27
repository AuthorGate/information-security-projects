from .io import digest, resource, seal

FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def upgrade(data: dict) -> dict:
    old = data.get("inventory")
    if not isinstance(old, dict) or data.get("snapshot_id") != "sha256:" + digest(old):
        raise ValueError("Legacy snapshot digest mismatch.")
    if old.get("account_ref") != "classroom" or old.get("provider") != "aws":
        raise ValueError("Unrecognized legacy inventory.")
    coverage = [{"service": service, "scope": "legacy", "operation": "week1 subset",
                 "state": "uncollected outside the Week 1 check"} for service in
                ("iam", "ec2", "cloudtrail", "kms", "rds")]
    rows = []
    for item in old.get("resources", []):
        if item.get("type") != "s3.bucket":
            raise ValueError("Unexpected legacy resource type.")
        flags = item.get("config", {}).get("public_access_block", {})
        complete = [c.get("state") for c in old.get("coverage", []) if
                    (c.get("operation"), c.get("resource_id"), c.get("region"), c.get("service")) ==
                    ("GetPublicAccessBlock", item["id"], item["region"], "s3")] == ["complete"]
        answer = None
        if complete and any(flags.get(k) is False for k in FLAGS):
            answer = False
        elif complete and all(flags.get(k) is True for k in FLAGS):
            answer = True
        rows.append(resource("bucket", item["id"], {"bucket_bpa": answer}, item["region"]))
    result = seal({"provider": "aws", "source": "legacy", "regions": old.get("requested_regions", []),
                 "resources": rows, "coverage": coverage, "legacy_snapshot_id": data["snapshot_id"]})
    result["captured_at"] = data.get("captured_at")
    return result
