from .common import Reader
from .policy_facts import public_canary
from ..io import resource

FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def blocks(page: dict | None) -> bool | None:
    if page is None:
        return None
    if page == {}:
        return False
    settings = page.get("PublicAccessBlockConfiguration", {})
    if any(settings.get(k) is False for k in FLAGS):
        return False
    return True if all(settings.get(k) is True for k in FLAGS) else None


def collect(reader: Reader, account_reader: Reader, account: str, regions: list[str],
            account_facts: dict) -> list:
    absent = ("NoSuchPublicAccessBlockConfiguration",)
    account_facts["account_bpa"] = blocks(account_reader.call("get_public_access_block",
                                              AccountId=account, absent=absent))
    rows = []
    for bucket in reader.rows("list_buckets", "Buckets"):
        name = bucket["Name"]
        location = reader.call("get_bucket_location", Bucket=name)
        region = (location or {}).get("LocationConstraint") or "us-east-1"
        region = "eu-west-1" if region == "EU" else region
        if location is None:
            rows.append(resource("bucket", "arn:aws:s3:::" + name, {}, "unknown"))
            continue
        if region not in regions:
            continue
        version = reader.call("get_bucket_versioning", Bucket=name)
        logs = reader.call("get_bucket_logging", Bucket=name)
        tag_page = reader.call("get_bucket_tagging", Bucket=name, absent=("NoSuchTagSet",))
        tags = (tag_page or {}).get("TagSet", [])
        crown = any(t.get("Key") == "PathProofCrownJewel" and t.get("Value") == "true" for t in tags)
        page = reader.call("get_public_access_block", Bucket=name, absent=absent)
        facts = {"bucket_bpa": blocks(page), "versioning": None if version is None else
                 version.get("Status") == "Enabled", "access_logging": None if logs is None else
                 "LoggingEnabled" in logs}
        policy = reader.call("get_bucket_policy", Bucket=name, absent=("NoSuchBucketPolicy",))
        facts["private_canary"] = public_canary(policy, "arn:aws:s3:::" + name)
        rows.append(resource("bucket", "arn:aws:s3:::" + name, facts, region, crown_jewel=crown))
    return rows
