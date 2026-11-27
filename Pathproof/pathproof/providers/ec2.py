from .common import Reader, boolean
from ..io import resource


def admin_safe(rules: list, ipv6: bool) -> bool:
    field, cidr, public = ("Ipv6Ranges", "CidrIpv6", "::/0") if ipv6 else (
        "IpRanges", "CidrIp", "0.0.0.0/0")
    for rule in rules:
        if not any(r.get(cidr) == public for r in rule.get(field, [])):
            continue
        if rule.get("IpProtocol") == "-1":
            return False
        if rule.get("IpProtocol") in ("tcp", "6") and any(
                rule.get("FromPort", 0) <= p <= rule.get("ToPort", 65535) for p in (22, 3389)):
            return False
    return True


def collect(r: Reader, region: str) -> list:
    rows = []
    for sg in r.rows("describe_security_groups", "SecurityGroups"):
        rules = sg["IpPermissions"]
        rows.append(resource("sg", sg["GroupId"], {"ipv4_admin": admin_safe(rules, False),
                             "ipv6_admin": admin_safe(rules, True)}, region))
        if sg["GroupName"] == "default":
            rows.append(resource("default_sg", "default/" + sg["GroupId"],
                                 {"empty": not (rules or sg["IpPermissionsEgress"])}, region))
    for page in r.rows("describe_instances", "Reservations"):
        for item in page["Instances"]:
            data = item.get("MetadataOptions", {})
            safe = None
            if data.get("HttpEndpoint") == "disabled" or data.get("HttpTokens") == "required":
                safe = True
            elif data.get("HttpEndpoint") == "enabled" and data.get("HttpTokens") == "optional":
                safe = False
            facts = {"imds_safe": safe, "public_ip_assigned": bool(item.get("PublicIpAddress")),
                     "instance_profile_attached": bool(item.get("IamInstanceProfile"))}
            rows.append(resource("instance", item["InstanceId"], facts, region))
    rows.append(resource("ec2_region", "ec2/" + region,
                         {"ebs_default": boolean(r.call("get_ebs_encryption_by_default"),
                                                 "EbsEncryptionByDefault")}, region))
    for vol in r.rows("describe_volumes", "Volumes"):
        rows.append(resource("volume", vol["VolumeId"], {"encrypted": boolean(vol, "Encrypted")}, region))
    return rows
