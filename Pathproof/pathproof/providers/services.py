from .common import Reader, boolean, labels
from ..io import resource


def kms(r: Reader, region: str) -> list:
    rows = []
    for key in r.rows("list_keys", "Keys"):
        detail = r.call("describe_key", KeyId=key["KeyId"])
        info = (detail or {}).get("KeyMetadata", {})
        state = info.get("KeyState")
        rows.append(resource("key", key["KeyArn"], {"enabled": boolean(info, "Enabled"),
                             "no_deletion": None if state is None else
                             state not in ("PendingDeletion", "PendingReplicaDeletion")}, region))
        eligible = (info.get("KeyManager") == "CUSTOMER" and info.get("Origin") == "AWS_KMS"
                    and info.get("KeySpec") == "SYMMETRIC_DEFAULT" and not info.get("CustomKeyStoreId"))
        if eligible or not info:
            page = r.call("get_key_rotation_status", KeyId=key["KeyId"]) if eligible else None
            rows.append(resource("rotation_key", "rotation/" + key["KeyArn"],
                                 {"rotation": boolean(page, "KeyRotationEnabled")}, region))
    return rows


def rds(r: Reader, region: str) -> list:
    rows = []
    for db in r.rows("describe_db_instances", "DBInstances"):
        facts = {"encrypted": boolean(db, "StorageEncrypted"), "private": boolean(db, "PubliclyAccessible", True),
                 "minor_upgrade": boolean(db, "AutoMinorVersionUpgrade"),
                 "deletion_protection": boolean(db, "DeletionProtection"),
                 "backups": None if "BackupRetentionPeriod" not in db else db["BackupRetentionPeriod"] >= 7}
        rows.append(resource("database", db["DBInstanceArn"], facts, region, **labels(db.get("TagList", []))))
    return rows
