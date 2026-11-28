from .core import Finding, assess


def rds01(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "encrypted")


def rds02(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "private")


def rds03(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "minor_upgrade")


def rds04(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "backups")


def rds05(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "deletion_protection")
