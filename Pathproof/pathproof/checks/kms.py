from .core import Finding, assess


def kms01(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "rotation")


def kms02(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "enabled")


def kms03(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "no_deletion")
