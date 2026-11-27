from .core import Finding, assess


def ct01(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "logging")


def ct02(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "multi_mgmt")


def ct03(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "validation")


def ct04(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "kms")
