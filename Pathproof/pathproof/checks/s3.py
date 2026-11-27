from .core import Finding, assess


def s301(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "account_bpa")


def s302(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "bucket_bpa")


def s303(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "private_canary")


def s304(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "versioning")


def s305(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "access_logging")
