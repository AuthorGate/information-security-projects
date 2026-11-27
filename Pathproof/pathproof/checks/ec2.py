from .core import Finding, assess


def ec201(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "ipv4_admin")


def ec202(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "ipv6_admin")


def ec203(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "empty")


def ec204(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "imds_safe")


def ec205(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "ebs_default")


def ec206(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "encrypted")
