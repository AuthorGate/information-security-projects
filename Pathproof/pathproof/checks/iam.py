from .core import Finding, assess


def iam01(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "root_mfa")


def iam02(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "no_root_key")


def iam03(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "console_mfa")


def iam04(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "password_length")


def iam05(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "password_reuse")


def iam06(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "trust_scoped")


def iam07(item: dict, meta: dict) -> Finding:
    return assess(item, meta, "self_scoped")
