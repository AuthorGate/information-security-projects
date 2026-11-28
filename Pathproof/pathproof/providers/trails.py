from .common import Reader, boolean
from ..io import resource


def either(values: list) -> bool | None:
    if True in values:
        return True
    return None if None in values else False


def management(page: dict | None) -> bool | None:
    if page is None or "EventSelectors" not in page or page.get("AdvancedEventSelectors"):
        return None
    modes = set()
    for rule in page["EventSelectors"]:
        if rule.get("IncludeManagementEvents", True) and not rule.get("ExcludeManagementEventSources"):
            modes.add(rule.get("ReadWriteType", "All"))
    return "All" in modes or {"ReadOnly", "WriteOnly"} <= modes


def together(*values: bool | None) -> bool | None:
    return False if False in values else None if None in values else True


def collect(r: Reader, region: str) -> list:
    page = r.call("describe_trails", includeShadowTrails=True)
    rows, active, multi, full = [], [], [], []
    if page is None:
        active.append(None)
        multi.append(None)
        full.append(None)
    for trail in (page or {}).get("trailList", []):
        arn = trail["TrailARN"]
        logging = boolean(r.call("get_trail_status", Name=arn), "IsLogging")
        regional = together(logging, boolean(trail, "IsMultiRegionTrail"))
        mgmt = management(r.call("get_event_selectors", TrailName=arn))
        active.append(logging)
        multi.append(regional)
        full.append(together(regional, mgmt))
        rows.append(resource("trail", region + "/" + arn, {"validation": boolean(trail, "LogFileValidationEnabled"),
                             "kms": bool(trail.get("KmsKeyId"))}, region))
    rows.append(resource("trail_scope", "trails/" + region, {"logging": either(active),
                         "active_multi": either(multi), "multi_mgmt": either(full)}, region))
    return rows
