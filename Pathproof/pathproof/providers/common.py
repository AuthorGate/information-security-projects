from collections.abc import Iterator
from typing import Any, Protocol


class Provider(Protocol):
    def collect(self, regions: list[str]) -> dict: ...


class Reader:
    def __init__(self, session: Any, service: str, region: str, coverage: list, scope: str | None = None):
        self.api = session.client(service, region_name=region)
        self.service = "s3" if service == "s3control" else service
        self.scope = scope or region
        self.coverage = coverage
        self.coverage.append({"service": self.service, "scope": self.scope,
                              "operation": "inventory", "state": "complete"})

    def error(self, op: str, exc: Exception) -> str:
        return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)

    def gap(self, op: str, reason: str) -> None:
        row = {"service": self.service, "scope": self.scope, "operation": op, "state": reason}
        if row not in self.coverage:
            self.coverage.append(row)

    def call(self, op: str, *, absent: tuple = (), **args) -> dict | None:
        from botocore.exceptions import BotoCoreError, ClientError
        try:
            return getattr(self.api, op)(**args)
        except (BotoCoreError, ClientError) as exc:
            code = self.error(op, exc)
            if code in absent:
                return {}
            self.gap(op, code)
            return None

    def rows(self, op: str, key: str, **args) -> Iterator[dict]:
        from botocore.exceptions import BotoCoreError, ClientError
        if not self.api.can_paginate(op):
            page = self.call(op, **args)
            if page is not None:
                yield from page.get(key, [])
                if page.get("NextToken") or page.get("IsTruncated") or page.get("Marker"):
                    self.gap(op, "incomplete pagination")
            return
        try:
            for page in self.api.get_paginator(op).paginate(**args):
                yield from page[key]
        except (BotoCoreError, ClientError) as exc:
            self.gap(op, self.error(op, exc))


def boolean(record: dict | None, key: str, invert: bool = False) -> bool | None:
    value = (record or {}).get(key)
    if type(value) is not bool:
        return None
    return not value if invert else value


def present(record: dict | None, key: str) -> bool | None:
    return None if record is None else bool(record.get(key))


def labels(tags: list) -> dict:
    allowed = {"PathProofCrownJewel": "crown_jewel", "PathProofLowPrivilege": "low_privilege"}
    return {allowed[t["Key"]]: True for t in tags
            if t.get("Key") in allowed and t.get("Value") == "true"}
