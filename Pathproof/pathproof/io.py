from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterator

import yaml

ASSETS = Path(__file__).parent / "assets"


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return sha256(payload.encode()).hexdigest()


def seal(inventory: dict) -> dict:
    captured = datetime.now(timezone.utc).isoformat() if inventory.get("source") == "aws" else "2026-11-26T00:00:00+00:00"
    return {"schema_version": 2, "snapshot_id": digest(inventory), "inventory": inventory, "captured_at": captured}


def read_snapshot(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and type(data.get("schema_version")) is int and data["schema_version"] == 1:
        from .legacy import upgrade
        data = upgrade(data)
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 2:
        raise ValueError("Unsupported snapshot. Use a PathProof version 2 inventory.")
    inv = data.get("inventory")
    if not isinstance(inv, dict) or data.get("snapshot_id") != digest(inv):
        raise ValueError("Snapshot digest mismatch.")
    if inv.get("provider") != "aws" or not isinstance(inv.get("resources"), list):
        raise ValueError("Invalid AWS inventory.")
    seen = set()
    for row in inv["resources"]:
        if not isinstance(row, dict) or not isinstance(row.get("facts"), dict):
            raise ValueError("Invalid resource facts.")
        if not all(isinstance(row.get(k), str) for k in ("id", "type", "region")):
            raise ValueError("Invalid resource identity.")
        if row["id"] in seen:
            raise ValueError("Duplicate resource ID.")
        seen.add(row["id"])
    if not isinstance(inv.get("coverage"), list):
        raise ValueError("Missing coverage.")
    return data


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(content)
        except BaseException:
            f.close()
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def write_json(path: Path, value: object) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


@contextmanager
def state_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(path.suffix + ".lock")
    try:
        stream = lock.open("x")
    except FileExistsError:
        raise ValueError("Lab is locked. See the recovery note in README.md.") from None
    try:
        with stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        lock.unlink(missing_ok=True)


def resource(kind: str, key: str, facts: dict, region: str = "global", **labels) -> dict:
    return {"type": kind, "id": key, "region": region, "facts": facts, "labels": labels}
