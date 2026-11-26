from .fixtures import baseline, snapshot, toggle, USER
from .io import ASSETS, load_yaml, resource, seal
from .providers import iam, ec2, s3, trails, services


class RecordedReads:
    def __init__(self, pages: dict):
        self.pages = pages

    def call(self, op: str, **params) -> dict | None:
        return self.pages.get(op)

    def rows(self, op: str, key: str, **params):
        return iter(self.pages.get(op, {}).get(key, []))


def reference_snapshot() -> dict:
    raw = load_yaml(ASSETS / "test_api.yaml")
    rows = []
    for label, recorded in raw.items():
        region = "us-east-1"
        readers = {service: RecordedReads(pages) for service, pages in recorded.items()}
        batch = iam.collect(readers["iam"], "classroom")
        batch += s3.collect(readers["s3"], readers["s3"], "classroom", [region], batch[0]["facts"])
        batch += ec2.collect(readers["ec2"], region)
        batch += trails.collect(readers["cloudtrail"], region)
        batch += services.kms(readers["kms"], region)
        batch += services.rds(readers["rds"], region)
        state = baseline()
        if label == "bad":
            for key in ("T2", "T3"):
                state, _ = toggle(state, key, True)
        lab = snapshot(state)["inventory"]["resources"]
        user = next(r for r in batch if r["type"] == "user")
        user["facts"]["self_scoped"] = next(r for r in lab if r["id"] == USER)["facts"]["self_scoped"]
        batch.append(next(r for r in lab if r["type"] == "role"))
        for item in batch:
            item["id"] = label + "/" + item["type"]
            rows.append(item)
    for kind in sorted({r["type"] for r in rows}):
        rows.append(resource(kind, "partial/" + kind, {}))
    return seal({"provider": "aws", "source": "accuracy fixtures", "regions": ["us-east-1"],
                 "coverage": [], "resources": rows})
