from . import ec2, iam, s3, services, trails
from .common import Reader
from ..io import seal


class AWS:
    def collect(self, regions: list[str]) -> dict:
        import boto3

        session = boto3.Session(region_name=regions[0])
        account = session.client("sts").get_caller_identity()["Account"]
        coverage = []
        def reader(service: str, region: str, scope: str | None = None) -> Reader:
            return Reader(session, service, region, coverage, scope)
        first = regions[0]
        rows = iam.collect(reader("iam", first, "global"), account)
        rows += s3.collect(reader("s3", first, "selected regions"), reader("s3control", first, "account"),
                           account, regions, rows[0]["facts"])
        for region in regions:
            for name, collect in (("ec2", ec2.collect), ("cloudtrail", trails.collect),
                                  ("kms", services.kms), ("rds", services.rds)):
                rows += collect(reader(name, region), region)
        return seal({"provider": "aws", "source": "aws", "regions": regions, "coverage": coverage,
                     "resources": sorted(rows, key=lambda row: row["id"])})
