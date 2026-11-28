from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import csv
import json
import unittest
from unittest.mock import patch

from pathproof.checks.core import catalogue, findings
from pathproof.io import ASSETS, load_yaml, read_snapshot, write_json
from pathproof.reports import scan, exports
from pathproof.selftest import reference_snapshot, score, selftest


class Checks(unittest.TestCase):
    def test_all_thirty_have_three_independently_labelled_cases(self) -> None:
        results = selftest()
        self.assertEqual(len(results), 30)
        for name, row in results.items():
            with self.subTest(check=name):
                self.assertEqual([row[k] for k in ("tp", "fp", "tn", "fn")], [1, 0, 1, 0])
                self.assertTrue(row["unknown_is_manual"])

    def test_precision_and_recall_respond_to_different_errors(self) -> None:
        rows = findings(reference_snapshot())
        truth = load_yaml(ASSETS / "truth.yaml")
        for r in rows:
            if r["check_id"] == "IAM01" and r["resource"].startswith("bad/"):
                r["status"] = "MANUAL"
            if r["check_id"] == "S302" and r["resource"].startswith("good/"):
                r["status"] = "FAIL"
        data = score(rows, truth)
        self.assertEqual(data["IAM01"]["recall"], 0)
        self.assertIsNone(data["IAM01"]["precision"])
        self.assertEqual(data["S302"]["precision"], 0.5)

    def test_real_normalization_regression_changes_recall(self) -> None:
        with patch("pathproof.providers.ec2.admin_safe", return_value=True):
            results = selftest()
        self.assertEqual(results["EC201"]["recall"], 0)
        self.assertEqual(results["EC202"]["fn"], 1)
        self.assertEqual(results["RDS02"]["recall"], 1)

    def test_unknown_type_never_becomes_safe(self) -> None:
        for meta, check in catalogue():
            row = {"id": "x", "type": meta["kind"], "region": "global", "facts": {meta["fact"]: 1}}
            self.assertEqual(check(row, meta).status, "MANUAL")

    def test_gap_widens_review_scope(self) -> None:
        snap = reference_snapshot()
        snap["inventory"]["coverage"].append({"scope": "west", "service": "s3", "operation": "list_buckets",
                                             "state": "AccessDenied"})
        rows = [r for r in findings(snap) if r["resource"] == "coverage/west"]
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(r["status"] == "MANUAL" for r in rows))

    def test_filter_and_muting_preserve_compliance_and_raw_evidence(self) -> None:
        snap = reference_snapshot()
        full = scan(snap, "LOW", None, None)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "mute.yaml"
            path.write_text("rules: [{check_id: IAM01, resource: bad/account, reason: class}]", encoding="utf-8")
            view = scan(snap, "HIGH", path, None)
            self.assertEqual(full["compliance"], view["compliance"])
            target = next(r for r in view["findings"] if r["check_id"] == "IAM01" and r["resource"] == "bad/account")
            self.assertEqual((target["visible"], target["mute_reason"]), (False, "class"))
            exports(Path(tmp), view)
            self.assertEqual(len(json.loads((Path(tmp) / "report.json").read_text())["findings"]), 90)
            self.assertIn("CIS evidence", (Path(tmp) / "report.html").read_text(encoding="utf-8"))
            with (Path(tmp) / "report.csv").open(encoding="utf-8", newline="") as stream:
                csv_rows = list(csv.DictReader(stream))
            self.assertFalse(any(r["check_id"] == "IAM01" and r["resource"] == "bad/account" for r in csv_rows))
            self.assertEqual(len(csv_rows), sum(r["visible"] for r in view["findings"]))

    def test_digest_detects_edited_inventory(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            snap = deepcopy(reference_snapshot())
            snap["inventory"]["resources"].pop()
            write_json(path, snap)
            with self.assertRaisesRegex(ValueError, "digest"):
                read_snapshot(path)
