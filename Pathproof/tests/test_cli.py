from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from pathproof.cli import main
from pathproof.io import state_lock


class CLI(TestCase):
    def test_live_teacher_sequence(self) -> None:
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            lab = str(Path(tmp) / "lab.json")
            out = Path(tmp) / "proof"
            self.assertEqual(main(["lab", "seed", "--lab", lab]), 0)
            self.assertEqual(main(["lab", "seed", "--lab", lab]), 2)
            self.assertEqual(main(["lab", "break", "T1", "--lab", lab]), 0)
            before = Path(lab).read_bytes()
            self.assertEqual(main(["fix", "T1", "--lab", lab, "--preview"]), 0)
            self.assertEqual(before, Path(lab).read_bytes())
            self.assertEqual(main(["fix", "T1", "--lab", lab, "--out", str(out)]), 0)
            result = json.loads((out / "proof.json").read_text())
            self.assertEqual(result["outcome"], "verified")
            self.assertEqual(main(["replay", "T1", "--snapshot", str(out / "before.json"), "--rehydrate"]), 0)
            self.assertEqual(main(["fix", "T1", "--lab", lab, "--out", str(out)]), 2)
            self.assertEqual(main(["lab", "fix", "T1", "--lab", lab]), 0)

    def test_competing_lab_writer_rejected(self) -> None:
        with TemporaryDirectory() as tmp, redirect_stderr(StringIO()):
            lab = Path(tmp) / "state.json"
            with state_lock(lab):
                self.assertEqual(main(["lab", "seed", "--lab", str(lab)]), 2)
            self.assertFalse(lab.exists())

    def test_offline_demo_reports_and_reproducibility(self) -> None:
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()):
            reports = []
            for name in ("one", "two"):
                out = Path(tmp) / name
                self.assertEqual(main(["demo", "--narrate", "--out", str(out)]), 0)
                reports.append(json.loads((out / "report.json").read_text()))
                self.assertEqual(len(reports[-1]["proofs"]), 5)
                self.assertNotIn("Bearer ", (out / "report.json").read_text())
                self.assertTrue((out / "report.html").is_file())
            self.assertEqual(reports[0], reports[1])
