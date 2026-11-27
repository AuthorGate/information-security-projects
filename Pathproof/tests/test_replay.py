from copy import deepcopy
from http.client import HTTPConnection
from importlib.util import find_spec
import os
from unittest import TestCase, skipUnless
from unittest.mock import patch

from pathproof.analysis import analyze
from pathproof.conformance import online
from pathproof.fixtures import BAD, READER, baseline, snapshot, toggle
from pathproof.replay import measure, offline, plan, proof
from pathproof.restore import lab_state
from pathproof.sandbox import read, sandbox
from pathproof.storage import guard


class Experiments(TestCase):
    def test_every_scenario_has_appropriate_evidence_and_one_edit(self) -> None:
        for key in ("T1", "T2", "T3", "T4", "T5"):
            with self.subTest(scenario=key):
                bad, _ = toggle(baseline(), key, True)
                fixed, run = proof(bad, key, "memory")
                self.assertEqual(fixed, baseline())
                self.assertEqual(run["outcome"], "verified")
                self.assertEqual(run["before"]["plan"], run["after"]["plan"])
                self.assertTrue(all(run["after"]["must_still_work"].values()))
                self.assertEqual(sum(bad[k] != fixed[k] for k in bad), 1)
                if key in ("T1", "T2", "T3"):
                    self.assertEqual(run["after"]["verdict"], "BLOCKED")
                    self.assertTrue(run["after"]["control"])
                else:
                    self.assertEqual((run["after"]["verdict"], run["after"]["state"]), (None, "absent"))
                if key == "T1":
                    self.assertEqual(run["before"]["evidence"]["http_status"], 200)
                    self.assertEqual(run["after"]["evidence"]["http_status"], 403)
                    self.assertEqual(run["after"]["authorized_read"]["http_status"], 200)

    def test_repeated_fixes_are_idempotent(self) -> None:
        state, report = proof(baseline(), "T1", "memory")
        self.assertEqual(report["outcome"], "already_fixed")
        self.assertEqual(state, baseline())

    def test_graph_routes_scores_and_multiplier(self) -> None:
        state = baseline()
        for key in ("T1", "T2", "T3", "T4", "T5"):
            state, _ = toggle(state, key, True)
        graph = analyze(snapshot(state))
        self.assertTrue({"can_assume", "can_read", "can_modify_policy", "exposes_credentials"} <=
                        {e["relation"] for e in graph["edges"]})
        paths = [p for pair in graph["pairs"] for p in pair["paths"]]
        self.assertEqual(sorted(p["score_range"][0] for p in paths), [6, 18, 30])
        fixed, _ = toggle(state, "T5", False)
        after = analyze(snapshot(fixed))
        self.assertEqual(graph["edges"], after["edges"])
        self.assertEqual(sorted(p["score_range"][0] for pair in after["pairs"] for p in pair["paths"]), [4, 12, 20])

    def test_offline_read_does_not_use_network_and_rehydrates_identically(self) -> None:
        state, _ = toggle(baseline(), "T1", True)
        snap = snapshot(state)
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            self.assertEqual(offline(snap, "T1")["verdict"], "THEORETICAL")
            self.assertEqual(lab_state(snap), state)
        snap["inventory"]["source"] = "aws"
        with self.assertRaises(ValueError):
            lab_state(snap)

    def test_gate_unknown_does_not_get_a_blocked_verdict(self) -> None:
        state, _ = toggle(baseline(), "T1", True)
        state["bucket_statements"].append(dict(BAD["T1"], Effect="Deny", Condition={"unknown": True}))
        with sandbox(state, "memory") as (port, token):
            result = read(port, token, "Internet", "memory")
            self.assertEqual(result["http_status"], 409)
            self.assertIsNone(result["verdict"])

    def test_wrong_authorized_token_is_refused(self) -> None:
        with sandbox(baseline(), "memory") as (port, token):
            self.assertEqual(read(port, "wrong-token", READER, "memory")["http_status"], 401)

    def test_wrong_content_and_unknown_denial_cannot_prove_access(self) -> None:
        with patch("pathproof.sandbox.HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = "ALLOW"
            response.read.return_value = b"wrong"
            self.assertIsNone(read(8200, "", "Internet", "memory")["verdict"])
            response.status = 403
            self.assertIsNone(read(8200, "", "Internet", "memory")["verdict"])

    def test_guard_refuses_remote_alias_wrong_port_scheme_or_userinfo(self) -> None:
        for url in ("https://127.0.0.1:8200", "http://localhost:8200", "http://127.0.0.1:8201",
                    "http://127.0.0.1:8200@example.org", "http://169.254.169.254"):
            with self.assertRaises(ValueError):
                guard(url, 8200)
        guard("http://127.0.0.1:8200", 8200)

    def test_ambiguous_patch_and_broken_business_assertion(self) -> None:
        state, _ = toggle(baseline(), "T1", True)
        ambiguous = deepcopy(state)
        ambiguous["bucket_statements"].append(BAD["T1"])
        with self.assertRaises(ValueError):
            proof(ambiguous, "T1", "memory")
        state["bucket_statements"] = [BAD["T1"]]
        kept, report = proof(state, "T1", "memory")
        self.assertEqual(report["outcome"], "unresolved")
        self.assertEqual(kept, state)

    @skipUnless(find_spec("networkx"), "NetworkX dependency")
    def test_networkx_engine(self) -> None:
        self.assertEqual(analyze(snapshot(baseline()))["engine"], "networkx")

    @skipUnless(find_spec("moto") and find_spec("boto3"), "Moto and boto3 dependencies")
    def test_moto_owned_server(self) -> None:
        state, _ = toggle(baseline(), "T1", True)
        result = measure(state, plan("T1"), "moto")
        self.assertEqual(result["verdict"], "PROVEN")

    @skipUnless(os.getenv("PATHPROOF_CONFORMANCE_ARN"), "explicit authorized sandbox subject")
    def test_live_conformance(self) -> None:
        report = online(os.environ["PATHPROOF_CONFORMANCE_ARN"])
        self.assertEqual(report["aws_compared"], report["aws_agreed"])
        self.assertGreater(report["aws_compared"], 0)
