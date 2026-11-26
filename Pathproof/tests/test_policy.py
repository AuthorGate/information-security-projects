from unittest import TestCase
from unittest.mock import Mock

from pathproof.conformance import cases, compare
from pathproof.fixtures import OBJECT, ROLE, USER, grant, trust
from pathproof.passive import permission
from pathproof.policy import evaluate


class Policies(TestCase):
    def test_explicit_deny_overrides_conditional_and_allow(self) -> None:
        allow = grant("a", "s3:G?t*", OBJECT)
        deny = dict(allow, Effect="Deny")
        conditional = dict(allow, Condition={"example": True})
        for ordered in ([conditional, deny, allow], [allow, deny, conditional]):
            self.assertEqual(evaluate(ordered, "S3:GetObject", OBJECT), "EXPLICIT_DENY")
        self.assertEqual(evaluate([allow, conditional], "s3:GetObject", OBJECT), "UNKNOWN")

    def test_notaction_is_resource_scoped(self) -> None:
        rule = {"Effect": "Allow", "NotAction": "s3:List*", "Resource": OBJECT}
        self.assertEqual(evaluate([rule], "s3:GetObject", OBJECT), "ALLOW")
        self.assertEqual(evaluate([dict(rule, NotAction="s3:Get*")], "s3:GetObject", OBJECT), "IMPLICIT_DENY")
        self.assertEqual(evaluate([rule], "iam:PutUserPolicy", OBJECT), "UNKNOWN")

    def test_trust_and_unknown(self) -> None:
        rule = trust("x", USER)
        self.assertEqual(evaluate([rule], "sts:AssumeRole", ROLE, USER, True), "ALLOW")
        root = dict(rule, Principal={"AWS": "arn:aws:iam::111111111111:root"})
        self.assertEqual(evaluate([root], "sts:AssumeRole", ROLE, USER, True), "UNKNOWN")

    def test_lists_and_resource_case(self) -> None:
        rule = grant("a", "s3:GetObject", OBJECT)
        rule.update(Action=["s3:Get*", "s3:List*"], Resource=[OBJECT.upper()])
        self.assertEqual(evaluate([rule], "s3:GetObject", OBJECT), "IMPLICIT_DENY")

    def test_passive_decision_requires_complete_exact_scope(self) -> None:
        client = Mock()
        row = {"EvalActionName": "s3:GetObject", "EvalResourceName": OBJECT, "EvalDecision": "allowed"}
        client.simulate_principal_policy.return_value = {"EvaluationResults": [row]}
        self.assertEqual(permission(client, USER, OBJECT)["verdict"], "POLICY-VERIFIED")
        row["EvalDecision"] = "explicitDeny"
        self.assertEqual(permission(client, USER, OBJECT)["verdict"], "BLOCKED")
        row["MissingContextValues"] = ["context"]
        self.assertIsNone(permission(client, USER, OBJECT)["verdict"])
        with self.assertRaises(ValueError):
            permission(client, USER, OBJECT + "*")

    def test_conformance_cases_offline_and_simulator_disagreement(self) -> None:
        report = compare()
        self.assertEqual(report["local_matches"], len(cases()["cases"]))
        self.assertEqual(report["aws_mode"], "skipped")
        client = Mock()
        client.get_user.return_value = {"User": {"Arn": USER}}
        client.list_user_policies.return_value = {"PolicyNames": []}
        client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        client.list_groups_for_user.return_value = {"Groups": []}
        config = cases()
        client.simulate_principal_policy.return_value = {"EvaluationResults": [
            {"EvalActionName": config["action"], "EvalResourceName": config["target"], "EvalDecision": "implicitDeny"}]}
        result = compare(client, USER)
        self.assertLess(result["aws_agreed"], result["aws_compared"])
        self.assertGreater(result["aws_excluded"], 0)
