from contextlib import ExitStack
from importlib.util import find_spec
from unittest import TestCase, skipUnless
from unittest.mock import patch

from pathproof.providers.aws import AWS
from pathproof.providers.common import Reader


@skipUnless(find_spec("boto3"), "boto3 and botocore dependencies")
class SDK(TestCase):
    def test_six_collectors_through_sdk_clients(self) -> None:
        import boto3
        from botocore.stub import Stubber
        session = boto3.Session(aws_access_key_id="classroom", aws_secret_access_key="classroom",
                                region_name="us-east-1")
        responses = {
            "sts": [("get_caller_identity", {"Account":"111111111111","UserId":"classroom",
                                             "Arn":"arn:aws:iam::111111111111:user/classroom"})],
            "iam": [("get_account_summary", {"SummaryMap":{"AccountMFAEnabled":1,"AccountAccessKeysPresent":0}}),
                    ("get_account_password_policy", {"PasswordPolicy":{"MinimumPasswordLength":14}}),
                    ("list_users", {"Users":[]}), ("list_roles", {"Roles":[]})],
            "s3control": [("get_public_access_block", {"PublicAccessBlockConfiguration":{
                "BlockPublicAcls":True, "IgnorePublicAcls":True, "BlockPublicPolicy":True, "RestrictPublicBuckets":True}})],
            "s3": [("list_buckets", {"Buckets":[]})],
            "ec2": [("describe_security_groups", {"SecurityGroups":[]}), ("describe_instances", {"Reservations":[]}),
                    ("get_ebs_encryption_by_default", {"EbsEncryptionByDefault":True}),
                    ("describe_volumes", {"Volumes":[]})],
            "cloudtrail": [("describe_trails", {"trailList":[]})],
            "kms": [("list_keys", {"Keys":[]})],
            "rds": [("describe_db_instances", {"DBInstances":[]})]}
        clients, stubs = {}, []
        with ExitStack() as stack:
            for name, steps in responses.items():
                clients[name] = session.client(name)
                stub = stack.enter_context(Stubber(clients[name]))
                stubs.append(stub)
                for op, response in steps:
                    stub.add_response(op, response)
            with patch("boto3.Session") as factory:
                factory.return_value.client.side_effect = lambda service, **kw: clients[service]
                inv = AWS().collect(["us-east-1"])["inventory"]
            self.assertEqual({c["service"] for c in inv["coverage"]}, {"iam","s3","ec2","kms","rds","cloudtrail"})
            self.assertEqual(inv["source"], "aws")
            for stub in stubs:
                stub.assert_no_pending_responses()

    def test_pagination_error_retains_first_page(self) -> None:
        import boto3
        from botocore.stub import Stubber
        session = boto3.Session(aws_access_key_id="classroom", aws_secret_access_key="classroom",
                                region_name="us-east-1")
        coverage = []
        reader = Reader(session, "ec2", "us-east-1", coverage)
        with Stubber(reader.api) as stub:
            stub.add_response("describe_volumes", {"Volumes":[{"VolumeId":"vol-1"}],"NextToken":"page2"})
            stub.add_client_error("describe_volumes", "UnauthorizedOperation", expected_params={"NextToken":"page2"})
            result = list(reader.rows("describe_volumes", "Volumes"))
        self.assertEqual(result, [{"VolumeId":"vol-1"}])
        self.assertEqual(coverage[-1]["state"], "UnauthorizedOperation")
