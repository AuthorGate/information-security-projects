from unittest import TestCase

from pathproof.providers import ec2, iam, s3, services, trails
from pathproof.providers.policy_facts import public_canary, trust_scope
from pathproof.fixtures import BAD, BUCKET, ROLE, USER


class Pages:
    def __init__(self, values: dict):
        self.values = values

    def call(self, name, **params):
        return self.values.get(name)

    def rows(self, name, key, **params):
        return iter(self.values.get(name, {}).get(key, []))


class AWSCollectors(TestCase):
    def test_iam_independent_observations(self) -> None:
        values = {"get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1}},
                  "get_account_password_policy": {"PasswordPolicy": {"MinimumPasswordLength": 13, "PasswordReusePrevention": 24}},
                  "list_users": {"Users": [{"UserName": "student", "Arn": USER}]}, "get_login_profile": {},
                  "list_roles": {"Roles": [{"Arn": ROLE, "AssumeRolePolicyDocument": {"Statement": [BAD["T2"]]}}]},
                  "list_user_tags": {"Tags": [{"Key": "PathProofLowPrivilege", "Value": "true"}]},
                  "list_user_policies": {"PolicyNames": ["example"]}, "get_user_policy": {"PolicyDocument": {"Statement": BAD["T3"]}}}
        results = iam.collect(Pages(values), "classroom")
        facts = {r["type"]: r["facts"] for r in results}
        self.assertEqual(facts["account"], {"root_mfa": True, "no_root_key": False,
                                            "password_length": False, "password_reuse": True})
        self.assertEqual(facts["user"], {"console_mfa": True, "self_scoped": False})
        self.assertFalse(facts["role"]["trust_scoped"])

    def test_s3_regions_redaction_and_unknown(self) -> None:
        page = Pages({"list_buckets": {"Buckets": [{"Name": BUCKET.split(":::")[1]}]},
                      "get_bucket_location": {"LocationConstraint": None},
                      "get_bucket_policy": {"Policy": {"Statement": BAD["T1"]}},
                      "get_bucket_versioning": {"Status": "Enabled"},
                      "get_bucket_tagging": {"TagSet": [{"Key":"secret", "Value":"SENTINEL"}]}})
        account = {}
        rows = s3.collect(page, page, "classroom", ["us-east-1"], account)
        self.assertIsNone(account["account_bpa"])
        self.assertIsNone(rows[0]["facts"]["bucket_bpa"])
        self.assertTrue(rows[0]["facts"]["versioning"])
        self.assertFalse(rows[0]["facts"]["private_canary"])
        self.assertNotIn("SENTINEL", str(rows))
        self.assertTrue(public_canary({}, BUCKET))
        self.assertIsNone(public_canary(None, BUCKET))
        self.assertIsNone(trust_scope({}, ROLE, [USER]))

    def test_ec2_ipv6_ranges_all_ports_and_default_scope(self) -> None:
        public = {"IpProtocol":"tcp","FromPort":20,"ToPort":23,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]}
        p = Pages({"describe_security_groups":{"SecurityGroups":[{"GroupId":"sg-1","GroupName":"default",
                   "IpPermissions":[public],"IpPermissionsEgress":[]}]},
                   "describe_instances":{"Reservations":[{"Instances":[{"InstanceId":"i-1","MetadataOptions":{
                   "HttpEndpoint":"enabled","HttpTokens":"optional"}}]}]},
                   "describe_volumes":{"Volumes":[{"VolumeId":"vol-1","Encrypted":True}]}})
        rows = {r["type"]:r["facts"] for r in ec2.collect(p, "us-east-1")}
        self.assertEqual(rows["sg"], {"ipv4_admin":True,"ipv6_admin":False})
        self.assertFalse(rows["default_sg"]["empty"])
        self.assertFalse(rows["instance"]["imds_safe"])
        self.assertTrue(rows["volume"]["encrypted"])

    def test_cloudtrail_coverage_management_and_status_are_separate(self) -> None:
        p = Pages({"describe_trails":{"trailList":[{"TrailARN":"trail","IsMultiRegionTrail":True,
                   "LogFileValidationEnabled":True}]}, "get_trail_status":{"IsLogging":True},
                   "get_event_selectors":{"AdvancedEventSelectors":[{}]}})
        facts = trails.collect(p, "us-east-1")[-1]["facts"]
        self.assertTrue(facts["active_multi"])
        self.assertIsNone(facts["multi_mgmt"])
        self.assertFalse(trails.collect(Pages({"describe_trails":{"trailList":[]}}), "x")[-1]["facts"]["logging"])
        self.assertIsNone(trails.collect(Pages({}), "x")[-1]["facts"]["logging"])

    def test_kms_eligibility_and_rds_known_and_missing(self) -> None:
        p = Pages({"list_keys":{"Keys":[{"KeyId":"k","KeyArn":"arn-k"}]},
                   "describe_key":{"KeyMetadata":{"KeyManager":"CUSTOMER","KeySpec":"SYMMETRIC_DEFAULT",
                   "Origin":"AWS_KMS","Enabled":False,"KeyState":"PendingDeletion"}},
                   "get_key_rotation_status":{"KeyRotationEnabled":True},
                   "describe_db_instances":{"DBInstances":[{"DBInstanceArn":"db","PubliclyAccessible":True,
                   "BackupRetentionPeriod":6,"TagList":[{"Key":"PathProofCrownJewel","Value":"true"}]}]}})
        k = services.kms(p, "x")
        self.assertEqual(k[0]["facts"], {"enabled":False, "no_deletion":False})
        self.assertTrue(k[1]["facts"]["rotation"])
        db = services.rds(p, "x")[0]
        self.assertEqual((db["facts"]["private"], db["facts"]["backups"], db["facts"]["encrypted"]),
                         (False, False, None))
        self.assertTrue(db["labels"]["crown_jewel"])
