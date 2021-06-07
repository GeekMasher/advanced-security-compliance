import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.policy import Policy


class TestPolicyLoading(unittest.TestCase):
    def setUp(self):
        self.policy = Policy("error")
        return super().setUp()

    def testNotMatchContent(self):
        wildcards = ["example-*"]

        item = "test"

        result = self.policy.matchContent(item, wildcards)
        self.assertFalse(result)

    def testMatchBasicContent(self):
        wildcards = ["example", "test"]

        item = "test"

        result = self.policy.matchContent(item, wildcards)
        self.assertTrue(result)

    def testNotMatchWildcardContent(self):
        wildcards = ["example-*"]

        item = "example"

        result = self.policy.matchContent(item, wildcards)
        self.assertFalse(result)

    def testMatchWildcardContent(self):
        wildcards = ["example-*"]

        item = "example-test"

        result = self.policy.matchContent(item, wildcards)
        self.assertTrue(result)

    def testLoadingAndMatching(self):
        policy_path = "tests/samples/wildcards.yml"
        self.assertTrue(os.path.exists(policy_path))

        policy = Policy("error", path=policy_path)

        ids = policy.policy.get("licensing", {}).get("conditions", {}).get("ids")
        self.assertEqual(ids, ["*-Examples", "MyLicencing-*"])

        self.assertFalse(policy.checkLisencingViolation("MyLicencing"))
        self.assertTrue(policy.checkLisencingViolation("MyLicencing-1.0"))

        self.assertTrue(policy.checkLisencingViolation("Test-Examples"))
