import os
import sys
import shutil
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.policies.policy import Policy
from ghascompliance.utils.octouri import OctoUri


class TestPolicyLoadingRemote(unittest.TestCase):
    def setUp(self):
        self.policy: Policy = None

        return super().setUp()

    def tearDown(self):

        if self.policy and os.path.exists(self.policy.temp_repo):
            shutil.rmtree(self.policy.temp_repo)

        return super().tearDown()

    def testBranches(self):
        #  More of an integration test
        self.policy = Policy(
            severity="error",
            uri=OctoUri(
                repository="GeekMasher/advanced-security-compliance",
                path="examples/policies/test-policy.yml",
                branch="main",
            ),
            token=os.environ.get("GITHUB_TOKEN"),
        )

        self.assertEqual(
            self.policy.policy.get("licensing", {})
            .get("conditions", {})
            .get("ids", []),
            ["MIT"],
        )
