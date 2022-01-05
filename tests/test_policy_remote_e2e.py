import os
import sys
import shutil
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.policy import Policy


class TestPolicyLoadingRemote(unittest.TestCase):
    def setUp(self):
        self.policy: Policy = None
        return super().setUp()

    def tearDown(self):

        if os.path.exists(self.policy.temp_repo):
            shutil.rmtree(self.policy.temp_repo)

        return super().tearDown()

    def _testBranches(self):
        #  More of an integration test
        self.policy = Policy(
            severity="error",
            repository="GeekMasher/advanced-security-compliance",
            token=os.environ.get("GITHUB_TOKEN"),
            path="examples/policies/test-policy.yml",
            branch="testing",
        )

        self.assertEqual(
            self.policy.policy.get("licensing", {})
            .get("conditions", {})
            .get("ids", []),
            ["MIT"],
        )
