import sys
import unittest

sys.path.append(".")

from ghascompliance.policies.models import *


class TestPoliciesModels(unittest.TestCase):
    def setUp(self):
        return super().setUp()

    def testPolicyModel(self):
        policy = PolicyModel(version="2.0", name="TestCase")

        self.assertEqual(policy.name, "TestCase")

        #  Make sure not policies are loaded by default unless general
        self.assertIsNotNone(policy.general)
        self.assertEqual(policy.general.level, "error")

    def testPolicyModelDefaults(self):
        policy = PolicyModel(
            version="2.0", name="TestCase", general=GeneralPolicyModel(level="warning")
        )

        self.assertEqual(policy.general.level, "warning")

        self.assertIsNotNone(policy.codescanning)
        self.assertEqual(policy.codescanning.level, policy.general.level)

        self.assertIsNotNone(policy.dependabot)
        self.assertEqual(policy.dependabot.level, policy.general.level)

        self.assertIsNotNone(policy.licensing)
        self.assertEqual(policy.licensing.level, policy.general.level)

        self.assertIsNotNone(policy.dependencies)
        self.assertEqual(policy.dependencies.level, policy.general.level)

        self.assertIsNotNone(policy.secretscanning)

    def testPolicyModelPolicies(self):
        policy = PolicyModel(version="2.0", name="TestCase")

        self.assertEqual(len(policy.policies), 5)

    def testGeneralPolicyModel(self):
        policy = GeneralPolicyModel(level="error")
        self.assertEqual(policy.level, "error")

    def testGeneralPolicyModelSeverities(self):
        policy = GeneralPolicyModel(level="error")
        # from errors
        severities = policy.getSeverityList()
        result = ["critical", "high", "error"]

        self.assertEqual(severities, result)

        # none
        severities = policy.getSeverityList("none")
        self.assertEqual(severities, [])

        # all
        severities = policy.getSeverityList("all")
        result = [
            "critical",
            "high",
            "error",
            "errors",
            "medium",
            "moderate",
            "low",
            "warning",
            "warnings",
            "note",
            "notes",
        ]
        self.assertEqual(
            severities,
            result,
        )

    def testGeneralPolicyModelLevels(self):

        with self.assertRaises(Exception) as context:
            policy = GeneralPolicyModel(level="random_string")

        self.assertTrue(
            "`level` variable is set to unknown value" in str(context.exception)
        )

    def testBlockPolicyModels(self):
        ids = ["GHSA-446m-mv8f-q348"]
        names = ["pip://requests"]

        policy = BlockPolicyModels(ids=ids, names=names)

        self.assertEqual(policy.ids, ids)
        self.assertEqual(policy.names, names)
