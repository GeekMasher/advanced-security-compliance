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
        self.assertEqual(policy.version, "2.0")

        #  Make sure not policies are loaded by default unless general
        self.assertIsNone(policy.general)
        self.assertIsNotNone(policy.codescanning)
        self.assertIsNotNone(policy.dependabot)
        self.assertIsNotNone(policy.dependencies)
        self.assertIsNotNone(policy.licensing)
        self.assertIsNotNone(policy.secretscanning)

    def testPolicyModelGeneralDefaults(self):
        policy = PolicyModel(
            version="2.0", name="TestCase", general=GeneralPolicyModel(level="warning")
        )
        # TODO: might need to be changed
        self.assertEqual(policy.name, "TestCase")
        self.assertTrue(policy.general.enabled)
        self.assertEqual(policy.general.level, "warning")

        #  Make sure policy are loaded by default with general
        self.assertIsNotNone(policy.codescanning)
        self.assertTrue(policy.codescanning.enabled)
        # self.assertEqual(policy.codescanning.level, policy.general.level)

        self.assertIsNotNone(policy.dependabot)
        self.assertTrue(policy.dependabot.enabled)
        # self.assertEqual(policy.dependabot.level, policy.general.level)

        self.assertIsNotNone(policy.licensing)
        self.assertTrue(policy.licensing.enabled)
        # self.assertEqual(policy.licensing.level, policy.general.level)

        self.assertIsNotNone(policy.dependencies)
        self.assertTrue(policy.dependencies.enabled)
        # self.assertEqual(policy.dependencies.level, policy.general.level)

        self.assertIsNotNone(policy.secretscanning)
        self.assertTrue(policy.secretscanning.enabled)
        # self.assertEqual(policy.secretscanning.level, policy.general.level)

    def testPolicyModelPolicies(self):
        policy = PolicyModel(
            version="2.0", name="TestCase", general=GeneralPolicyModel(level="warning")
        )

        self.assertEqual(len(policy.getPolicies()), 5)
        # TODO: test if all policies are loaded

    def testPolicyModelCodeScanning(self):
        policy = PolicyModel(
            version="2.0",
            name="TestCase",
            codescanning=GeneralPolicyModel(level="warning"),
        )
        self.assertTrue(policy.codescanning.enabled)
        self.assertFalse(policy.dependabot.enabled)
        self.assertFalse(policy.dependencies.enabled)
        self.assertFalse(policy.licensing.enabled)
        self.assertFalse(policy.secretscanning.enabled)


class TestGeneralPolicyModel(unittest.TestCase):
    def setUp(self):
        return super().setUp()

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

    def testGentralPolicyModelLevels(self):

        with self.assertRaises(Exception) as context:
            policy = GeneralPolicyModel(level="random_string")

        self.assertTrue(
            "`level` variable is set to unknown value" in str(context.exception)
        )

    def testBlockPolicyModels(self):
        ids = ["GHSA-446m-mv8f-q348"]
        names = ["pip://requests"]

        policy = BlockPolicyModels(ids=ids, names=names)

        # When the policy is loaded, the ids and names are lowercased
        self.assertEqual(policy.ids, ["ghsa-446m-mv8f-q348"])
        self.assertEqual(policy.names, names)


class TestRemediateModel(unittest.TestCase):
    def testNegativeValues(self):
        with self.assertRaises(Exception) as context:
            _ = RemediateModel(high=-1, error=15)

        self.assertTrue("Invalid remediate value for" in str(context.exception))

        with self.assertRaises(Exception) as context:
            _ = RemediateModel(high=-13, error=15)

        self.assertTrue("Invalid remediate value for" in str(context.exception))

    def testGetRemediateTime(self):
        remediate = RemediateModel(high=1, error=15)

        self.assertTrue(remediate.enabled)

        self.assertEqual(remediate.high, 1)
        result = remediate.getRemediateTime("high")
        self.assertEqual(result, 1)

        self.assertEqual(remediate.error, 15)
        result = remediate.getRemediateTime("error")
        self.assertEqual(result, 15)

        # Non specified remediate levels
        self.assertIsNone(remediate.warning)
        result = remediate.getRemediateTime("critical")
        # Comes from error being set
        self.assertEqual(result, 1)

        self.assertIsNone(remediate.warning)
        result = remediate.getRemediateTime("warning")
        self.assertIsNone(result)
