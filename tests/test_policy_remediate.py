import sys
import datetime
import unittest

sys.path.append(".")

from ghascompliance.policies.policy import Policy
from ghascompliance.utils.octouri import OctoUri


class TestPolicyLoading(unittest.TestCase):
    def testLoadingGeneral(self):
        example = {
            "general": {"remediate": {"error": 1}},
            "codescanning": {"level": "error"},
        }
        engine = Policy()
        engine.policy = engine.loadPolicy(example)

        self.assertIsNotNone(engine.policy.general.remediate)
        self.assertEqual(engine.policy.general.level, "none")
        self.assertTrue(engine.policy.general.remediate.enabled)
        self.assertEqual(engine.policy.general.remediate.error, 1)
        # Inherits from general
        self.assertIsNotNone(engine.policy.codescanning.remediate)
        self.assertTrue(engine.policy.codescanning.remediate.enabled)
        self.assertEqual(engine.policy.codescanning.level, "error")
        self.assertEqual(engine.policy.codescanning.remediate.error, 1)
        # Inherits from general
        self.assertIsNotNone(engine.policy.secretscanning.remediate)
        self.assertTrue(engine.policy.secretscanning.remediate.enabled)
        self.assertEqual(engine.policy.secretscanning.remediate.error, 1)

    def testOverwritingPolicies(self):
        policy = {
            "general": {"remediate": {"error": 1}},
            "codescanning": {"level": "error"},
            "dependabot": {"level": "high", "remediate": {"high": 7}},
        }
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        self.assertTrue(engine.policy.codescanning.enabled)
        self.assertEqual(engine.policy.codescanning.level, "error")
        self.assertEqual(engine.policy.codescanning.remediate.error, 1)

        self.assertTrue(engine.policy.dependabot.enabled)
        self.assertEqual(engine.policy.dependabot.level, "high")
        self.assertIsNone(engine.policy.dependabot.remediate.error)
        self.assertEqual(engine.policy.dependabot.remediate.high, 7)

    def testViolationRemediationYesterday(self):
        yesterday = datetime.datetime.now() - datetime.timedelta(days=2)
        policy = {"codescanning": {"level": "error", "remediate": {"error": 1}}}
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        self.assertIsNotNone(engine.policy.codescanning.remediate)
        self.assertEqual(engine.policy.codescanning.remediate.error, 1)

        result = engine.checkViolationRemediation(
            "error", engine.policy.codescanning.remediate, yesterday
        )
        self.assertTrue(result)

    def testViolationRemediationToday(self):
        today = datetime.datetime.now()
        policy = {"codescanning": {"level": "error", "remediate": {"error": 1}}}
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        self.assertIsNotNone(engine.policy.codescanning.remediate)
        self.assertEqual(engine.policy.codescanning.remediate.error, 1)

        result = engine.checkViolationRemediation(
            "error", engine.policy.codescanning.remediate, today
        )
        self.assertFalse(result)

    def testViolationRemediationTodayZeroDays(self):
        today = datetime.datetime.now()
        policy = {"codescanning": {"level": "error", "remediate": {"error": 0}}}
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        self.assertIsNotNone(engine.policy.codescanning.remediate)
        self.assertEqual(engine.policy.codescanning.remediate.error, 0)

        result = engine.checkViolationRemediation(
            "error", engine.policy.codescanning.remediate, today
        )
        self.assertTrue(result)

    def testViolationRemediationTomorrow(self):
        tomorrow = datetime.datetime.now() + datetime.timedelta(days=1)
        policy = {"codescanning": {"level": "error", "remediate": {"error": 1}}}
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        result = engine.checkViolationRemediation(
            "error", engine.policy.codescanning.remediate, tomorrow
        )
        self.assertFalse(result)

    def testUnknownUnspecifiedHighSeverity(self):
        sevendaysago = datetime.datetime.now() - datetime.timedelta(days=7)
        policy = {"codescanning": {"level": "error", "remediate": {"error": 1}}}
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        result = engine.checkViolationRemediation(
            "critical",
            engine.policy.codescanning.remediate,
            sevendaysago,
        )
        # Because error is set, this should be true
        self.assertTrue(result)

    def testUnknownUnspecifiedLowSeverity(self):
        sevendaysago = datetime.datetime.now() - datetime.timedelta(days=7)
        policy = {"codescanning": {"level": "error", "remediate": {"error": 1}}}
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        result = engine.checkViolationRemediation(
            "warning",
            engine.policy.codescanning.remediate,
            sevendaysago,
        )
        self.assertFalse(result)
