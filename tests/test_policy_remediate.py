import os
import sys
import yaml
import uuid
import datetime
import unittest

import tempfile

sys.path.append(".")

from ghascompliance.policy import Policy


class TestPolicyLoading(unittest.TestCase):
    def setUp(self):
        self.policy = Policy("error")

        self.example = {
            "general": {"remediate": {"error": 1}},
            "codescanning": {"level": "error"},
        }

        return super().setUp()

    def testLoadingGeneral(self):

        self.policy.loadPolicy(self.example)

        self.assertIsNotNone(self.policy.remediate)
        self.assertEqual(self.policy.remediate, self.example["general"]["remediate"])

        self.assertEqual(
            self.policy.policy.get("codescanning", {}).get("remediate"),
            self.policy.remediate,
        )

    def testOverwritingPolicies(self):
        my_policy = {
            "general": {"remediate": {"error": 1}},
            "codescanning": {"level": "error"},
            "dependabot": {"level": "high", "remediate": {"high": 7}},
        }
        self.policy.loadPolicy(my_policy)

        self.assertEqual(
            self.policy.policy.get("dependabot", {}).get("remediate"),
            my_policy.get("dependabot", {}).get("remediate"),
        )

        self.assertEqual(
            self.policy.policy.get("dependabot", {}).get("remediate", {}).get("high"), 7
        )

    def testViolationRemediationYesterday(self):
        yesterday = datetime.datetime.now() - datetime.timedelta(days=2)

        self.policy.loadPolicy(self.example)

        result = self.policy.checkViolationRemediation(
            "error", self.example.get("codescanning", {}).get("remediate"), yesterday
        )
        self.assertTrue(result)

    def testViolationRemediationToday(self):
        today = datetime.datetime.now()

        self.policy.loadPolicy(self.example)

        result = self.policy.checkViolationRemediation(
            "error", self.example.get("codescanning", {}).get("remediate"), today
        )
        self.assertFalse(result)

    def testViolationRemediationTomorrow(self):
        tomorrow = datetime.datetime.now() + datetime.timedelta(days=1)

        self.policy.loadPolicy(self.example)

        result = self.policy.checkViolationRemediation(
            "error", self.example.get("codescanning", {}).get("remediate"), tomorrow
        )
        self.assertFalse(result)

    def testUnknownUnspecifiedSeverity(self):
        sevendaysago = datetime.datetime.now() + datetime.timedelta(days=7)

        self.policy.loadPolicy(self.example)

        result = self.policy.checkViolationRemediation(
            "critical",
            self.example.get("codescanning", {}).get("remediate"),
            sevendaysago,
        )
        self.assertFalse(result)

    def testUnknownUnspecifiedSeverity(self):
        sevendaysago = datetime.datetime.now() - datetime.timedelta(days=7)

        self.policy.loadPolicy(self.example)

        result = self.policy.checkViolationRemediation(
            "warning",
            self.example.get("codescanning", {}).get("remediate"),
            sevendaysago,
        )
        self.assertFalse(result)

    def testUnspecifiedSeverity(self):
        sevendaysago = datetime.datetime.now() - datetime.timedelta(days=7)

        self.policy.loadPolicy(self.example)

        result = self.policy.checkViolationRemediation(
            "critical",
            self.example.get("codescanning", {}).get("remediate"),
            sevendaysago,
        )
        self.assertTrue(result)
