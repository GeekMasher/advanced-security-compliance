import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.utils.octouri import validateUri
from ghascompliance.utils.config import *
from ghascompliance.utils.octouri import OctoUri


class TestConfigration(unittest.TestCase):
    def testLoadStandardPath(self):
        path = "policies/default.yml"
        config = PolicyConfig(path=path)

        uri = validateUri(path)

        self.assertEqual(config.path, uri.path)
        self.assertIsNone(config.repository)
        self.assertIsNone(config.branch)

    def testLoadOcotUriPath(self):
        path = "GeekMasher/security-queries/policies/default.yml@main"
        config = PolicyConfig(path=path)

        uri = validateUri(path)

        self.assertEqual(config.path, uri.path)
        self.assertEqual(config.repository, uri.repository)
        self.assertEqual(config.branch, uri.branch)


class TestReportingConfig(unittest.TestCase):
    def testGetAllReports(self):
        issue_template = IssuesConfig(
            repository="GeekMasher/advanced-security-compliance"
        )
        config = ReportingConfig(issues=issue_template)

        reports = config.getReports()

        issue = reports.get("issues")
        self.assertEqual(issue_template, issue)

        summary = reports.get("issues_summary")
        self.assertFalse(summary.enabled)

    def testGetEnabledReports(self):
        issue_template = IssuesConfig(
            repository="GeekMasher/advanced-security-compliance"
        )
        config = ReportingConfig(issues=issue_template)

        self.assertTrue(issue_template.enabled)

        reports = config.getReports(enabled=True)
        # Only Issue report should be enabled
        self.assertEqual(len(reports), 1)

        issue = reports.get("issues")
        self.assertEqual(issue_template, issue)
