import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.octokit.octokit import GitHub


class TestPolicyLoading(unittest.TestCase):
    def testGitHubInstance(self):
        instance = "https://github.com"
        github = GitHub("GeekMasher/advanced-security-compliance", instance=instance)

        self.assertEqual(github.get("instance"), instance)
        self.assertEqual(github.get("api.rest"), "https://api.github.com")
        self.assertEqual(github.get("api.graphql"), "https://api.github.com/graphql")

    def testGitHubServerInstance(self):
        instance = "https://ghes.example.com"
        github = GitHub("GeekMasher/advanced-security-compliance", instance=instance)

        self.assertEqual(github.get("instance"), instance)
        self.assertEqual(github.get("api.rest"), "https://ghes.example.com/api/v3")
        self.assertEqual(
            github.get("api.graphql"), "https://ghes.example.com/api/graphql"
        )
