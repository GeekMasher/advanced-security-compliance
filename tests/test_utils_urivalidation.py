import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.utils.octouri import validateUri


class TestPolicyLoading(unittest.TestCase):
    def testUriFile(self):
        path = "ghascompliance/defaults/policy.yml"
        uri = validateUri(path)

        self.assertIsNone(uri.repository)
        self.assertEqual(uri.path, path)
        self.assertIsNone(uri.branch)

    def testFullUriGitRepo(self):
        path = "GeekMasher/security-queries/policies/advance.yml@main"
        uri = validateUri(path)

        self.assertEqual(uri.repository, "GeekMasher/security-queries")
        self.assertEqual(uri.path, "policies/advance.yml")
        self.assertEqual(uri.branch, "main")

    def testUriGitRepo(self):
        repo = "GeekMasher/security-queries"
        uri = validateUri(repo)

        self.assertEqual(uri.repository, repo)
        self.assertIsNone(uri.path)
        self.assertIsNone(uri.branch)

    def testUriAbsolutePath(self):
        path = "/etc/password"

        with self.assertRaises(Exception) as context:
            uri = validateUri(path)

        self.assertTrue("Absolute paths are not allowed" in str(context.exception))

    def testRelativePathWithPathTraversal(self):
        # TODO: Better support needed
        path = "../../../../etc/password"
        with self.assertRaises(Exception) as context:
            uri = validateUri(path)

        self.assertTrue("Absolute paths are not allowed" in str(context.exception))

    def testUriGitRepoNoPath(self):
        path = "GeekMasher/security-queries@main"
        uri = validateUri(path)

        self.assertEqual(uri.repository, "GeekMasher/security-queries")
        self.assertIsNone(uri.path)
        self.assertEqual(uri.branch, "main")
