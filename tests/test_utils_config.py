import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.utils.octouri import validateUri
from ghascompliance.utils.config import *


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
