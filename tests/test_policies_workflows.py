import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.policies.workflow import WorkflowsPolicy


class TestWorkflowsPolicy(unittest.TestCase):
    def test(self):
        config = {"codeql": {"required": True, "action": "github/codeql-action/init"}}

        policy = WorkflowsPolicy()
