import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.policies.policy import Policy
from ghascompliance.utils.octouri import OctoUri


class TestPolicyLoading(unittest.TestCase):
    def testBasicLoading(self):
        policy = {"general": {"level": "error"}}

        engine = Policy("error")
        engine.policy = engine.loadPolicy(policy)

        self.assertEqual(engine.policy.general.level, "error")
        self.assertTrue(engine.policy.general.enabled)

    def testBasicLoading2(self):
        policy = {
            "codescanning": {"level": "warnings", "conditions": {"ids": ["example1"]}}
        }

        engine = Policy("error")
        engine.policy = engine.loadPolicy(policy)

        self.assertEqual(engine.policy.codescanning.level, "warnings")
        self.assertEqual(engine.policy.codescanning.conditions.ids, ["example1"])
        self.assertTrue(engine.policy.codescanning.enabled)

    def _testUnwantedSection(self):
        policy = {"codescanning": {"test": "error"}}

        with self.assertRaises(Exception) as context:
            engine = Policy("error")
            engine.loadPolicy(policy)

        self.assertTrue("Schema Validation Failed" in str(context.exception))

    def _testUnwantedBlock(self):
        self.writePolicyToFile({"codescanning": {"conditions": {"tests": []}}})

        with self.assertRaises(Exception) as context:
            policy = Policy("error", uri=OctoUri(path=self.policy_file))

        self.assertTrue("Schema Validation Failed" in str(context.exception))

    def testImport(self):
        path = "ghascompliance/defaults/projects.txt"
        policy = {"codescanning": {"conditions": {"imports": {"ids": path}}}}
        data = ["kibana"]

        engine = Policy("error")
        engine.policy = engine.loadPolicy(policy)

        self.assertIsNotNone(engine.policy.codescanning.conditions)
        self.assertIsNotNone(engine.policy.codescanning.conditions.imports)
        self.assertEqual(engine.policy.codescanning.conditions.imports.ids, path)

        # Dataclass with automatically load imports
        self.assertIsNotNone(engine.policy.codescanning.conditions.ids)

        self.assertEqual(engine.policy.codescanning.conditions.ids, data)

    def _testImportOfImports(self):
        self.writePolicyToFile(
            {"codescanning": {"conditions": {"imports": {"imports": "random"}}}}
        )

        with self.assertRaises(Exception) as context:
            policy = Policy("error", uri=OctoUri(path=self.policy_file))

        self.assertTrue("Schema Validation Failed" in str(context.exception))

    def _testImportPathTraversal(self):
        self.writePolicyToFile(
            {
                "codescanning": {
                    "conditions": {
                        "imports": {"ids": "../../../../../../../etc/passwd"}
                    }
                }
            }
        )

        with self.assertRaises(Exception) as context:
            policy = Policy("error", uri=OctoUri(path=self.policy_file))

        self.assertTrue("Path Traversal Detected" in str(context.exception))


class TestPolicyExamples(unittest.TestCase):
    def testBasic(self):
        path = "examples/policies/basic.yml"

        engine = Policy("error", uri=OctoUri(path=path))

        self.assertEqual(engine.policy.codescanning.level, "error")
        self.assertTrue(engine.policy.codescanning.enabled)

        self.assertEqual(engine.policy.dependabot.level, "high")
        self.assertTrue(engine.policy.dependabot.enabled)

        self.assertEqual(engine.policy.secretscanning.level, "all")
        self.assertTrue(engine.policy.secretscanning.enabled)

        # Because general is set
        self.assertEqual(engine.policy.licensing.level, "error")
        self.assertTrue(engine.policy.secretscanning.enabled)

    def testGeneral(self):
        path = "examples/policies/general.yml"

        engine = Policy("error", uri=OctoUri(path=path))

        self.assertEqual(engine.policy.general.level, "error")
        self.assertEqual(engine.policy.codescanning.level, "error")
        self.assertEqual(engine.policy.dependabot.level, "error")
        self.assertEqual(engine.policy.dependencies.level, "error")
        self.assertEqual(engine.policy.licensing.level, "error")
        self.assertEqual(engine.policy.secretscanning.level, "error")

    def testConditions(self):
        path = "examples/policies/conditions.yml"

        engine = Policy("error", uri=OctoUri(path=path))

        # Validate licensing
        # IDs are lowercase
        self.assertEqual(engine.policy.licensing.conditions.ids, ["gpl-2.0", "gpl-3.0"])
        self.assertEqual(
            engine.policy.licensing.conditions.names,
            [
                "maven://org.apache.struts",
                "org.apache.struts",
                "maven://org.apache.struts#2.0.5",
            ],
        )
        self.assertEqual(engine.policy.licensing.warnings.ids, ["other", "na"])

    def testAdvance(self):
        path = "examples/policies/advance.yml"

        engine = Policy("error", uri=OctoUri(path=path))

        self.assertIsNone(engine.policy.general)

        self.assertTrue(engine.policy.codescanning.enabled)
        self.assertEqual(
            engine.policy.codescanning.conditions.ids, ["java/sql-injection"]
        )
        self.assertTrue(engine.policy.dependabot.enabled)
        # Not enabled
        self.assertFalse(engine.policy.dependencies.enabled)
        self.assertTrue(engine.policy.licensing.enabled)
        self.assertTrue(engine.policy.secretscanning.enabled)

        # Using imports
        self.assertEqual(
            engine.policy.licensing.conditions.imports.ids,
            "ghascompliance/defaults/licenses.txt",
        )
        self.assertEqual(engine.policy.licensing.conditions.ids, ["gpl-2.0", "gpl-3.0"])
        self.assertEqual(
            engine.policy.licensing.warnings.names,
            ["kibana"],
        )
