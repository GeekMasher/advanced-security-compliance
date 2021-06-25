import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.policy import Policy


class TestPolicyLoading(unittest.TestCase):
    def setUp(self):
        self.policy_file = self.genTempFile()
        return super().setUp()

    def tearDown(self):
        # if os.path.exists(self.policy_file):
        #     os.remove(self.policy_file)
        return super().tearDown()

    def genTempFile(self, ext=".yml"):
        return os.path.join(tempfile.gettempdir(), str(uuid.uuid4()) + ext)

    def writePolicyToFile(self, policy):
        with open(self.policy_file, "w") as handle:
            yaml.safe_dump(policy, handle)

        return self.policy_file

    def testBasicLoading(self):
        self.writePolicyToFile({"general": {"level": "error"}})

        policy = Policy("error", path=self.policy_file)

        self.assertEqual(policy.policy.get("general", {}).get("level"), "error")

    def testUnwantedSection(self):
        self.writePolicyToFile({"codescanning": {"test": "error"}})

        with self.assertRaises(Exception) as context:
            policy = Policy("error", path=self.policy_file)

        self.assertTrue("Schema Validation Failed" in str(context.exception))

    def testUnwantedBlock(self):
        self.writePolicyToFile({"codescanning": {"conditions": {"tests": []}}})

        with self.assertRaises(Exception) as context:
            policy = Policy("error", path=self.policy_file)

        self.assertTrue("Schema Validation Failed" in str(context.exception))

    def testImport(self):
        path = self.genTempFile(ext=".txt")
        self.writePolicyToFile(
            {"codescanning": {"conditions": {"imports": {"ids": path}}}}
        )

        data = ["test", "each", "line"]
        with open(path, "w") as handle:
            handle.write("\n".join(data))

        policy = Policy("error", path=self.policy_file)

        self.assertIsNotNone(policy.policy["codescanning"]["conditions"]["ids"])

        self.assertEqual(policy.policy["codescanning"]["conditions"]["ids"], data)

    def testImportOfImports(self):
        self.writePolicyToFile(
            {"codescanning": {"conditions": {"imports": {"imports": "random"}}}}
        )

        with self.assertRaises(Exception) as context:
            policy = Policy("error", path=self.policy_file)

        self.assertTrue("Schema Validation Failed" in str(context.exception))

    def testImportPathTraversal(self):
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
            policy = Policy("error", path=self.policy_file)

        self.assertTrue("Path Traversal Detected" in str(context.exception))


class TestPolicyExamples(unittest.TestCase):
    def testBasic(self):
        path = "examples/policies/basic.yml"

        policy = Policy("error", path=path)

        self.assertEqual(policy.policy.get("codescanning", {}).get("level"), "error")
        self.assertEqual(policy.policy.get("dependabot", {}).get("level"), "high")
        self.assertEqual(policy.policy.get("secretscanning", {}).get("level"), "all")

    def testGeneral(self):
        path = "examples/policies/general.yml"

        policy = Policy("error", path=path)

        self.assertEqual(policy.policy.get("general", {}).get("level"), "error")

    def testConditions(self):
        path = "examples/policies/conditions.yml"

        policy = Policy("error", path=path)

        self.assertEqual(
            policy.policy["licensing"]["conditions"]["ids"], ["GPL-2.0", "GPL-3.0"]
        )
        self.assertEqual(
            policy.policy["licensing"]["conditions"]["names"],
            [
                "maven://org.apache.struts",
                "org.apache.struts",
                "maven://org.apache.struts#2.0.5",
            ],
        )

        self.assertEqual(policy.policy["licensing"]["warnings"]["ids"], ["Other", "NA"])

    def testAdvance(self):
        path = "examples/policies/advance.yml"

        policy = Policy("error", path=path)

        self.assertEqual(
            policy.policy["licensing"]["conditions"]["ids"], ["GPL-2.0", "GPL-3.0"]
        )
        self.assertEqual(
            policy.policy["licensing"]["warnings"]["names"],
            ["kibana"],
        )
