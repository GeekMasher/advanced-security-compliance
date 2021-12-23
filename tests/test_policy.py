import sys
import unittest

sys.path.append(".")

from ghascompliance.policies.policy import Policy
from ghascompliance.utils.octouri import OctoUri


class TestPoliciesViolations(unittest.TestCase):
    def testCodeScanningAlertBasic(self):
        policy = {
            "codescanning": {"level": "error"},
        }
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        result = engine.checkViolation(
            "high", "codescanning", names=[], ids=[], creation_time=None
        )
        self.assertTrue(result)

        result = engine.checkViolation(
            "low", "codescanning", names=[], ids=[], creation_time=None
        )
        self.assertFalse(result)

    def testCodeScanningAlertBasicNames(self):
        policy = {
            "codescanning": {"level": "error", "conditions": {"names": ["test"]}},
        }
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        result = engine.checkViolation(
            "low", "codescanning", names=["test"], ids=[], creation_time=None
        )
        self.assertTrue(result)

        result = engine.checkViolation(
            "low", "codescanning", names=["example"], ids=[], creation_time=None
        )
        self.assertFalse(result)

    def testCodeScanningAlertBasicNames(self):
        policy = {
            "codescanning": {
                "level": "error",
                "conditions": {"ids": ["codescanning/id/42"]},
            },
        }
        engine = Policy()
        engine.policy = engine.loadPolicy(policy)

        result = engine.checkViolation(
            "low",
            "codescanning",
            names=[],
            ids=["codescanning/id/42"],
            creation_time=None,
        )
        self.assertTrue(result)

        result = engine.checkViolation(
            "low",
            "codescanning",
            names=[],
            ids=["codescanning/id/64"],
            creation_time=None,
        )
        self.assertFalse(result)


class TestPolicies(unittest.TestCase):
    def setUp(self):
        self.engine = Policy()

        self.samples = {
            "lodash": {
                "name": "lodash",
                "full_name": "npm://lodash",
                "manager": "NPM",
                "license": "MIT License",
            },
            "faker": {
                "name": "faker",
                "full_name": "npm://faker",
                "manager": "NPM",
                "license": "MIT License",
            },
            "mygpl": {
                "name": "mygpl",
                "full_name": "npm://mygpl",
                "manager": "NPM",
                "license": "GPL-2.0",
            },
        }

        return super().setUp()

    def testLicenseByName(self):
        mygpl = self.samples.get("mygpl")

        self.assertTrue(self.engine.checkLicensingViolation(mygpl["license"], mygpl))

    def testLicenseByDepLicense(self):
        faker = self.samples.get("faker")
        # load policy
        example = {"licensing": {"conditions": {"ids": [faker.get("license")]}}}
        self.engine.policy = self.engine.loadPolicy(example)

        # lowercase
        self.assertEqual(self.engine.policy.licensing.conditions.ids, ["mit license"])
        self.assertTrue(
            self.engine.checkLicensingViolationAgainstPolicy(faker["license"], faker)
        )

    def testLicenseByDependencyFullNames(self):
        faker = self.samples.get("faker")
        # load policy
        example = {"licensing": {"conditions": {"names": [faker.get("full_name")]}}}
        self.engine.policy = self.engine.loadPolicy(example)

        self.assertEqual(
            self.engine.policy.licensing.conditions.names, [faker.get("full_name")]
        )

        #  Full name check
        self.assertTrue(
            self.engine.checkLicensingViolationAgainstPolicy(faker["license"], faker)
        )

    def testLicenseByDependencyShortNames(self):
        faker = self.samples.get("faker")
        # load policy
        example = {"licensing": {"conditions": {"names": [faker.get("name")]}}}
        self.engine.policy = self.engine.loadPolicy(example)

        self.assertEqual(
            self.engine.policy.licensing.conditions.names,
            [faker.get("name")],
        )

        # Short name check
        self.assertTrue(
            self.engine.checkLicensingViolationAgainstPolicy(faker["license"], faker)
        )

    def testDependencyNamesDoNotMatch(self):
        # load policy
        example = {
            "dependencies": {
                "conditions": {"names": ["maven://org.apache.commons:commons-exec"]}
            }
        }
        self.engine.policy = self.engine.loadPolicy(example)

        #  Long and Short names
        names = ["maven://org.test.package", "org.test.package"]

        self.assertFalse(self.engine.checkViolation("all", "dependencies", names=names))

    def testDependencyFullNamesMatch(self):
        name = "maven://com.geekmasher.test#1.0.0"
        # load policy
        example = {"dependencies": {"conditions": {"names": [name]}}}
        self.engine.policy = self.engine.loadPolicy(example)

        names = ["maven://com.geekmasher.test", name]

        self.assertTrue(self.engine.checkViolation("all", "dependencies", names=names))

    def testDependencyNamesDoMatch(self):
        # load policy
        example = {
            "dependencies": {"conditions": {"names": ["maven://org.test.package"]}}
        }
        self.engine.policy = self.engine.loadPolicy(example)

        #  Long and Short names
        names = ["maven://org.test.package", "org.test.package"]

        self.assertTrue(self.engine.checkViolation("all", "dependencies", names=names))

    def testDependencyManager(self):
        # load policy
        example = {"dependencies": {"conditions": {"names": ["npm://faker"]}}}
        self.engine.policy = self.engine.loadPolicy(example)

        #  Long and Short names
        names = ["pip://faker", "faker"]

        self.assertFalse(self.engine.checkViolation("all", "dependencies", names=names))
