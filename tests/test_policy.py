import sys
import unittest

sys.path.append(".")

from ghascompliance.policy import Policy


class TestPolicies(unittest.TestCase):
    def setUp(self):
        self.policy = Policy("error")

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
                "name": "faker",
                "full_name": "npm://mygpl",
                "manager": "NPM",
                "license": "GPL-2.0",
            },
        }

        return super().setUp()

    def testLicenseByName(self):
        mygpl = self.samples.get("mygpl")

        self.assertTrue(self.policy.checkLicensingViolation(mygpl["license"], mygpl))

    def testLicenseByDepLicense(self):
        faker = self.samples.get("faker")

        self.policy.policy = {
            "licensing": {"conditions": {"ids": [faker.get("license")]}}
        }

        self.assertEqual(
            self.policy.policy.get("licensing", {}).get("conditions", {}).get("ids"),
            [faker.get("license")],
        )

        self.assertTrue(
            self.policy.checkLicensingViolationAgainstPolicy(faker["license"], faker)
        )

    def testLicenseByDependencyFullNames(self):
        faker = self.samples.get("faker")

        self.policy.policy = {
            "licensing": {"conditions": {"names": [faker.get("full_name")]}}
        }

        self.assertEqual(
            self.policy.policy.get("licensing", {}).get("conditions", {}).get("names"),
            [faker.get("full_name")],
        )

        #  Full name check
        self.assertTrue(
            self.policy.checkLicensingViolationAgainstPolicy(faker["license"], faker)
        )

    def testLicenseByDependencyShortNames(self):
        faker = self.samples.get("faker")

        self.policy.policy = {
            "licensing": {"conditions": {"names": [faker.get("name")]}}
        }

        self.assertEqual(
            self.policy.policy.get("licensing", {}).get("conditions", {}).get("names"),
            [faker.get("name")],
        )

        # Short name check
        self.assertTrue(
            self.policy.checkLicensingViolationAgainstPolicy(faker["license"], faker)
        )

    def testDependencyNamesDoNotMatch(self):
        self.policy.policy = {
            "dependencies": {
                "conditions": {"names": ["maven://org.apache.commons:commons-exec"]}
            }
        }

        #  Long and Short names
        names = ["maven://org.test.package", "org.test.package"]

        self.assertFalse(self.policy.checkViolation("all", "dependencies", names=names))

    def testDependencyFullNamesMatch(self):
        name = "maven://com.geekmasher.test#1.0.0"
        self.policy.policy = {"dependencies": {"conditions": {"names": [name]}}}

        names = ["maven://com.geekmasher.test", name]

        self.assertTrue(self.policy.checkViolation("all", "dependencies", names=names))

    def testDependencyNamesDoMatch(self):
        self.policy.policy = {
            "dependencies": {"conditions": {"names": ["maven://org.test.package"]}}
        }

        #  Long and Short names
        names = ["maven://org.test.package", "org.test.package"]

        self.assertTrue(self.policy.checkViolation("all", "dependencies", names=names))

    def testDependencyManager(self):
        self.policy.policy = {
            "dependencies": {"conditions": {"names": ["npm://faker"]}}
        }

        #  Long and Short names
        names = ["pip://faker", "faker"]

        self.assertFalse(self.policy.checkViolation("all", "dependencies", names=names))
