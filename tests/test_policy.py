import sys
import unittest

sys.path.append(".")

from ghascompliance.policy import Policy


class TestPolicies(unittest.TestCase):
    def setUp(self):
        self.policy = Policy("error")

        self.samples = {
            "lodash": {"name": "lodash", "manager": "NPM", "license": "MIT License"},
            "faker": {"name": "faker", "manager": "NPM", "license": "MIT License"},
            "mygpl": {"name": "faker", "manager": "NPM", "license": "GPL-2.0"},
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

    def testLicenseByDepName(self):
        faker = self.samples.get("faker")

        self.policy.policy = {
            "licensing": {"conditions": {"names": [faker.get("name")]}}
        }

        self.assertEqual(
            self.policy.policy.get("licensing", {}).get("conditions", {}).get("names"),
            [faker.get("name")],
        )

        self.assertTrue(
            self.policy.checkLicensingViolationAgainstPolicy(faker["license"], faker)
        )
