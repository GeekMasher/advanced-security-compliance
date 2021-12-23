import os
import sys
import yaml
import uuid
import unittest
import tempfile

sys.path.append(".")

from ghascompliance.utils.config import Config, ThreatModelConfig, PolicyConfig
from ghascompliance.utils.threatmodel import selectThreatModel, loadFile


class TestThreatModel(unittest.TestCase):
    def setUp(self):
        self.default_policy = PolicyConfig(path="ghascompliance/defaults/policy.yml")
        self.threat_model = ThreatModelConfig(
            source="TestCase",
            normal=self.default_policy,
        )
        self.config = Config(threat_models=self.threat_model)

    def testDefault(self):
        threat_model = selectThreatModel(self.config, "normal")
        self.assertEqual(threat_model, self.default_policy)

    def testHigh(self):
        high = PolicyConfig(path="ghascompliance/defaults/high.yml")
        self.config.threat_models.high = high

        model = selectThreatModel(self.config, "high")
        self.assertEqual(model.path, "ghascompliance/defaults/high.yml")

    def testLocalSource(self):
        path = "./.github/compliance.yml"
        config = ThreatModelConfig(source=path)

        level = loadFile(config.source)
        self.assertEqual(level, "low")

    def testLocalApplciations(self):
        path = "examples/config/applications.yml"

        level = loadFile(path, "GeekMasher/Pixi")
        self.assertEqual(level, "high")

        level = loadFile(path, "octodemo/demo-ghas-geekmasher-compliance")
        self.assertEqual(level, "low")

        level = loadFile(path, "bkimminich/juice-shop")
        self.assertEqual(level, "high")

        level = loadFile(path, "github/random_repo")
        self.assertEqual(level, "normal")
