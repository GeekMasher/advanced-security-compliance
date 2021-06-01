import os
import yaml
import shutil
import tempfile
import subprocess
from urllib.parse import urlparse
from ghascompliance.consts import SEVERITIES, TECHNOLOGIES, LICENSES
from ghascompliance.octokit import Octokit


class Policy:
    def __init__(
        self,
        severity=None,
        repository=None,
        token=None,
        path=None,
        branch=None,
        instance="https://github.com",
    ):
        self.risk_level = severity

        self.severities = self._buildSeverityList(severity)

        self.policy = None

        self.instance = instance
        self.token = token
        self.branch = branch
        self.repository = repository
        self.repository_path = path

        if repository and repository != "":
            self.loadFromRepo()
        elif path and path != "":
            self.loadLocalConfig(path)

    def loadFromRepo(self):
        instance = urlparse(self.instance).netloc
        if self.token:
            repo = "https://" + self.token + "@" + instance + "/" + self.repository
        else:
            repo = "https://" + instance + "/" + self.repository

        temp_path = os.path.join(tempfile.gettempdir(), "repo")

        if os.path.exists(temp_path):
            Octokit.debug("Deleting existing temp path")
            shutil.rmtree(temp_path)

        Octokit.info(f"Cloning policy repo - {self.repository}")

        with open(os.devnull, "w") as null:
            subprocess.run(
                ["git", "clone", "--depth=1", repo, temp_path], stdout=null, stderr=null
            )

        if not os.path.exists(temp_path):
            raise Exception("Repository failed to clone")

        full_path = os.path.join(temp_path, self.repository_path)

        self.loadLocalConfig(full_path)

    def loadLocalConfig(self, path: str):
        Octokit.info(f"Loading policy file - {path}")

        if not os.path.exists(path):
            raise Exception(f"Policy File does not exist - {path}")

        with open(path, "r") as handle:
            policy = yaml.safe_load(handle)

        # set 'general' to the current minimum
        if not policy.get("general", {}).get("level"):
            policy["general"] = {}
            policy["general"]["level"] = self.risk_level.lower()

        for tech in TECHNOLOGIES:
            # if the tech doesn't exists, we'll use general
            if policy.get(tech):
                # enforce each tech has a level
                if not policy.get(tech).get("level"):
                    raise Exception("Policy Schema check failed")

        Octokit.info("Policy loaded successfully")

        self.policy = policy

    def _buildSeverityList(self, severity):
        severity = severity.lower()
        if severity == "none":
            Octokit.debug("No Unacceptable Severities")
            return []
        elif severity == "all":
            Octokit.debug("Unacceptable Severities :: " + ",".join(SEVERITIES))
            return SEVERITIES
        else:
            severities = SEVERITIES[: SEVERITIES.index(severity) + 1]
            Octokit.debug("Unacceptable Severities :: " + ",".join(severities))
        return severities

    def checkViolation(self, severity, technology=None):
        severity = severity.lower()

        if self.policy:
            return self.checkViolationAgainstPolicy(severity, technology)
        else:
            if severity not in SEVERITIES:
                Octokit.warning(f"Unknown Severity used - {severity}")

            return severity in self.severities

    def checkViolationAgainstPolicy(self, severity, technology):
        severities = []
        level = "all"

        if technology:
            if self.policy.get(technology):
                level = self.policy.get(technology, {}).get("level")
                severities = self._buildSeverityList(level)
            else:
                level = self.policy.get(technology, {}).get("level")
                severities = self._buildSeverityList(level)
        else:
            severities = self.severities

        if level == "all":
            severities = SEVERITIES
        elif level == "none":
            severities = []

        return severity in severities

    def checkLisencingViolation(self, license):
        license = license.lower()
        return license in [l.lower() for l in LICENSES]
