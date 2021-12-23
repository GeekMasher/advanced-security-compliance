import os
import json
import yaml
import fnmatch
import datetime
import tempfile
from dataclasses import asdict
from typing import List
from urllib.parse import urlparse
from ghascompliance.consts import TECHNOLOGIES, LICENSES
from ghascompliance.octokit import Octokit
from ghascompliance.utils.octouri import OctoUri, validateUri
from ghascompliance.utils.dataclasses import _dataclass_from_dict
from ghascompliance.utils.gitfeatures import clone
from ghascompliance.utils.config import Paths
from ghascompliance.policies.models import (
    PolicyModel,
    GeneralPolicyModel,
    RemediateModel,
    SeverityLevelEnum,
)

__ROOT__ = os.path.dirname(os.path.basename(__file__))
__SCHEMA_VALIDATION__ = "Schema Validation Failed :: {msg} - {value}"


class Policy:
    def __init__(
        self,
        severity: str = "none",
        uri: OctoUri = OctoUri(),
        token: str = None,
        instance: str = "https://github.com",
    ):
        self.risk_level = severity
        self.severities = SeverityLevelEnum.getSeveritiesFromName(severity)

        #  Setup default model
        self.policy: PolicyModel = PolicyModel()
        if severity:
            # By default the policy is set to none so that this feature is
            # disabled unless its alligned with the severity level
            self.policy.general = GeneralPolicyModel(level=severity)

        self.instance = instance
        self.token = token

        if not isinstance(uri, OctoUri):
            uri = validateUri(uri)
        self.uri = uri

        if self.uri.repository and self.uri.branch:
            self.loadFromRepo()
        elif self.uri.path and self.uri.path != "":
            self.loadLocalConfig(self.uri.path)

    def loadFromRepo(self):
        instance = urlparse(self.instance).netloc

        Paths.policy_repository = clone(
            self.uri,
            name="policy",
            instance=self.instance,
            token=self.token,
        )

        full_path = os.path.join(self.temp_repo, self.uri.path)

        self.loadLocalConfig(full_path)

    def loadLocalConfig(self, path: str):
        Octokit.info(f"Loading policy file - {path}")

        if not os.path.exists(path):
            raise Exception(f"Policy File does not exist - {path}")

        with open(path, "r") as handle:
            policy = yaml.safe_load(handle)

        self.policy = self.loadPolicy(policy)

    def loadPolicy(self, policy: dict):
        model: PolicyModel = _dataclass_from_dict(PolicyModel, policy)
        Octokit.info("Policy loaded successfully")
        return model

    def savePolicy(self, path: str):
        #  Always clear the file
        Octokit.info("Saving Policy...")
        if os.path.exists(path):
            os.remove(path)
        with open(path, "w") as handle:
            json.dump(asdict(self.policy), handle, indent=2)
        Octokit.info("Policy saved")

    def matchContent(self, name: str, validators: List[str]):
        # Wildcard matching
        for validator in validators:
            results = fnmatch.filter([name], validator)
            if results:
                return True
        return False

    def checkViolationRemediation(
        self,
        severity: str,
        remediate: RemediateModel,
        creation_time: datetime.datetime,
    ):
        # Midnight "today"
        now = datetime.datetime.now().date()

        remediate_time = remediate.getRemediateTime(severity)
        if creation_time and remediate_time is not None:
            alert_datetime = creation_time + datetime.timedelta(days=remediate_time)
            if now >= alert_datetime.date():
                return True
        else:
            Octokit.debug("Remediation time not found")
        return False

    def checkViolation(
        self,
        severity: str,
        technology: str,
        names: List[str] = [],
        ids: List[str] = [],
        creation_time: datetime.datetime = None,
    ):
        severity = severity.lower()

        if not technology or technology == "":
            raise Exception("Technology is set to None")

        policy = self.policy.getPolicy(technology)

        if policy.remediate:
            Octokit.debug("Checking violation against remediate configuration")

            violation_remediation = self.checkViolationRemediation(
                severity, policy.remediate, creation_time
            )
            if policy.level:
                return violation_remediation and self.checkViolationAgainstPolicy(
                    severity, policy, names=names, ids=ids
                )
            else:
                return violation_remediation

        elif self.policy:
            return self.checkViolationAgainstPolicy(
                severity, policy, names=names, ids=ids
            )
        else:
            if severity == "none":
                return False
            elif severity == "all":
                return True
            elif severity not in SeverityLevelEnum.getAllSeverities():
                Octokit.warning(f"Unknown Severity used - {severity}")

            return severity in self.severities

    def checkViolationAgainstPolicy(
        self,
        severity: str,
        policy: GeneralPolicyModel,
        names: List[str] = [],
        ids: List[str] = [],
    ) -> bool:
        severities = []

        if policy and policy.enabled:
            for name in names:
                check_name = str(name).lower()

                if self.matchContent(check_name, policy.ignores.names):
                    return False
                elif self.matchContent(check_name, policy.conditions.names):
                    return True

            for id in ids:
                check_id = str(id).lower()

                if self.matchContent(check_id, policy.ignores.ids):
                    return False
                elif self.matchContent(check_id, policy.conditions.ids):
                    return True

            # If no names or ids are provided, check the policy level
            if policy.level:
                severities = SeverityLevelEnum.getSeveritiesFromName(policy.level)
        else:
            severities = self.severities

        if severity == "all":
            severities = SeverityLevelEnum.getAllSeverities()
        elif severity == "none":
            severities = []

        return severity in severities

    def checkLicensingViolation(self, license: str, dependency: dict = {}):
        license = license.lower()

        # Policy as Code
        if self.policy and self.policy.licensing.enabled:
            return self.checkLicensingViolationAgainstPolicy(license, dependency)

        return license in [l.lower() for l in LICENSES]

    def checkLicensingViolationAgainstPolicy(self, license: str, dependency: dict = {}):
        license = license.lower()
        policy = self.policy.licensing

        # Get all the dependencies names
        dependency_short_name = dependency.get("name", "NA")
        dependency_name = (
            dependency.get("manager", "NA") + "://" + dependency.get("name", "NA")
        )
        dependency_full = dependency.get("full_name", "NA://NA#NA")

        #  If the license name is in the warnings list
        if self.matchContent(license, policy.warnings.ids):
            Octokit.warning(
                f"Dependency License Warning :: {dependency_full} = {license}"
            )
        elif self.matchContent(dependency_full, policy.warnings.names):
            Octokit.warning(
                f"Dependency License Warning :: {dependency_full} = {license}"
            )

        ingore_ids = policy.ignores.ids
        ingore_names = policy.ignores.names

        condition_ids = policy.conditions.ids
        conditions_names = policy.conditions.names

        for value in [license, dependency_full, dependency_name, dependency_short_name]:

            if self.matchContent(value, ingore_ids) or self.matchContent(
                value, ingore_names
            ):
                return False

            elif self.matchContent(value, condition_ids) or self.matchContent(
                value, conditions_names
            ):
                return True

        return False
