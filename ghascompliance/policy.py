import os
import json
import yaml
import shutil
import fnmatch
import datetime
import tempfile
import subprocess
from typing import List
from urllib.parse import urlparse
from ghascompliance.consts import SEVERITIES, TECHNOLOGIES, LICENSES
from ghascompliance.octokit import Octokit

__ROOT__ = os.path.dirname(os.path.basename(__file__))
__SCHEMA_VALIDATION__ = "Schema Validation Failed :: {msg} - {value}"


class Policy:

    __BLOCK_ITEMS__ = ["ids", "names", "imports", "remediate"]
    __SECTION_ITEMS__ = ["level", "remediate", "conditions", "warnings", "ignores"]
    __IMPORT_ALLOWED_TYPES__ = ["txt"]

    def __init__(
        self,
        severity="error",
        repository=None,
        token=None,
        isGithubAppToken=False,
        path=None,
        branch=None,
        instance="https://github.com",
    ):
        self.risk_level = severity

        self.severities = self._buildSeverityList(severity)

        self.policy = {}
        self.remediate = None

        self.instance = instance
        self.token = token
        self.isGithubAppToken = isGithubAppToken
        self.branch = branch
        self.repository = repository
        self.repository_path = path

        self.temp_repo = None


        if repository and repository != "":
            self.loadFromRepo()
        elif path and path != "":
            self.loadLocalConfig(path)

    def loadFromRepo(self):
        instance = urlparse(self.instance).netloc
        if self.token:
            if not self.isGithubAppToken:
                repo = "https://" + self.token + "@" + instance + "/" + self.repository
            else:
                repo = "https://" + "x-access-token:" + self.token + "@" + instance + "/" + self.repository
        else:
            repo = "https://" + instance + "/" + self.repository

        self.temp_repo = os.path.join(tempfile.gettempdir(), "repo")

        if os.path.exists(self.temp_repo):
            Octokit.debug("Deleting existing temp path")
            shutil.rmtree(self.temp_repo)

        Octokit.info(f"Cloning policy repo - {self.repository}")

        cmd = ["git", "clone", "--depth=1"]

        if self.branch:
            cmd.extend(["-b", self.branch])

        cmd.extend([repo, self.temp_repo])

        Octokit.debug(f"Running command - {cmd}")

        with open(os.devnull, "w") as null:
            subprocess.run(
                cmd,
                stdout=null,
                stderr=null,
            )

        if not os.path.exists(self.temp_repo):
            raise Exception("Repository failed to clone")

        full_path = os.path.join(self.temp_repo, self.repository_path)

        self.loadLocalConfig(full_path)

    def loadLocalConfig(self, path: str):
        Octokit.info(f"Loading policy file - {path}")

        if not os.path.exists(path):
            raise Exception(f"Policy File does not exist - {path}")

        with open(path, "r") as handle:
            policy = yaml.safe_load(handle)

        self.loadPolicy(policy)

    def loadPolicy(self, policy: dict):

        if not policy.get("general"):
            policy["general"] = {}

        general = policy.get("general")

        # set 'general' to the current minimum
        if not general.get("level"):
            policy["general"]["level"] = self.risk_level.lower()

        if general.get("remediate"):
            self.remediate = general.get("remediate")
            policy["general"]["remediate"] = self.remediate

        for tech in TECHNOLOGIES:
            # Importing files
            policy[tech] = self.loadPolicySection(
                tech, policy.get(tech, policy["general"])
            )

        Octokit.info("Policy loaded successfully")

        self.policy = policy

    def loadPolicySection(self, name: str, data: dict):

        time_to_remediate_policy = False

        for section, section_data in data.items():
            # check if only certain sections are present
            if section not in Policy.__SECTION_ITEMS__:
                raise Exception(
                    __SCHEMA_VALIDATION__.format(
                        msg="Disallowed Section present", value=section
                    )
                )

            # Skip level
            if section == "level" and isinstance(section_data, str):
                continue

            # Time to Remediate
            if section == "remediate":
                Octokit.debug("Enabling Time to Remediate (section) :: " + name)
                time_to_remediate_policy = True
                continue

            # Validate blocks
            for block in list(section_data):
                if block not in Policy.__BLOCK_ITEMS__:
                    raise Exception(
                        __SCHEMA_VALIDATION__.format(
                            msg="Disallowed Block present", value=block
                        )
                    )

            # Importing
            if section_data.get("imports"):
                if section_data.get("imports", {}).get("imports"):
                    raise Exception(
                        __SCHEMA_VALIDATION__.format(
                            msg="Circular import", value="imports"
                        )
                    )

                for block in Policy.__BLOCK_ITEMS__:

                    Octokit.debug(f"Importing > {section} - {block}")

                    import_path = section_data.get("imports", {}).get(block)
                    if import_path and isinstance(import_path, str):
                        if section_data.get(block):
                            section_data[block].extend(
                                self.loadPolicyImport(import_path)
                            )
                        else:
                            section_data[block] = self.loadPolicyImport(import_path)

        if not time_to_remediate_policy and self.remediate:
            Octokit.info("Enabling Time to Remediate (global) :: " + name)
            data["remediate"] = self.remediate

        return data

    def loadPolicyImport(self, path: str):
        results = []
        traversal = False
        paths = [
            # Current Working Dir
            (os.getcwd(), path),
            # Temp Repo / Cloned Repo
            (str(self.temp_repo), path),
            # Action / CLI directory
            (__ROOT__, path),
        ]
        for root, path in paths:
            full_path = os.path.abspath(os.path.join(root, path))

            if os.path.exists(full_path) and os.path.isfile(full_path):
                if full_path.startswith(tempfile.gettempdir()):
                    Octokit.debug("Temp location used for import path")
                elif not full_path.startswith(root):
                    Octokit.error("Attempting to import file :: " + full_path)
                    raise Exception("Path Traversal Detected, halting import!")

                # TODO: MIME type checking?
                _, fileext = os.path.splitext(full_path)
                fileext = fileext.replace(".", "")

                if fileext not in Policy.__IMPORT_ALLOWED_TYPES__:
                    Octokit.warning(
                        "Trying to load a disallowed file type :: " + fileext
                    )
                    continue

                Octokit.info("Importing Path :: " + full_path)

                with open(full_path, "r") as handle:
                    for line in handle:
                        line = line.replace("\n", "").replace("\b", "")
                        if line == "" or line.startswith("#"):
                            continue
                        results.append(line)

                break
        return results

    def savePolicy(self, path: str):
        #  Always clear the file
        Octokit.info("Saving Policy...")
        if os.path.exists(path):
            os.remove(path)
        with open(path, "w") as handle:
            json.dump(self.policy, handle, indent=2)
        Octokit.info("Policy saved")

    def _buildSeverityList(self, severity: str):
        if not severity:
            raise Exception("`security` is set to None/Null")

        severity = severity.lower()
        severities = []

        if severity == "none":
            Octokit.debug("No Unacceptable Severities")
            return []
        elif severity == "all":
            Octokit.debug("Unacceptable Severities :: " + ",".join(SEVERITIES))
            return SEVERITIES
        elif severity in SEVERITIES:
            severities = SEVERITIES[: SEVERITIES.index(severity) + 1]
            Octokit.debug("Unacceptable Severities :: " + ",".join(severities))
        else:
            Octokit.warning(f"Unknown severity provided :: {severity}")
        return severities

    def matchContent(self, name: str, validators: List[str]):
        # case insensitive regex test if name is in validators
        for validator in validators:
            if re.search(validator, name, re.IGNORECASE):
                return True
        return False

    def checkViolationRemediation(
        self,
        severity: str,
        remediate: dict,
        creation_time: datetime.datetime,
    ):
        # Midnight "today"
        now = datetime.datetime.now().date()

        if creation_time and remediate.get(severity):
            alert_datetime = creation_time + datetime.timedelta(
                days=int(remediate.get(severity))
            )
            if now > alert_datetime.date():
                return True

        else:
            for remediate_severity, remediate_delta in remediate.items():
                remediate_severity_list = self._buildSeverityList(remediate_severity)

                if severity in remediate_severity_list:
                    alert_datetime = creation_time + datetime.timedelta(
                        days=int(remediate_delta)
                    )
                    if now > alert_datetime.date():
                        return True

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

        if self.policy.get(technology, {}).get("remediate"):
            Octokit.debug("Checking violation against remediate configuration")

            remediate_policy = self.policy.get(technology, {}).get("remediate")

            violation_remediation = self.checkViolationRemediation(
                severity, remediate_policy, creation_time
            )
            if self.policy.get(technology, {}).get("level"):
                return violation_remediation and self.checkViolationAgainstPolicy(
                    severity, technology, names=names, ids=ids
                )
            else:
                return violation_remediation

        elif self.policy:
            return self.checkViolationAgainstPolicy(
                severity, technology, names=names, ids=ids
            )
        else:
            if severity == "none":
                return False
            elif severity == "all":
                return True
            elif severity not in SEVERITIES:
                Octokit.warning(f"Unknown Severity used - {severity}")

            return severity in self.severities

    def checkViolationAgainstPolicy(
        self, severity: str, technology: str, names: List[str] = [], ids: List[str] = []
    ):
        severities = []
        level = "all"

        if technology:
            policy = self.policy.get(technology)
            if policy:
                for name in names:
                    check_name = str(name).lower()
                    condition_names = [
                        ign.lower()
                        for ign in policy.get("conditions", {}).get("names", [])
                    ]
                    ignores_names = [
                        ign.lower()
                        for ign in policy.get("ignores", {}).get("names", [])
                    ]
                    if self.matchContent(check_name, ignores_names):
                        return False
                    elif self.matchContent(check_name, condition_names):
                        return True

                for id in ids:
                    check_id = str(id).lower()
                    condition_ids = [
                        ign.lower()
                        for ign in policy.get("conditions", {}).get("ids", [])
                    ]
                    ignores_ids = [
                        ign.lower() for ign in policy.get("ignores", {}).get("ids", [])
                    ]
                    if self.matchContent(check_id, ignores_ids):
                        return False
                    elif self.matchContent(check_id, condition_ids):
                        return True

            if self.policy.get(technology, {}).get("level"):
                level = self.policy.get(technology, {}).get("level")
                severities = self._buildSeverityList(level)
        else:
            severities = self.severities

        if level == "all":
            severities = SEVERITIES
        elif level == "none":
            severities = []

        return severity in severities

    def checkLicensingViolation(self, license: str, dependency: dict = {}):
        license = license.lower()

        # Policy as Code
        if self.policy and self.policy.get("licensing"):
            return self.checkLicensingViolationAgainstPolicy(license, dependency)

        return license in [l.lower() for l in LICENSES]

    def checkLicensingViolationAgainstPolicy(self, license: str, dependency: dict = {}):
        policy = self.policy.get("licensing")
        license = license.lower()

        dependency_short_name = dependency.get("name", "NA")
        dependency_name = (
            dependency.get("manager", "NA") + "://" + dependency.get("name", "NA")
        )
        dependency_full = dependency.get("full_name", "NA://NA#NA")
        dependency_spdxId = dependency.get("spdxId", "NA")
        # log dependency spdxId
        Octokit.info(f"Dependency SPDX ID :: {dependency_spdxId}")


        # gather warning ids and names
        warning_ids = [wrn.lower() for wrn in policy.get("warnings", {}).get("ids", [])]
        warning_names = [
            wrn.lower() for wrn in policy.get("warnings", {}).get("names", [])
        ]

        #  if the license name is in the warnings list generate a warning
        if self.matchContent(license, warning_ids) or self.matchContent(
            dependency_full, warning_names
        ):
            Octokit.warning(
                f"Dependency License Warning :: {dependency_full} = {license}"
            )

        # gather ignore ids and names
        ignore_ids = [ign.lower() for ign in policy.get("ignores", {}).get("ids", [])]
        ignore_names = [
            ign.lower() for ign in policy.get("ignores", {}).get("names", [])
        ]

        # gather condition ids and names
        conditions_ids = [
            ign.lower() for ign in policy.get("conditions", {}).get("ids", [])
        ]
        Octokit.info(f"Conditions Ids :: {conditions_ids}")
        conditions_names = [
            ign.lower() for ign in policy.get("conditions", {}).get("names", [])
        ]
        Octokit.info(f"Conditions Names :: {conditions_names}")

        for value in [license, dependency_full, dependency_name, dependency_short_name, dependency_spdxId]:
            Octokit.info(f"Dependency Value line 449 :: {value}")

            # return false (ignore) if name or id is defined in the ignore portion of the policy
            if self.matchContent(value, ignore_ids) or self.matchContent(
                value, ignore_names
            ):
                Octokit.info(f"Dependency License Ignore :: {value}")
                return False
            # annotate error and return true if name or id is defined as a condition
            if self.matchContent(value, conditions_ids) or self.matchContent(
                value, conditions_names
            ):
                Octokit.error(
                    f"Dependency License Violation :: {dependency_full} == {license}"
                )
                return True

        return False
