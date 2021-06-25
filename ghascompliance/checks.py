import os
import json
from datetime import datetime
from typing import Callable, List

from ghascompliance.policy import Policy
from ghascompliance.octokit import Octokit, GitHub
from ghascompliance.octokit.codescanning import CodeScanning
from ghascompliance.octokit.secretscanning import SecretScanning
from ghascompliance.octokit.dependabot import Dependencies


class Checks:
    def __init__(
        self,
        github: GitHub,
        policy: Policy,
        display: bool = False,
        debugging: bool = False,
        results_path: str = ".compliance",
        caching: bool = True,
    ):
        self.github = github
        self.policy = policy

        self.display = display
        self.debugging = debugging
        self.results = results_path

        self.caching = caching

        os.makedirs(self.results, exist_ok=True)

    def getResults(self, name: str, callback: Callable, file_type: str = "json"):
        path = os.path.join(self.results, name + "." + file_type)

        if self.caching and os.path.exists(path):
            Octokit.info("Using Cached content :: " + name)
            with open(path, "r") as handle:
                return json.load(handle)
        else:
            results = callback()
            self.writeResults(name, results, file_type=file_type)
            return results

    def writeResults(self, name: str, results: str, file_type: str = "json"):
        path = os.path.join(self.results, name + "." + file_type)
        if not self.debugging:
            Octokit.debug("Skipping writing results to disk")
        elif file_type == "json":
            Octokit.info("Writing results to disk :: " + path)
            with open(path, "w") as handle:
                json.dump(results, handle, indent=2)
        else:
            Octokit.warning("Unsupported write type :: " + file_type)

    def checkCodeScanning(self):
        # Code Scanning results
        Octokit.createGroup("Code Scanning Results")
        code_scanning_errors = 0

        codescanning = CodeScanning(self.github)

        alerts = codescanning.getOpenAlerts(params={"ref": self.github.ref})
        Octokit.info("Total Code Scanning Alerts :: " + str(len(alerts)))

        self.writeResults("code-scanning", alerts)

        for alert in alerts:
            severity = alert.get("rule", {}).get("severity")
            rule_name = alert.get("rule", {}).get("description")

            ids = []
            # Rule ID
            ids.append(alert.get("rule", {}).get("id"))
            # TODO: CWE?

            names = []
            #  Rule Name
            names.append(rule_name)

            alert_creation_time = datetime.strptime(
                alert.get("created_at"), "%Y-%m-%dT%XZ"
            )

            if self.policy.checkViolation(
                severity,
                technology="codescanning",
                names=names,
                ids=ids,
                creation_time=alert_creation_time,
            ):
                if self.display:
                    error_format = "{tool_name} - {creation_time} - {rule_name}"

                    location = alert.get("most_recent_instance", {}).get("location", {})

                    Octokit.error(
                        error_format.format(
                            tool_name=alert.get("tool", {}).get("name"),
                            rule_name=rule_name,
                            creation_time=alert_creation_time,
                        ),
                        file=location.get("path"),
                        line=location.get("start_line"),
                        col=location.get("start_column"),
                    )

                code_scanning_errors += 1

        alerts_message = "Code Scanning violations :: {count}"
        Octokit.info(alerts_message.format(count=code_scanning_errors))

        Octokit.endGroup()

        return code_scanning_errors

    def checkDependabot(self):
        Octokit.createGroup("Dependabot Results")

        dependabot_errors = 0

        dependabot = Dependencies(self.github)

        # Get all Dependencies data
        alerts = self.getResults("dependabot", dependabot.getOpenAlerts)
        dependencies = self.getResults("dependencies", dependabot.getDependencies)

        Octokit.info("Total Dependabot Alerts :: " + str(len(alerts)))

        for alert in alerts:
            package = alert.get("securityVulnerability", {}).get("package", {})

            full_name = Dependencies.createDependencyName(
                package.get("ecosystem", "N/A"), package.get("name", "N/A")
            )

            if alert.get("dismissReason") is not None:
                Octokit.debug(
                    "Skipping Dependabot alert :: {} - {} ".format(
                        full_name,
                        alert.get("dismissReason"),
                    )
                )
                continue

            # Find the dependency from the graph
            dependency: dict = None
            for dep in dependencies:
                if dep.get("full_name").startswith(full_name):
                    dependency = dep
                    break

            advisory = alert.get("securityAdvisory", {})
            severity = advisory.get("severity").lower()

            alert_creation_time = datetime.strptime(
                alert.get("createdAt"), "%Y-%m-%dT%XZ"
            )

            ids = []
            #  GitHub Advisory
            ids.append(advisory.get("ghsaId").lower())
            #  CWE support
            cwes = []
            for cwe in advisory.get("cwes", {}).get("edges", []):
                cwes.append(cwe.get("node", {}).get("cweId"))
            ids.extend(cwes)

            names = []
            #  maven://org.apache.commons
            names.append(full_name)
            if dependency:
                full_name = dependency.get("full_name")
                #  maven://org.apache.commons#1.0
                names.append(dependency.get("full_name"))
            else:
                Octokit.debug(
                    "Dependency Graph to Dependabot alert match failed :: " + full_name
                )

            if self.policy.checkViolation(
                severity,
                "dependabot",
                names=names,
                ids=ids,
                creation_time=alert_creation_time,
            ):
                if self.display:
                    Octokit.error("Dependabot Alert :: {}".format(full_name))

                dependabot_errors += 1

        Octokit.info("Dependabot violations :: " + str(dependabot_errors))

        Octokit.endGroup()

        return dependabot_errors

    def checkDependencyLicensing(self):
        Octokit.createGroup(
            "Dependency Graph Results - Licensing",
            warning_prepfix="Dependency Graph Alert",
        )

        licensing_errors = 0

        dependabot = Dependencies(self.github)

        alerts = self.getResults("dependencies", dependabot.getDependencies)
        Octokit.info("Total Dependency Graph Dependencies :: " + str(len(alerts)))

        for dependency in alerts:
            Octokit.debug(" > {full_name} - {license}".format(**dependency))

            if self.policy.checkLicensingViolation(
                dependency.get("license"), dependency
            ):
                if self.display:
                    Octokit.error(
                        "Dependency Graph Alert :: {full_name} = {license}".format(
                            **dependency
                        )
                    )

                licensing_errors += 1

        Octokit.info("Dependency Graph violations :: " + str(licensing_errors))

        Octokit.endGroup()

        return licensing_errors

    def checkDependencies(self):
        Octokit.createGroup(
            "Dependency Graph",
            warning_prepfix="Dependency Graph Alert",
        )

        dependency_errors = 0

        dependabot = Dependencies(self.github)
        dependencies = self.getResults("dependencies", dependabot.getDependencies)

        Octokit.info("Total Dependency Graph :: " + str(len(dependencies)))

        policy = self.policy.policy.get("dependencies", {}).get("warnings", {})

        for dependency in dependencies:

            ids = []

            names = []
            # manager + name
            names.append(
                Dependencies.createDependencyName(
                    dependency.get("manager"), dependency.get("name")
                )
            )
            # manager + name + version
            names.append(dependency.get("full_name"))

            #  none is set to just check if the name or pattern is discovered
            if self.policy.checkViolation("none", "dependencies", names=names, ids=ids):
                if self.display:
                    Octokit.error(
                        "Dependency Graph Alert :: {}".format(
                            dependency.get("full_name")
                        )
                    )
                dependency_errors += 1

            #
            if "Maintenance" in policy.get("ids", []):
                for main in dependency.get("maintenance", []):
                    Octokit.warning(
                        "{main:<18} - {full_name}".format(
                            **dependency, main=main.title()
                        )
                    )
                    dependency_errors += 1

            if "Organization" in policy.get("ids", []) and not dependency.get(
                "organization"
            ):
                Octokit.warning(
                    "Dependency Graph Maintenance Alert :: {error:<18} - {full_name}".format(
                        **dependency, error="Non-Org Repo"
                    )
                )
                dependency_errors += 1

        Octokit.info("Dependency Graph violations :: " + str(dependency_errors))

        Octokit.endGroup()

        return dependency_errors

    def checkSecretScanning(self):
        # Secret Scanning Results
        Octokit.createGroup("Secret Scanning Results")

        secrets_errors = 0

        secretscanning = SecretScanning(self.github)

        alerts = secretscanning.getOpenAlerts()
        Octokit.info("Total Secret Scanning Alerts :: " + str(len(alerts)))

        self.writeResults("secretscanning", alerts)

        for alert in alerts:

            alert_creation_time = datetime.strptime(
                alert.get("created_at"), "%Y-%m-%dT%XZ"
            )

            ids = []
            ids.append(alert.get("secret_type"))

            if self.policy.checkViolation(
                "critical", "secretscanning", ids=ids, creation_time=alert_creation_time
            ):
                if self.display:
                    Octokit.info("Unresolved Secret - {secret_type}".format(**alert))

            secrets_errors += 1

        Octokit.info("Secret Scanning violations :: " + str(secrets_errors))

        Octokit.endGroup()

        return secrets_errors

    def isRemediationPolicy(self, technology: str = "general") -> bool:
        return self.policy.policy.get(technology, {}).get("remediate") is not None
