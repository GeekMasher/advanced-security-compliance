import os
import json

from ghascompliance.policy import Policy
from ghascompliance.octokit import Octokit, GitHub
from ghascompliance.octokit.codescanning import CodeScanning
from ghascompliance.octokit.secretscanning import SecretScanning
from ghascompliance.octokit.dependabot import Dependabot


class Checks:
    def __init__(
        self,
        github: GitHub,
        policy: Policy,
        display: bool = False,
        debugging: bool = False,
        results_path: str = ".compliance",
    ):
        self.github = github
        self.policy = policy

        self.display = display
        self.debugging = debugging
        self.results = results_path

        os.makedirs(self.results, exist_ok=True)

    def writeResults(self, name, results, file_type="json"):
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
            rule_id = alert.get("rule", {}).get("id")

            if self.policy.checkViolation(
                severity, "codescanning", name=rule_name, id=rule_id
            ):
                if self.display:
                    location = alert.get("most_recent_instance", {}).get("location", {})
                    Octokit.error(
                        alert.get("tool", {}).get("name") + " - " + rule_name,
                        file=location.get("path"),
                        line=location.get("start_line"),
                        col=location.get("start_column"),
                    )

                code_scanning_errors += 1

        Octokit.info("Code Scanning violations :: " + str(code_scanning_errors))

        Octokit.endGroup()

        return code_scanning_errors

    def checkDependabot(self):
        Octokit.createGroup("Dependabot Results")

        dependabot_errors = 0

        dependabot = Dependabot(self.github)

        alerts = dependabot.getOpenAlerts()
        Octokit.info("Total Dependabot Alerts :: " + str(len(alerts)))

        self.writeResults("dependabot", alerts)

        for alert in alerts:
            package = alert.get("securityVulnerability", {}).get("package", {})

            if alert.get("dismissReason") is not None:
                Octokit.debug(
                    "Skipping Dependabot alert :: {}={} - {} ".format(
                        package.get("ecosystem", "N/A"),
                        package.get("name", "N/A"),
                        alert.get("dismissReason"),
                    )
                )
                continue

            severity = alert.get("securityAdvisory", {}).get("severity").lower()

            alert_id = alert.get("securityAdvisory", {}).get("ghsaId").lower()
            # Alert name support?

            if self.policy.checkViolation(severity, "dependabot", id=alert_id):
                if self.display:
                    Octokit.error(
                        "Dependabot Alert :: {}={}".format(
                            package.get("ecosystem", "N/A"),
                            package.get("name", "N/A"),
                        )
                    )

                dependabot_errors += 1

        Octokit.info("Dependabot violations :: " + str(dependabot_errors))

        Octokit.endGroup()

        return dependabot_errors

    def checkDependencyLicensing(self):
        Octokit.createGroup("Dependency Graph Results - Licensing")

        licensing_errors = 0

        dependabot = Dependabot(self.github)

        alerts = dependabot.getLicenseInfo()
        Octokit.info("Total Dependency Graph Dependencies :: " + str(len(alerts)))

        self.writeResults("licensing", alerts)

        for dependency in alerts:
            Octokit.debug(" > {name} ({manager}) - {license}".format(**dependency))

            if self.policy.checkLicensingViolation(
                dependency.get("license"), dependency
            ):
                if self.display:
                    Octokit.error(
                        "Dependency Graph Alert :: {name} ({manager}) = {license}".format(
                            **dependency
                        )
                    )

                licensing_errors += 1

        Octokit.info("Dependency Graph violations :: " + str(licensing_errors))

        Octokit.endGroup()

        return licensing_errors

    def checkSecretScanning(self):
        # Secret Scanning Results
        Octokit.createGroup("Secret Scanning Results")

        secrets_errors = 0

        secretscanning = SecretScanning(self.github)

        alerts = secretscanning.getOpenAlerts()
        Octokit.info("Total Secret Scanning Alerts :: " + str(len(alerts)))

        self.writeResults("secretscanning", alerts)

        for alert in alerts:
            if self.policy.checkViolation("critical", "secretscanning"):
                if self.display:
                    Octokit.info("Unresolved Secret - {secret_type}".format(**alert))

            secrets_errors += 1

        Octokit.info("Secret Scanning violations :: " + str(secrets_errors))

        Octokit.endGroup()

        return secrets_errors
