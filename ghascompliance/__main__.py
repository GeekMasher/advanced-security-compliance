import os
import json
import argparse
import logging

from ghascompliance.__version__ import __name__ as tool_name, __banner__
from ghascompliance.consts import SEVERITIES
from ghascompliance.octokit import Octokit
from ghascompliance.policy import Policy
from ghascompliance.octokit.codescanning import CodeScanning
from ghascompliance.octokit.secretscanning import SecretScanning
from ghascompliance.octokit.dependabot import Dependabot


GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER")
GITHUB_EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME")
# GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_REF = os.environ.get("GITHUB_REF")


parser = argparse.ArgumentParser(tool_name)

parser.add_argument(
    "--debug", action="store_true", default=bool(os.environ.get("DEBUG"))
)
parser.add_argument("--disable-code-scanning", action="store_true")
parser.add_argument("--disable-dependabot", action="store_true")
parser.add_argument("--disable-secret-scanning", action="store_true")

github_arguments = parser.add_argument_group("GitHub")
github_arguments.add_argument("--github-token", default=GITHUB_TOKEN)
github_arguments.add_argument("--github-instance", default="https://github.com")
github_arguments.add_argument("--github-repository", default=GITHUB_REPOSITORY)
# github_arguments.add_argument("--github-event", default=GITHUB_EVENT_PATH)
github_arguments.add_argument("--github-ref", default=GITHUB_REF)
# github_arguments.add_argument("--workflow-event", default=GITHUB_EVENT_NAME)
github_arguments.add_argument("--github-policy")
github_arguments.add_argument("--github-policy-branch", default="main")
github_arguments.add_argument("--github-policy-path", default="policy.yml")

thresholds = parser.add_argument_group("Thresholds")
thresholds.add_argument(
    "--display",
    action="store_true",
    help="Display alerts that violate the threshold",
)
thresholds.add_argument("--action", default="break")
thresholds.add_argument("--severity", default="Error")
thresholds.add_argument("--list-severities", action="store_true")
thresholds.add_argument("--count", type=int, default=-1)


if __name__ == "__main__":
    # print(__banner__)
    arguments = parser.parse_args()

    logging.basicConfig(
        filename="ghas-compliant.log",
        level=logging.DEBUG if arguments.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if arguments.debug:
        Octokit.debug("Debugging enabled")

    # TODO: Should load the event.json
    if GITHUB_EVENT_NAME is not None:
        Octokit.__EVENT__ = True
        # Octokit.loadEvents(arguments.github_event)
        arguments.display = True

    if not arguments.github_token:
        raise Exception("Github Access Token required")
    if not arguments.github_repository:
        raise Exception("Github Repository required")

    if arguments.list_severities:
        for severity in SEVERITIES:
            Octokit.info(" -> {}".format(severity))

        exit(0)

    if arguments.debug:
        os.makedirs("results", exist_ok=True)

    policy_location = None

    Octokit.createGroup("Policy as Code")
    if arguments.github_policy and arguments.github_policy != "":
        # Process [org]/repo
        if "/" in arguments.github_policy:
            policy_location = arguments.github_policy
        else:
            if GITHUB_OWNER is None:
                raise Exception("GitHub Owner/Repo not provided")
            policy_location = GITHUB_OWNER + "/" + arguments.github_policy

        Octokit.info(
            "Loading Policy as Code from Repository - {}/{}/{}".format(
                arguments.github_instance, policy_location, arguments.github_policy_path
            )
        )

    # Load policy engine
    policy = Policy(
        severity=arguments.severity,
        repository=policy_location,
        path=arguments.github_policy_path,
        token=arguments.github_token,
        instance=arguments.github_instance,
    )

    if arguments.display:
        for plcy, data in policy.policy.items():
            Octokit.info(
                " > {policy} == '{level}'".format(policy=plcy, level=data.get("level"))
            )

    Octokit.endGroup()

    # Total errors
    errors = 0

    if not arguments.disable_code_scanning:
        # Code Scanning results
        Octokit.createGroup("Code Scanning Results")
        code_scanning_errors = 0

        codescanning = CodeScanning(
            arguments.github_repository, token=arguments.github_token
        )

        alerts = codescanning.getOpenAlerts(params={"ref": arguments.github_ref})
        Octokit.info("Total Code Scanning Alerts :: " + str(len(alerts)))

        if arguments.debug:
            with open("results/code-scanning.json", "w") as handle:
                json.dump(alerts, handle, indent=2)

        for alert in alerts:
            severity = alert.get("rule", {}).get("severity")

            if policy.checkViolation(severity, "codescanning"):
                if arguments.display:
                    location = alert.get("most_recent_instance", {}).get("location", {})
                    Octokit.error(
                        alert.get("tool", {}).get("name")
                        + " - "
                        + alert.get("rule", {}).get("description"),
                        file=location.get("path"),
                        line=location.get("start_line"),
                        col=location.get("start_column"),
                    )

                code_scanning_errors += 1

        Octokit.info("Code Scanning violations :: " + str(code_scanning_errors))
        errors += code_scanning_errors

        Octokit.endGroup()

    if not arguments.disable_dependabot:
        Octokit.createGroup("Dependabot Results")

        dependabot_errors = 0

        dependabot = Dependabot(
            arguments.github_repository, token=arguments.github_token
        )

        try:
            alerts = dependabot.getOpenAlerts()
            Octokit.info("Total Dependabot Alerts :: " + str(len(alerts)))

            if arguments.debug:
                with open("results/dependabot.json", "w") as handle:
                    json.dump(alerts, handle, indent=2)

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

                if policy.checkViolation(severity, "dependabot"):
                    if arguments.display:
                        Octokit.error(
                            "Dependabot Alert :: {}={}".format(
                                package.get("ecosystem", "N/A"),
                                package.get("name", "N/A"),
                            )
                        )

                    dependabot_errors += 1

        except Exception as err:
            Octokit.error("Issue contacting Dependabot API (PAT scope?)")

        Octokit.info("Dependabot violations :: " + str(dependabot_errors))
        errors += dependabot_errors

        Octokit.endGroup()

    if not arguments.disable_secret_scanning:
        # Secret Scanning Results
        Octokit.createGroup("Secret Scanning Results")

        secretscanning = SecretScanning(
            arguments.github_repository, token=arguments.github_token
        )

        try:
            alerts = secretscanning.getOpenAlerts()
            Octokit.info("Total Secret Scanning Alerts :: " + str(len(alerts)))

            if arguments.debug:
                with open("results/secretscanning.json", "w") as handle:
                    json.dump(alerts, handle, indent=2)

            for alert in alerts:
                if policy.checkViolation("critical", "secretscanning"):
                    if arguments.display:
                        Octokit.info(
                            "Unresolved Secret - {secret_type}".format(**alert)
                        )

                errors += 1

        except Exception as err:
            Octokit.error("Issue contacting Secret Scanning API (public repo?)")

        Octokit.endGroup()

    Octokit.info("Total unacceptable alerts :: " + str(errors))

    if arguments.action == "break" and errors > 0:
        Octokit.error("Unacceptable Threshold of Risk has been hit!")
        exit(1)
    elif arguments.action == "continue":
        Octokit.debug("Skipping threshold break check...")
    elif errors == 0:
        Octokit.info("Acceptable risk and no threshold reached.")
    else:
        Octokit.error("Unknown action type :: " + str(arguments.action))
