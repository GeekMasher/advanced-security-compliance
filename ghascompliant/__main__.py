from ghascompliant.octokit.octokit import OctoRequests
import os
import argparse
import logging

from yaml import serialize

from ghascompliant.__version__ import __name__ as tool_name, __banner__
from ghascompliant.consts import SEVERITIES
from ghascompliant.octokit import Octokit
from ghascompliant.octokit.codescanning import CodeScanning
from ghascompliant.octokit.secretscanning import SecretScanning


GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
# GITHUB_EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME")
# GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_REF = os.environ.get("GITHUB_REF")


parser = argparse.ArgumentParser(tool_name)

parser.add_argument("--debug", action="store_true", default=os.environ.get("DEBUG"))
parser.add_argument("--disable-code-scanning", action="store_true")
parser.add_argument("--disable-secret-scanning", action="store_true")

github_arguments = parser.add_argument_group("GitHub")
github_arguments.add_argument("--github-token", default=GITHUB_TOKEN)
github_arguments.add_argument("--github-repository", default=GITHUB_REPOSITORY)
# github_arguments.add_argument("--github-event", default=GITHUB_EVENT_PATH)
github_arguments.add_argument("--github-ref", default=GITHUB_REF)
# github_arguments.add_argument("--workflow-event", default=GITHUB_EVENT_NAME)

thresholds = parser.add_argument_group("Thresholds")
thresholds.add_argument(
    "--display",
    type=bool,
    default=False,
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
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Octokit.loadEvents(arguments.github_event)

    if not arguments.github_token:
        raise Exception("Github Access Token required")
    if not arguments.github_repository:
        raise Exception("Github Repository required")

    if arguments.list_severities:
        for severity in SEVERITIES:
            Octokit.info(" -> {}".format(severity))

        exit(0)

    # Total errors
    errors = 0

    if not arguments.disable_code_scanning:
        # Code Scanning results
        Octokit.createGroup("Code Scanning Results")
        code_scanning_errors = 0
        codescanning = CodeScanning(
            arguments.github_repository, token=arguments.github_token
        )

        severities = SEVERITIES[: SEVERITIES.index(arguments.severity.lower()) + 1]
        Octokit.debug("Unacceptable Severities :: " + ",".join(severities))

        alerts = codescanning.getOpenAlerts(params={"ref": arguments.github_ref})
        Octokit.info("Total Code Scanning Alerts :: " + str(len(alerts)))

        for alert in alerts:
            severity = alert.get("rule", {}).get("severity")

            if severity in severities:
                if not arguments.display:
                    Octokit.debug(
                        "Alert: {tool} - {name}".format(
                            tool=alert.get("tool", {}).get("name"),
                            name=alert.get("rule", {}).get("description"),
                        )
                    )
                else:
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

        OctoRequests.info("Code Scanning violations :: " + str(code_scanning_errors))
        errors += code_scanning_errors

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

            for alert in alerts:
                Octokit.info("Unresolved Secret - {secret_type}".format(**alert))

                errors += 1

        except Exception as err:
            Octokit.warning("Issue contacting Secret Scanning API (public repo?)")

        Octokit.endGroup()

    Octokit.createGroup("Final Checks")

    Octokit.info("Total unacceptable alerts :: " + str(errors))

    if arguments.action == "break" and errors > 0:
        Octokit.error("Unacceptable Threshold of Risk has been hit!")
        Octokit.endGroup()
        exit(1)
    elif arguments.action == "continue":
        Octokit.debug("Skipping threshold break check...")
    else:
        Octokit.error("Unknown action type :: " + str(arguments.action))

    Octokit.endGroup()
