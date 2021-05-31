import os
import argparse
import logging

from yaml import serialize

from ghascompliant.__version__ import __name__ as tool_name, __banner__
from ghascompliant.consts import SEVERITIES
from ghascompliant.octokit import Octokit, CodeScanning


GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
# GITHUB_EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME")
# GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_REF = os.environ.get("GITHUB_REF")


parser = argparse.ArgumentParser(tool_name)

parser.add_argument("--debug", action="store_true", default=os.environ.get("DEBUG"))

github_arguments = parser.add_argument_group("GitHub")
github_arguments.add_argument("--github-token", default=GITHUB_TOKEN)
github_arguments.add_argument("--github-repository", default=GITHUB_REPOSITORY)
# github_arguments.add_argument("--github-event", default=GITHUB_EVENT_PATH)
github_arguments.add_argument("--github-ref", default=GITHUB_REF)
# github_arguments.add_argument("--workflow-event", default=GITHUB_EVENT_NAME)

thresholds = parser.add_argument_group("Thresholds")
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

    codescanning = CodeScanning(
        arguments.github_repository, token=arguments.github_token
    )

    severities = SEVERITIES[: SEVERITIES.index(arguments.severity.lower()) + 1]
    Octokit.debug("Unacceptable Severities :: " + ",".join(severities))

    Octokit.createGroup("Analysing Results")

    alerts = codescanning.getOpenAlerts(params={"ref": arguments.github_ref})
    Octokit.info("Total alerts in repository :: " + str(len(alerts)))

    errors = 0

    for alert in alerts:
        severity = alert.get("rule", {}).get("severity")

        if severity in severities and severity == "error":
            location = alert.get("most_recent_instance", {}).get("location", {})
            Octokit.error(
                alert.get("rule", {}).get("description"),
                file=location.get("path"),
                line=location.get("start_line"),
                col=location.get("start_column"),
            )

            errors += 1
        elif severity in severities and severity == "warning":
            Octokit.warning(
                alert.get("rule", {}).get("description"),
                file=alert.get("most_recent_instance", {})
                .get("location", {})
                .get("path"),
            )

            errors += 1

    Octokit.endGroup()
    Octokit.info("Total unacceptable alerts :: " + str(errors))

    if arguments.action == "break" and errors > 0:
        raise Exception("Unacceptable Threshold of Risk has been hit!")
    elif arguments.action == "continue":
        Octokit.debug("Skipping threshold break check...")
    else:
        Octokit.error("Unknown action type :: " + str(arguments.action))
