import os
import json
import argparse
import logging

from ghascompliance.__version__ import __name__ as tool_name, __banner__, __url__
from ghascompliance.consts import SEVERITIES
from ghascompliance.octokit import Octokit, GitHub
from ghascompliance.policy import Policy
from ghascompliance.checks import *


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
parser.add_argument("--disable-caching", action="store_false")
parser.add_argument("--disable-code-scanning", action="store_true")
parser.add_argument("--disable-dependabot", action="store_true")
parser.add_argument("--disable-dependency-licensing", action="store_true")
parser.add_argument("--disable-dependencies", action="store_true")
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
github_arguments.add_argument(
    "--github-policy-path", default="ghascompliance/defaults/policy.yml"
)

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
    print(__banner__)
    arguments = parser.parse_args()

    logging.basicConfig(
        filename="ghas-compliant.log",
        level=logging.DEBUG if arguments.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if arguments.debug:
        Octokit.debug("Debugging enabled")

    if GITHUB_EVENT_NAME is not None:
        Octokit.__EVENT__ = True

    if not arguments.github_token:
        raise Exception("Github Access Token required")
    if not arguments.github_repository:
        raise Exception("Github Repository required")

    github = GitHub(
        repository=arguments.github_repository,
        instance=arguments.github_instance,
        token=arguments.github_token,
    )

    if arguments.list_severities:
        for severity in SEVERITIES:
            Octokit.info(" -> {}".format(severity))

        exit(0)

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
    elif arguments.github_policy_path:
        if not os.path.exists(arguments.github_policy_path):
            Octokit.debug("Policy config file not present on system, skipping...")
            arguments.github_policy_path = None
        else:
            Octokit.info(
                "Policy config file set: {}".format(arguments.github_policy_path)
            )

    results = ".compliance"

    # Load policy engine
    policy = Policy(
        severity=arguments.severity,
        repository=policy_location,
        path=arguments.github_policy_path,
        token=arguments.github_token,
        instance=arguments.github_instance,
    )

    policy.savePolicy(os.path.join(results, "policy.json"))

    Octokit.info("Finished loading policy")

    if arguments.display and policy.policy:
        Octokit.info("```")
        for plcy, data in policy.policy.items():
            if plcy == "name":
                Octokit.info(f"name: {data}")
            else:
                Octokit.info(
                    "{policy}: '{level}'".format(policy=plcy, level=data.get("level"))
                )

        Octokit.info("```")

    Octokit.endGroup()

    checks = Checks(
        github,
        policy,
        debugging=arguments.debug,
        display=arguments.display,
        results_path=results,
        caching=arguments.disable_caching,
    )

    errors = 0

    try:
        if not arguments.disable_code_scanning:
            errors += checks.checkCodeScanning()

        if not arguments.disable_dependabot:
            errors += checks.checkDependabot()

        # Dependency Graph
        if not arguments.disable_dependencies:
            errors += checks.checkDependencies()

        # Dependency Graph Licensing
        if not arguments.disable_dependency_licensing:
            errors += checks.checkDependencyLicensing()

        if not arguments.disable_secret_scanning:
            errors += checks.checkSecretScanning()

    except Exception as err:
        Octokit.error("Unknown Exception was hit, please repo this to " + __url__)
        Octokit.error(str(err))

        if arguments.debug:
            raise err

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
