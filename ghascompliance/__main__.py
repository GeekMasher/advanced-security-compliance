import os
import json
import argparse
import logging

from ghascompliance.__version__ import __name__ as tool_name, __banner__, __url__
from ghascompliance.consts import SEVERITIES
from ghascompliance.octokit import Octokit, GitHub
from ghascompliance.policy import Policy
from ghascompliance.checks import *
from ghascompliance.reporting import __REPORTERS__
from ghascompliance.reporting.models import Report, SecurityReport
from ghascompliance.utils import Config, validateUri, clone
from ghascompliance.utils.threatmodel import selectThreatModel, loadFile

# https://docs.github.com/en/actions/reference/environment-variables#default-environment-variables
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER")
GITHUB_EVENT_NAME = os.environ.get("GITHUB_EVENT_NAME")
# GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH")
GITHUB_REF = os.environ.get("GITHUB_REF")
GITHUB_INSTANCE = os.environ.get("GITHUB_SERVER_URL", "https://github.com")

HERE = os.path.dirname(os.path.realpath(__file__))

POLICY_PATH = os.path.join(HERE, "defaults", "policy.yml")

parser = argparse.ArgumentParser(tool_name)

parser.add_argument(
    "--debug", action="store_true", default=bool(os.environ.get("DEBUG"))
)
parser.add_argument("--config", type=str)

parser.add_argument("--disable-caching", action="store_false")
parser.add_argument("--disable-code-scanning", action="store_true")
parser.add_argument("--disable-dependabot", action="store_true")
parser.add_argument("--disable-dependency-licensing", action="store_true")
parser.add_argument("--disable-dependencies", action="store_true")
parser.add_argument("--disable-secret-scanning", action="store_true")

github_arguments = parser.add_argument_group("GitHub")
github_arguments.add_argument("--github-token", default=GITHUB_TOKEN)
github_arguments.add_argument("--github-instance", default=GITHUB_INSTANCE)
github_arguments.add_argument("--github-repository", default=GITHUB_REPOSITORY)
# github_arguments.add_argument("--github-event", default=GITHUB_EVENT_PATH)
github_arguments.add_argument("--github-ref", default=GITHUB_REF)
# github_arguments.add_argument("--workflow-event", default=GITHUB_EVENT_NAME)
github_arguments.add_argument("--github-policy")
github_arguments.add_argument("--github-policy-branch", default="main")
github_arguments.add_argument(
    "--github-policy-path",
    default=POLICY_PATH,
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

    Octokit.createGroup("Initialise")

    if arguments.config:
        config_uri = validateUri(arguments.config)

        if config_uri.repository and config_uri.branch:
            Octokit.info("Loading config from repository...")
            config_path = clone(
                config_uri.repository, config_uri.branch, token=arguments.github_token
            )
            config_path = os.path.join(config_path, config_uri.path)
            Octokit.info(f"Loaded configuration file: {config_path}")

            config = Config.load(config_path)

        else:
            Octokit.info("Loading config from file path")

            if not os.path.exists(arguments.config):
                raise Exception("Configuration set but not found")

            config = Config.load(arguments.config)

        if config.threat_models:
            Octokit.info("Threat modeling enabled...")

            source = validateUri(config.threat_models.source)

            if source.repository:
                Octokit.info(f"Loading Threat Model file from Repository: {source}")

                threat_model_path = clone(
                    source.repository,
                    source.branch,
                    token=arguments.github_token,
                )
                threat_model_path = os.path.join(threat_model_path, source.path)
                thread_model_level = loadFile(
                    threat_model_path, arguments.github_repository
                )

            else:
                thread_model_level = loadFile(source.path, arguments.github_repository)

            config.policy = selectThreatModel(config, thread_model_level)
            Octokit.debug(f"Selected Threat Model: {config.policy}")

        Octokit.info(f"Loaded configuration file: {arguments.config}")

    else:
        Octokit.debug(f"Using default configuration settings")
        config = Config()

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
        instance=arguments.github_instance or config.github.instance,
        token=arguments.github_token,
    )

    Octokit.info(f"GitHub Repository :: {github.repo}")
    Octokit.info(f"GitHub Instance :: {github.instance}")

    if arguments.list_severities:
        for severity in SEVERITIES:
            Octokit.info(" -> {}".format(severity))

        exit(0)

    policy_location = None

    Octokit.endGroup()
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

    elif config.policy.repository and arguments.github_policy_path == POLICY_PATH:
        policy_location = config.policy.repository
        arguments.github_policy_path = config.policy.path

        Octokit.info(
            "Loading Policy as Code from Configuration - {}/{}".format(
                config.policy.repository, config.policy.path
            )
        )

    elif arguments.github_policy_path:
        if not os.path.exists(arguments.github_policy_path):
            Octokit.info("Policy config file not present on system, skipping...")
            Octokit.info("File path skipped :: " + str(arguments.github_policy_path))
            arguments.github_policy_path = None
        else:
            Octokit.info(
                "Policy config file set: {}".format(arguments.github_policy_path)
            )

    results = ".compliance"

    # Load policy engine
    policy = Policy(
        severity=arguments.severity or config.policy.severity,
        repository=policy_location,
        path=arguments.github_policy_path,
        token=arguments.github_token,
        instance=arguments.github_instance or config.policy.instance,
    )

    os.makedirs(results, exist_ok=True)
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
        display=arguments.display or config.policy.display,
        results_path=results,
        caching=arguments.disable_caching,
    )

    security_report = Report()

    errors = 0

    try:
        if not arguments.disable_code_scanning and config.checkers.codescanning:
            security_report.codescanning = checks.checkCodeScanning()

        if not arguments.disable_dependabot and config.checkers.dependabot:
            security_report.dependabot = checks.checkDependabot()

        # Dependency Graph
        if not arguments.disable_dependencies and config.checkers.dependencies:
            security_report.dependencies = checks.checkDependencies()

        # Dependency Graph Licensing
        if not arguments.disable_dependency_licensing and config.checkers.licensing:
            security_report.licensing = checks.checkDependencyLicensing()

        if not arguments.disable_secret_scanning and config.checkers.secretscanning:
            security_report.secretscanning = checks.checkSecretScanning()

    except Exception as err:
        Octokit.error("Unknown Exception was hit, please repo this to " + __url__)
        Octokit.error(str(err))

        if arguments.debug:
            raise err

    reporters = config.reporting.getReports(enabled=True)
    if len(reporters) >= 1:
        Octokit.createGroup("Reporting")
        for report_name, report_config in reporters.items():
            Octokit.info(f"Reporting: {report_name}")

            reporter = __REPORTERS__.get(report_name)

            if callable(reporter):
                result = reporter(
                    config=report_config,
                    report=security_report,
                    github=github,
                    global_config=config,
                    token=arguments.github_token,
                )

        Octokit.endGroup()

    Octokit.info("Total unacceptable alerts :: " + str(security_report.total))

    if arguments.action == "break" and security_report.total > 0:
        Octokit.error("Unacceptable Threshold of Risk has been hit!")
        exit(1)
    elif arguments.action == "continue":
        Octokit.debug("Skipping threshold break check...")
    elif security_report.total == 0:
        Octokit.info("Acceptable risk and no threshold reached.")
    else:
        Octokit.error("Unknown action type :: " + str(arguments.action))
