import os
import datetime

from jinja2 import Template

from ghascompliance import __HERE__
from ghascompliance.octokit.octokit import GitHub, Octokit
from ghascompliance.octokit.issues import GitHubIssues
from ghascompliance.reporting.models import IssuesConfig, Report


TEMPLATE_FOLDER = os.path.join(__HERE__, "defaults", "templates")


def formatContent(input: str, **kwargs):

    options = kwargs

    now = datetime.datetime.now()
    options["date"] = now.strftime("%Y-%m-%d")
    options["week"] = now.strftime("%V")

    #  Automatically remove certain items just incase
    template = Template(input)

    # return input.format(**options)
    return template.render(**options)


def createSummaryIssue(config: IssuesConfig = None, report: Report = None, **kargvs):

    template_path = os.path.join(TEMPLATE_FOLDER, config.template)
    #  TODO: Path traversal?
    if not os.path.exists(template_path):
        raise Exception(f"Template file does not exist: {template_path}")

    Octokit.debug(f"Issues Template used: {template_path}")
    with open(template_path, "r") as handle:
        template_content = handle.read()

    github = GitHub(config.repository, kargvs.get("token"))
    github_global = kargvs.get("github")
    github_issues = GitHubIssues(github)

    title = formatContent(
        config.title,
        status=":red_circle:",
        report=report,
        repository=github_global.repo,
        owner=github_global.owner,
        risk_rating="normal",
    )

    issues = github_issues.getAllIssues()

    present = None
    for issue in issues:
        if issue.get("title") == title:
            present = issue.get("number")

    content = formatContent(
        template_content,
        status=":red_circle:",
        report=report,
        repository=github_global.repo,
        owner=github_global.owner,
        repository_url=github_global.url,
        risk_rating="normal",
    )

    if present and report.total > 0:
        Octokit.info(f"Updating GitHub Issue ({present}) :: {title}")

        res = github_issues.updateIssue(
            present, title, content, assignees=config.assignees
        )
    elif report.total == 0 and config.close:
        pass

    else:
        Octokit.info(f"Creating new GitHub Issue :: {title}")

        res = github_issues.createIssue(title, content, assignees=config.assignees)
        Octokit.info(f"Created Issue: {res.get('number')}")
