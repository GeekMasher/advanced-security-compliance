from requests.api import request
import requests

from ghascompliance.octokit.octokit import OctoRequests


class GitHubIssues(OctoRequests):
    @OctoRequests.request(
        "GET", "/repos/{owner}/{repo}/issues", params={"state": "all"}
    )
    def getAllIssues(self, response: dict = {}):
        return response

    def createIssue(self, title: str, body: str, assignees: list = [], **kwargs):
        url_path = "/repos/{owner}/{repo}/issues"
        full_url = self.github.get("api.rest") + self.format(url_path)

        data = {"title": title, "body": body, "assignees": assignees}

        response = requests.post(full_url, headers=self.headers, json=data)

        return response.json()

    def updateIssue(
        self, issue_id: int, title: str, body: str, assignees: list = [], **kwargs
    ):
        url_path = "/repos/{owner}/{repo}/issues/{issue_number}"
        full_url = self.github.get("api.rest") + self.format(
            url_path, issue_number=issue_id
        )

        data = {"title": title, "body": body, "assignees": assignees, "state": "open"}

        response = requests.patch(full_url, headers=self.headers, json=data)

        return response.json()
