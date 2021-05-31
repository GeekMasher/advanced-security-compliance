from ghascompliant.octokit.octokit import OctoRequests


class CodeScanning(OctoRequests):
    @OctoRequests.request(
        "GET", "/repos/{owner}/{repo}/code-scanning/alerts", params={"state": "open"}
    )
    def getOpenAlerts(self, response: dict = {}):
        return response
