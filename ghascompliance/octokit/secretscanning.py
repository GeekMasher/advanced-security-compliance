from ghascompliance.octokit.octokit import OctoRequests


class SecretScanning(OctoRequests):
    @OctoRequests.request(
        "GET", "/repos/{owner}/{repo}/secret-scanning/alerts", params={"state": "open"}
    )
    def getOpenAlerts(self, response: dict = {}):
        return response
