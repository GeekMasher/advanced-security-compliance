from ghascompliance.octokit.octokit import OctoRequests


class CodeScanning(OctoRequests):
    @OctoRequests.request(
        "GET", "/repos/{owner}/{repo}/code-scanning/alerts", params={"state": "open"}
    )
    def getOpenAlerts(self, response: dict = {}):
        """Get all Open Code Scanning Alerts"""
        return response
