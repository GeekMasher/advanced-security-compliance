import json
import requests
from string import Template
from ghascompliance.octokit.octokit import OctoRequests, Octokit

GRAPHQL_GET_INFO = """\
{
    repository(owner: "$owner", name: "$repo") {
        vulnerabilityAlerts(first: 100) {
            nodes {
                createdAt
                dismissReason
                securityVulnerability {
                    package {
                        ecosystem
                        name
                    }
                }
                securityAdvisory{
                    ghsaId
                    severity
                }
            }
        }
    }
}
"""

# https://docs.github.com/en/graphql/reference/objects#repository
# https://docs.github.com/en/graphql/reference/objects#dependencygraphdependency
GRAPHQL_LICENSE_INFO = """\
{
    repository(owner: "$owner", name: "$repo") {
        name
        licenseInfo {
            name
        }
    }
}
"""


class Dependabot(OctoRequests):
    def __init__(self, repository, token):
        instance = "https://api.github.com/graphql"
        super().__init__(repository=repository, token=token, instance=instance)

    def getOpenAlerts(self, response: dict = {}):

        variables = {"owner": self.owner, "repo": self.repo}

        query = Template(GRAPHQL_GET_INFO).substitute(**variables)

        request = requests.post(
            "https://api.github.com/graphql",
            json={"query": query},
            headers=self.headers,
        )

        if request.status_code != 200:
            raise Exception(
                "Query failed to run by returning code of {}. {}".format(
                    request.status_code, query
                )
            )
        response = request.json()
        if response.get("errors"):
            Octokit.error(json.dumps(response))
            raise Exception("Query failed to run")
        data = (
            response.get("data", {})
            .get("repository", {})
            .get("vulnerabilityAlerts", {})
            .get("nodes", [])
        )
        return data

    def getLicenseInfo(self, response: dict = {}):
        variables = {"owner": self.owner, "repo": self.repo}

        query = Template(GRAPHQL_LICENSE_INFO).substitute(**variables)

        request = requests.post(
            "https://api.github.com/graphql",
            json={"query": query},
            headers=self.headers,
        )

        if request.status_code != 200:
            raise Exception(
                "Query failed to run by returning code of {}. {}".format(
                    request.status_code, query
                )
            )
        response = request.json()
        if response.get("errors"):
            Octokit.error(json.dumps(response, indent=2))
            raise Exception("Query failed to run")

        return response
