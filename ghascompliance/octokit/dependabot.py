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
        dependencyGraphManifests {
        totalCount
        edges {
            node {
                filename
                dependencies{
                    edges {
                        node {
                            packageName
                            packageManager
                            requirements
                            repository {
                                licenseInfo {
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
        }
    }
}
"""


class Dependabot(OctoRequests):
    def __init__(self, repository, token):
        instance = "https://api.github.com/graphql"
        super().__init__(repository=repository, token=token, instance=instance)

        self.headers["Accept"] = "application/vnd.github.hawkgirl-preview+json"

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

        results = []

        repo = response.get("data", {}).get("repository", {})
        # repo_name = repo.get('name')
        # repo_license = repo.get('licenseInfo', {}).get('name')

        manifests = repo.get("dependencyGraphManifests", {}).get("edges", [])

        for manifest in manifests:
            manifest = manifest.get("node", {})
            manifest_path = manifest.get("filename")

            dependencies = manifest.get("dependencies", {}).get("edges", [])

            for dependency in dependencies:
                dependency = dependency.get("node", {})

                dependency_manager = dependency.get("packageManager", "NA")

                dependency_name = dependency.get("packageName", "NA")
                dependency_lisence = dependency.get("repository", {}).get("licenseInfo")
                if not dependency_lisence:
                    dependency_lisence_name = "NA"
                else:
                    dependency_lisence_name = dependency_lisence.get("name", "NA")

                Octokit.debug(f" > {dependency_name} == {dependency_lisence_name}")

                results.append(
                    {
                        "name": dependency_name,
                        "manager": dependency_manager,
                        "lisence": dependency_lisence_name,
                    }
                )

        return results
