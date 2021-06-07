import json
import requests
from string import Template
from ghascompliance.octokit.octokit import GitHub, OctoRequests, Octokit

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
    def __init__(self, github: GitHub):
        instance = "https://api.github.com/graphql"
        super().__init__(github=github)

        self.headers["Accept"] = "application/vnd.github.hawkgirl-preview+json"

    def getOpenAlerts(self, response: dict = {}):

        variables = {"owner": self.github.owner, "repo": self.github.repo}

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
        variables = {"owner": self.github.owner, "repo": self.github.repo}

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
                dependency_repo = dependency.get("repository")

                dependency_license = (
                    dependency_repo.get("licenseInfo") if dependency_repo else {}
                )

                dependency_license_name = (
                    dependency_license.get("name", "NA") if dependency_license else "NA"
                )

                Octokit.debug(f" > {dependency_name} == {dependency_license_name}")

                results.append(
                    {
                        "name": dependency_name,
                        "manager": dependency_manager,
                        "license": dependency_license_name,
                    }
                )

        return results
