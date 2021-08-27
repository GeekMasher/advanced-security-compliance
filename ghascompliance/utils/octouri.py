from os import getcwd
from pathlib import Path
from dataclasses import dataclass


@dataclass
class OctoUri:
    # owner/repo
    repository: str = None
    path: str = None
    branch: str = None

    def __str__(self) -> str:
        if self.repository and self.path and self.branch:
            return f"{self.repository}/{self.path}@{self.branch}"
        elif self.repository and self.path:
            return f"{self.repository}/{self.path}"
        elif self.repository:
            return self.repository
        return f"{self.path}"


def validateUri(uri: str) -> OctoUri:
    #  Octo URI string
    if "@" in uri:

        repo, branch = uri.split("@", 1)

        org, repo = repo.split("/", 1)

        if "/" in repo:
            repo, path = repo.split("/", 1)
        else:
            path = None

        return OctoUri(f"{org}/{repo}", path, branch)

    #  Relative path
    if uri.startswith("./"):
        return OctoUri(path=uri)

    #  Paths
    uri = str(Path(uri).resolve()).replace(getcwd() + "/", "")

    #  Absolute paths
    if uri.startswith("/"):
        raise Exception(f"Absolute paths are not allowed: {uri}")
    #  Repo based path
    elif uri.count("/") == 1:
        return OctoUri(repository=uri)

    return OctoUri(path=uri)
