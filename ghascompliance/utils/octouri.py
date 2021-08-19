from dataclasses import dataclass


@dataclass
class OctoUri:
    # owner/repo
    repository: str = None
    path: str = None
    branch: str = None


def validateUri(uri: str) -> OctoUri:
    #  Always a relative path
    if uri.startswith("./") or uri.startswith("/"):
        return OctoUri(path=uri)
    #  Repo based path
    elif "@" in uri:

        repo, branch = uri.split("@", 1)

        org, repo = repo.split("/", 1)

        if "/" in repo:
            repo, path = repo.split("/", 1)
        else:
            path = None

        return OctoUri(f"{org}/{repo}", path, branch)

    return OctoUri(path=uri)
