import os
import shutil
import tempfile
import subprocess
from urllib.parse import urlparse
from ghascompliance.utils.octouri import OctoUri


def createGitURI(repository, instance, token):
    if token:
        repo = f"https://{token}@{instance}/{repository}"
    else:
        repo = f"https://{instance}/{repository}"
    return repo


def clone(
    uri: OctoUri,
    name: str = "repo",
    instance="https://github.com",
    token=None,
    output=None,
):
    instance = urlparse(instance).netloc

    repo = createGitURI(uri.repository, instance, token)

    if not output:
        output = os.path.join(tempfile.gettempdir(), name)

    if os.path.exists(output):
        # Octokit.debug("Deleting existing temp path")
        shutil.rmtree(output)

    # Octokit.info(f"Cloning policy repo - {self.repository}")

    cmd = ["git", "clone", "--depth=1"]

    if uri.branch:
        cmd.extend(["-b", uri.branch])

    cmd.extend([repo, output])

    # Octokit.debug(f"Running command - {cmd}")

    with open(os.devnull, "w") as null:
        subprocess.run(
            cmd,
            stdout=null,
            stderr=null,
        )

    if not os.path.exists(output):
        raise Exception("Repository failed to clone")

    return output
