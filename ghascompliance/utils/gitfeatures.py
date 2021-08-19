import os
import shutil
import tempfile
import subprocess
from urllib.parse import urlparse


def createGitURI(repository, instance, token):
    if token:
        repo = "https://" + token + "@" + instance + "/" + repository
    else:
        repo = "https://" + instance + "/" + repository
    return repo


def clone(
    repository, branch=None, instance="https://github.com", token=None, output=None
):
    instance = urlparse(instance).netloc

    repo = createGitURI(repository, instance, token)

    if not output:
        output = os.path.join(tempfile.gettempdir(), "repo")

    if os.path.exists(output):
        # Octokit.debug("Deleting existing temp path")
        shutil.rmtree(output)

    # Octokit.info(f"Cloning policy repo - {self.repository}")

    cmd = ["git", "clone", "--depth=1"]

    if branch:
        cmd.extend(["-b", branch])

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
