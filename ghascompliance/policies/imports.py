import os
import tempfile
from ghascompliance import __HERE__
from ghascompliance.octokit.octokit import Octokit
from ghascompliance.utils.config import Paths

__SUPPORTED_TYPES__ = ["txt"]


def loadPolicyImport(path: str):
    results = []
    traversal = False
    paths = []
    # Current Working Dir
    paths.append((os.getcwd(), path))

    # Temp Repo / Cloned Repo
    if Paths.policy_repository:
        Octokit.debug("loadPolicyImport(): Policy Repository is set")
        paths.append((str(Paths.policy_repository), path))

    # Action / CLI directory
    paths.append((__HERE__, path))

    for root, path in paths:
        full_path = os.path.abspath(os.path.join(root, path))

        if os.path.exists(full_path) and os.path.isfile(full_path):
            if full_path.startswith(tempfile.gettempdir()):
                Octokit.debug("Temp location used for import path")
            elif not full_path.startswith(root):
                Octokit.error("Attempting to import file :: " + full_path)
                raise Exception("Path Traversal Detected, halting import!")

            # TODO: MIME type checking?
            _, fileext = os.path.splitext(full_path)
            fileext = fileext.replace(".", "")

            if fileext not in __SUPPORTED_TYPES__:
                Octokit.warning("Trying to load a disallowed file type :: " + fileext)
                continue

            Octokit.info("Importing Path :: " + full_path)

            with open(full_path, "r") as handle:
                for line in handle:
                    line = line.replace("\n", "").replace("\b", "")
                    if line == "" or line.startswith("#"):
                        continue
                    results.append(line)

            break
    return results
