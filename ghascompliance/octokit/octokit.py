import os
import json
import yaml
import logging
import requests
from urllib.parse import urlparse

from ghascompliance.__version__ import __name__
from ghascompliance.consts import API_ERRORS


class GitHub:
    def __init__(
        self,
        repository=None,
        token=None,
        instance="https://github.com",
        ref=None,
        **kwargs
    ):
        self.__dict__ = dict()

        self.owner = None
        self.repo = None
        self.set("repository", repository)

        if "/" in self.repository:
            owner, repo = self.repository.split("/", 1)
            self.set("owner", owner)
            self.set("repo", repo)
        else:
            self.set("owner", "")
            self.set("repo", repository)

        self.set("token", token)
        # TODO: Validate instance
        url = urlparse(instance)
        self.set("instance", instance)
        # TODO: Validate API url
        api = url.scheme + "://api." + url.netloc
        self.set("api.rest", api)
        self.set("api.graphql", api + "/graphql")
        # TODO: Validate ref; examples: refs/heads/main
        self.set("ref", ref)

    def set(self, key, value, default=None):
        if value:
            self.__dict__.__setitem__(key, value)
        else:
            self.__dict__.__setitem__(key, default)

    def get(self, key, default=None):
        result = self.__getitem__(key)
        return result if result else default

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return repr(self.__dict__)

    @property
    def url(self):
        return "https://" + self.instance + "/" + self.repository

    @property
    def cloneUrl(self):
        instance = urlparse(self.instance).netloc
        if self.token:
            # Public / Private repos
            return "https://" + self.token + "@" + instance + "/" + self.repository
        else:
            # Public repos
            return "https://" + instance + "/" + self.repository


class Octokit:
    __ERRORS__ = []
    __EVENT__ = None

    logger = logging.getLogger(__name__)

    @staticmethod
    def info(msg):
        logging.info(msg)
        print(msg)

    def debug(msg):
        logging.debug(msg)
        if Octokit.logger.level == logging.DEBUG and Octokit.__EVENT__:
            print("::debug :: {msg}".format(msg=msg))
        elif Octokit.logger.level == logging.DEBUG:
            print("[*] " + msg)

    @staticmethod
    def warning(msg):
        logging.warning(msg)
        if Octokit.__EVENT__:
            print("::warning :: {msg}".format(msg=msg))
        else:
            print("[!] " + msg)

    @staticmethod
    def error(msg, file=None, line=0, col=0):
        Octokit.__ERRORS__.append(msg)
        logging.error(msg)

        if Octokit.__EVENT__:
            print("::error ::{msg}".format(msg=msg))
        elif file:
            print(
                "::error file={file},line={line},col={col}::{msg}".format(
                    msg=msg, file=file, line=line, col=col
                )
            )
        else:
            print("[!] {msg}".format(msg=msg))

    @staticmethod
    def createGroup(name):
        if Octokit.__EVENT__:
            print("::group::{name}".format(name=name))
        else:
            print("{:-^42}".format(name))

    @staticmethod
    def endGroup():
        if Octokit.__EVENT__:
            print("::endgroup::")

    @staticmethod
    def setOutput(key, value):

        if Octokit.__EVENT__:
            print("::set-output name={}::{}".format(key, value))
        else:
            Octokit.warning(
                "Setting output is not supported in a non GitHub Action context"
            )
        # subprocess.call(["echo", "::set-output name={}::{}".format(key, value)])

    @staticmethod
    def loadEvents(path: str):
        Octokit.debug("Loading event: " + str(path))
        event = {}

        if path and os.path.exists(path):
            with open(path, "r") as handle:
                event = yaml.safe_load(handle)
            Octokit.__EVENT__ = event
        return event


class OctoRequests(Octokit):
    def __init__(self, github: GitHub):
        self.github = github

        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": "token " + self.github.token,
        }

        super().__init__()

    def format(self, string: str, **kwargs):
        frmt = string.format(**self.github.__dict__, **kwargs)
        return frmt

    @staticmethod
    def checkErrors(name):
        for error in API_ERRORS:
            if error.get("message") == name:
                Octokit.debug("Known error :: " + error.get("message"))

                message = error.get("pretty", error.get("message"))
                Octokit.warning(message)

                if error.get("raise"):
                    raise Exception(message)
                return True

        return False

    def request(method, url, params={}):
        def decorator(func):
            def wrap(self, **kwargs):
                full_url = self.github.get("api.rest") + self.format(url)
                full_response = []
                per_page = 100

                Octokit.debug("OctoRequests :: {}".format(func.__name__))

                full_params = {**params, **kwargs.get("params", {})}

                page = 1
                while True:
                    full_params["per_page"] = per_page
                    full_params["page"] = page

                    Octokit.debug("Request Parameters :: " + str(full_params))

                    response = requests.request(
                        method, full_url, headers=self.headers, params=full_params
                    )

                    json_data = response.json()

                    if response.status_code != 200:
                        if not OctoRequests.checkErrors(json_data.get("message")):
                            # Throw unknown errors
                            Octokit.error(json.dumps(json_data, indent=2))
                            raise Exception("Failed to execute OctoRequest")
                        break

                    if isinstance(json_data, dict) and json_data.get("errors"):
                        if not OctoRequests.checkErrors(json_data.get("message")):
                            # Throw unknown errors
                            Octokit.error(json.dumps(json_data, indent=2))
                            raise Exception("Failed to execute OctoRequest")

                    full_response.extend(json_data)
                    if len(response.json()) < per_page:
                        break

                    page += 1

                result = func(self, response=full_response)

                return result

            return wrap

        return decorator
