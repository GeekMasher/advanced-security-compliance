import os
import yaml
import logging
import requests

from ghascompliance.__version__ import __name__


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
    def __init__(self, repository=None, token=None, instance="https://api.github.com"):
        self.repository = repository
        self.owner, self.repo = repository.split("/", 1)
        self.token = token
        self.instance = instance

        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": "token " + self.token,
        }

        super().__init__()

    def format(self, string: str, **kwargs):
        frmt = string.format(
            repositor=self.repository, owner=self.owner, repo=self.repo, **kwargs
        )
        return frmt

    def request(method, url, params={}):
        def decorator(func):
            def wrap(self, **kwargs):
                full_url = self.instance + self.format(url)
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

                    if response.status_code != 200:
                        Octokit.error(response.text)
                        raise Exception("OctoRequest failed :: " + full_url)

                    full_response.extend(response.json())
                    if len(response.json()) < per_page:
                        break

                    page += 1

                result = func(self, response=full_response)

                return result

            return wrap

        return decorator
