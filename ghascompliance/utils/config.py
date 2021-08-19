import os
import yaml
from dataclasses import dataclass


def _dataclass_from_dict(klass, dikt):
    try:
        fieldtypes = klass.__annotations__
        return klass(**{f: _dataclass_from_dict(fieldtypes[f], dikt[f]) for f in dikt})

    except KeyError as err:
        raise Exception(f"Unknown key being set in configuration file : {err}")

    except AttributeError as err:
        if isinstance(dikt, (tuple, list)):
            return [_dataclass_from_dict(klass.__args__[0], f) for f in dikt]
        return dikt


@dataclass
class PolicyConfig:
    instance: str = "https://github.com"
    repository: str = None
    path: str = None
    branch: str = None

    severity: str = "Error"

    display: bool = False


@dataclass
class ThreatModelConfig:
    source: str = None
    high: PolicyConfig = None
    normal: PolicyConfig = None
    low: PolicyConfig = None


@dataclass
class CheckersConfig:
    codescanning: bool = True
    dependabot: bool = True
    dependencies: bool = True
    licensing: bool = True
    secretscanning: bool = True


@dataclass
class IssuesConfig:
    owner: str = None
    repository: str = None


@dataclass
class ReportingConfig:
    issues: IssuesConfig = IssuesConfig()


@dataclass
class GitHubConfig:
    instance: str = None
    repository: str = None


@dataclass
class Config:
    name: str = "Configuration"
    github: GitHubConfig = GitHubConfig()

    policy: PolicyConfig = PolicyConfig()

    threat_models: ThreatModelConfig = ThreatModelConfig()

    checkers: CheckersConfig = CheckersConfig()

    reporting: ReportingConfig = ReportingConfig()

    @staticmethod
    def load(path: str):
        if not os.path.exists(path):
            return

        with open(path) as handle:
            data = yaml.safe_load(handle)

        return _dataclass_from_dict(Config, data)
