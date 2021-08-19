import os
import yaml
from dataclasses import dataclass

from ghascompliance.utils.config import Config, _dataclass_from_dict
from ghascompliance.octokit.octokit import Octokit


@dataclass
class ThreatModel:
    level: str = "normal"


def selectThreatModel(config: Config, level: str):
    if level is None or level == "":
        return config.policy

    if level == "high" and config.threat_models.high:
        Octokit.info(f"Threat model selected: `{level}`")
        return config.threat_models.high
    elif level == "low" and config.threat_models.low:
        Octokit.info(f"Threat model selected: `{level}`")
        return config.threat_models.low
    elif level == "normal" and config.threat_models.normal:
        Octokit.info(f"Threat model selected: `{level}`")
        return config.threat_models.normal

    Octokit.debug(f"Threat model selected: default")
    return config.policy


def loadFile(path: str) -> ThreatModel:
    if not os.path.exists(path):
        raise Exception(f"Threat Modeling Compliance file does not exists at: {path}")

    with open(path, "r") as handle:
        content = yaml.safe_load(handle)

    return ThreatModel(**content)