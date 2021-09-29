from enum import Enum
from dataclasses import dataclass, field
from ghascompliance.octokit.dependabot import Dependencies
from typing import List

from ghascompliance.__version__ import __version__


class PolicyException(Exception):
    pass


@dataclass
class SeverityLevelEnum(Enum):
    #  Critical to High issues
    CRITICAL = "critical"
    HIGH = "high"
    ERROR = "error"
    ERRORS = "errors"
    #  Medium to Low issues
    MEDIUM = "medium"
    MODERATE = "moderate"
    LOW = "low"
    WARNING = "warning"
    WARNINGS = "warnings"
    # Informational issues
    NOTE = "note"
    NOTES = "notes"
    # Misc
    ALL = "all"
    NONE = "none"

    @staticmethod
    def getAllSeverities(include_misc=False):
        all_severities = []
        for item in SeverityLevelEnum:
            if not include_misc and item.name in ["ALL", "NONE"]:
                continue
            all_severities.append(item.value)
        return all_severities

    @staticmethod
    def getSeveritiesFromName(severity: str):
        severities = SeverityLevelEnum.getAllSeverities()
        if severity == "none":
            return []
        elif severity == "all":
            return severities

        return severities[: severities.index(severity) + 1]


@dataclass
class BlockImportsPolicyModel:
    ids: str = None
    names: str = None


@dataclass
class BlockPolicyModels:
    ids: List[str] = field(default_factory=list)
    names: List[str] = field(default_factory=list)

    imports: BlockImportsPolicyModel = None


@dataclass
class GeneralPolicyModel:
    #  The deault severity level that the policy will trigger on
    level: str = "error"
    #  Conditions
    conditions: BlockPolicyModels = None
    #  Warnings
    warnings: BlockPolicyModels = None
    #  Ignored
    ignores: BlockPolicyModels = None

    def __post_init__(self):
        #  Validate level
        if self.level not in SeverityLevelEnum.getAllSeverities(include_misc=True):
            raise PolicyException(
                f"{self.__class__.__name__}: `level` variable is set to unknown value"
            )

    def getSeverityList(self, severity: str = None):
        if not severity:
            severity = self.level
        elif severity not in SeverityLevelEnum.getAllSeverities(True):
            raise PolicyException(f"Unknown Severity level: {severity}")

        return SeverityLevelEnum.getSeveritiesFromName(severity)


@dataclass
class PolicyModel:
    version: str = __version__
    name: str = "Policy"

    # ===== Policies =====
    #  General (default)
    general: GeneralPolicyModel = GeneralPolicyModel()

    #  Code Scanning
    codescanning: GeneralPolicyModel = None

    #  Dependencies
    dependabot: GeneralPolicyModel = None
    licensing: GeneralPolicyModel = None
    dependencies: GeneralPolicyModel = None

    #  Secret Scanning
    secretscanning: GeneralPolicyModel = None

    def __post_init__(self):
        #  Code Scanning
        if not self.codescanning:
            self.codescanning = GeneralPolicyModel(self.general.level)
        #  Dependencies
        if not self.dependabot:
            self.dependabot = GeneralPolicyModel(self.general.level)
        if not self.licensing:
            self.licensing = GeneralPolicyModel(self.general.level)
        if not self.dependencies:
            self.dependencies = GeneralPolicyModel(self.general.level)
        #  Secret Scanning
        if not self.secretscanning:
            self.secretscanning = GeneralPolicyModel(self.general.level)

    @property
    def policies(self) -> List[str]:
        ret = []
        for annoname, annotype in self.__annotations__.items():
            if annoname == "general":
                continue
            if annotype.__name__ == GeneralPolicyModel.__name__:
                ret.append(annoname)

        return ret
