from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field, replace
import logging
from ghascompliance.octokit.octokit import Octokit
from ghascompliance.octokit.dependabot import Dependencies
from typing import List, Dict, Optional

from ghascompliance.__version__ import __version__
from ghascompliance.policies.imports import loadPolicyImport


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
    def getAllSeverities(include_misc: bool = False):
        all_severities = []
        for item in SeverityLevelEnum:
            if not include_misc and item.name in ["ALL", "NONE"]:
                continue
            all_severities.append(item.value)
        return all_severities

    @staticmethod
    def getSeveritiesFromName(severity: str, grouping: str = "higher") -> List[str]:
        """Get the list of severities from a given severity.
        Args:
            severity (str): The severity to get the list of severities from.
            grouping (str): The grouping type to use (higher or lower).
        """
        severities = SeverityLevelEnum.getAllSeverities()
        if severity == "none":
            return []
        elif severity == "all":
            return severities

        if grouping == "higher":
            return severities[: severities.index(severity) + 1]
        elif grouping == "lower":
            return severities[severities.index(severity) :]


@dataclass
class BlockImportsPolicyModel:
    ids: str = None
    names: str = None

    replace: bool = False


@dataclass
class BlockPolicyModels:
    ids: List[str] = field(default_factory=list)
    names: List[str] = field(default_factory=list)

    imports: BlockImportsPolicyModel = None

    def __post_init__(self):
        #  Perform imports
        if self.imports:
            for anno, _ in self.imports.__annotations__.items():
                if anno == "replace":
                    continue
                import_path = getattr(self.imports, anno)
                if import_path is None:
                    continue

                results = []
                if hasattr(self, anno) and not self.imports.replace:
                    results.extend(getattr(self, anno))
                # Replace existing values
                results.extend(loadPolicyImport(import_path))

                if hasattr(self, anno):
                    setattr(self, anno, results)
                    Octokit.debug(f"Set import results")

        # TODO: Keep the original values for the user?
        # lower case all values
        self.ids = [id.lower() for id in self.ids]
        self.names = [name.lower() for name in self.names]

    @property
    def enabled(self) -> bool:
        return self.ids or self.names


@dataclass
class RemediateModel:
    critical: int = None
    high: int = None
    error: int = None
    errors: int = None
    medium: int = None
    moderate: int = None
    low: int = None
    warning: int = None
    warnings: int = None
    note: int = None
    notes: int = None
    all: int = None

    def __post_init__(self):
        # Check if any remediate has a negative value
        for key in self.__annotations__.keys():
            if key == "all":
                continue
            val = getattr(self, key)
            # Skip if none or positive
            if val is None or val >= 0:
                continue

            raise PolicyException(f"Invalid remediate value for `{key}`")

    @property
    def enabled(self) -> bool:
        """Check if remediate is enabled"""
        for sevr in self.__annotations__.keys():
            val = getattr(self, sevr)
            if val is not None or val == -1:
                return True
        return False

    def getRemediateTime(self, severity: str) -> int:
        """Get the remediate time for a given severity.
        Args:
            severity (str): The severity to get the remediate time for.
        """
        severities = SeverityLevelEnum.getSeveritiesFromName(severity, grouping="lower")

        for sevr in severities:
            val = getattr(self, sevr)
            #  Skip if none
            if val is None or val == -1:
                continue
            return val
        return None


@dataclass
class GeneralPolicyModel:
    #  The deault severity level that the policy will trigger on
    level: str = "none"
    #  Conditions
    conditions: BlockPolicyModels = BlockPolicyModels()
    #  Warnings
    warnings: BlockPolicyModels = BlockPolicyModels()
    #  Ignored
    ignores: BlockPolicyModels = BlockPolicyModels()
    # Remediate
    remediate: RemediateModel = None

    def __post_init__(self):
        #  Validate level
        if self.level not in SeverityLevelEnum.getAllSeverities(include_misc=True):
            raise PolicyException(
                f"{self.__class__.__name__}: `level` variable is set to unknown value"
            )

    @property
    def enabled(self) -> bool:
        if self.level != "none":
            return True
        if self.conditions.enabled or self.warnings.enabled or self.ignores.enabled:
            return True
        return False

    @property
    def timeToRemediateActive(self):
        return self.remediate is not None

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
    general: GeneralPolicyModel = None

    #  Code Scanning
    codescanning: GeneralPolicyModel = GeneralPolicyModel()

    #  Dependencies
    dependabot: GeneralPolicyModel = GeneralPolicyModel()
    licensing: GeneralPolicyModel = GeneralPolicyModel()
    dependencies: GeneralPolicyModel = GeneralPolicyModel()

    #  Secret Scanning
    secretscanning: GeneralPolicyModel = GeneralPolicyModel()

    def __post_init__(self):
        if self.general is None:
            return
        # apply General policy to all policies
        for policy, model in self.getPolicies().items():
            #  Set default severity level
            if getattr(self, policy).level == "none":
                model.level = self.general.level
                setattr(self, policy, model)

            if getattr(self, policy).remediate is None:
                # Replace with default remediate
                model.remediate = self.general.remediate
                setattr(self, policy, model)

    def getPolicies(self) -> Dict[str, GeneralPolicyModel]:
        """Get a dict of all the policies"""
        ret = {}
        for annoname, annotype in self.__annotations__.items():
            if annoname == "general":
                continue
            if annotype.__name__ == GeneralPolicyModel.__name__:
                ret[annoname] = getattr(self, annoname)

        return ret

    def getPolicy(self, policy_name: str) -> Optional[GeneralPolicyModel]:
        if getattr(self, policy_name).enabled:
            return getattr(self, policy_name)
        return None
