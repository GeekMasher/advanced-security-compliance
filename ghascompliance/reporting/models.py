from dataclasses import dataclass


@dataclass
class Reports:
    enabled: bool = False

    def isEnabled(self):
        return self.enabled


@dataclass
class IssuesConfig(Reports):
    owner: str = None
    repository: str = None

    def __post_init__(self):
        if self.owner and self.repository:
            self._enabled = True


@dataclass
class ReportingConfig:
    issues: IssuesConfig = IssuesConfig()

    def getReports(self):
        return ReportingConfig.__annotations__
