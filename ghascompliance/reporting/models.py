from dataclasses import dataclass


@dataclass
class Reports:
    enabled: bool = False


@dataclass
class IssuesConfig(Reports):
    owner: str = None
    repository: str = None

    def __post_init__(self):
        if self.repository:
            self.enabled = True


@dataclass
class ReportingConfig:
    issues: IssuesConfig = IssuesConfig()

    def getReports(self):
        reports = {}
        for ann in ReportingConfig.__annotations__:
            reports[ann] = self.__getattribute__(ann)
        return reports
