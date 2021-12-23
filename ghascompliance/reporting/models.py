from dataclasses import dataclass, field


@dataclass
class SecurityReport:
    errors: int = 0
    warnings: int = 0

    @property
    def total(self):
        return self.errors + self.warnings

    @property
    def status(self):
        if self.errors > 0:
            return ":red_circle:"
        elif self.warnings > 0:
            return ":yellow_circle:"
        return ":green_circle:"


@dataclass
class Report:
    codescanning: SecurityReport = SecurityReport()
    dependabot: SecurityReport = SecurityReport()
    dependencies: SecurityReport = SecurityReport()
    licensing: SecurityReport = SecurityReport()
    secretscanning: SecurityReport = SecurityReport()

    @property
    def total(self):
        total = 0
        for ann in Report.__annotations__:
            _report = self.__getattribute__(ann)
            if _report:
                total += _report.total

        return total


@dataclass
class Reports:
    enabled: bool = False


@dataclass
class IssuesConfig(Reports):
    #  GitHub Issue title
    title: str = "[GHAS Compliance] {owner}/{repository}"
    #  Template for issue body
    template: str = "issues.md"
    #  Repository
    repository: str = None

    # Default assignees
    assignees: list[str] = field(default_factory=list)

    #  Close the issue if no issues are reported
    close: bool = False

    def __post_init__(self):
        if self.repository:
            self.enabled = True


@dataclass
class ReportingConfig:
    issues: IssuesConfig = IssuesConfig()

    issues_summary: IssuesConfig = IssuesConfig()

    def getReports(self, enabled: bool = None):
        reports = {}
        for ann in ReportingConfig.__annotations__:
            if enabled is None:
                reports[ann] = self.__getattribute__(ann)
            else:
                report = self.__getattribute__(ann)
                if report.enabled == enabled:
                    reports[ann] = report

        return reports
