from dataclasses import dataclass, field

from ghascompliance.utils.octouri import validateUri

"""
workflows:
  codeql:
    required: true
    action: github/codeql-action/init
    using:
      config-file: GeekMasher/security-queries/config/codeql.yml@main
      queries: security-extended

  eslint:
    required: true
    upload: true
    languages: [ javascript ]
    action: github/ossar-action
"""


@dataclass
class WorkflowsPolicy:
    action: str = None
    required: bool = False


@dataclass
class WorkflowsPolicy:
    workflows: list[WorkflowsPolicy] = field(default_factory=list)
