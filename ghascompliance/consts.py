# Future proofing using NIST severity standard
SEVERITIES = [
    "critical",
    "high",
    "error",
    "errors",
    "medium",
    "moderate",  # Dependabot
    "low",
    "warning",
    "warnings",
    # Informational issues
    "note",
    "notes",
]

TECHNOLOGIES = [
    "codescanning",
    "dependabot",
    "licensing",
    "dependencies",
    "secretscanning",
]

LICENSES = [
    # GPL
    "GPL-2.0",
    "GPL-3.0",
    # LGPL
    "LGPL-3.0 License",
    "LGPL-2.1",
]

# API string, Pretty Print, raise exception?
API_ERRORS = [
    {
        "message": "repository not enabled for code scanning",
        "pretty": "Code Scanning is Disabled on Repository",
        "raise": False,
    },
    {
        "message": "Secret scanning APIs are not available on public repositories",
        "raise": False,
    },
    {"message": "Repository is not part of an organization.", "raise": False},
]
