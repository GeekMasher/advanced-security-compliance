# advanced-security-compliant

GitHub Advance Security Compliance Action


## Usage

### Action

```yaml
# Compliance
- name: Advance Security Compliance Action
  uses: GeekMasher/advanced-security-compliant@main
```

##### Action with parameters

```yaml
# Compliance
- name: Advance Security Compliance Action
  uses: GeekMasher/advanced-security-compliant@main
  with:
    # Set the severity levels which to set the threshold. All previous 
    # severities are included so selecting 'error' also selects 'critical' and 
    # 'high' along with 'error'.
    severity: error
    # Repository owner/name
    repository: GeekMasher/advanced-security-compliant
    # GitHub Personal Access Token
    token: GITHUB_PAT
    # GitHub reference
    ref: refs/heads/main
    # What course of action to take upon discovering security issues that pass
    # threshold?
    action: break
    # Additional arguments
    argvs: '--disable-secret-scanning --disable-dependabot'
```


##### Full Example

```yaml
name: Compliance

on:
  push:
    branches: [ main, master, develop, release-* ]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Advance Security Compliance Action
        uses: GeekMasher/advanced-security-compliant@main
```
