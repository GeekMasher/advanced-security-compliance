# advanced-security-compliance

This Action was designed to allow users to configure their Risk threshold for security issues reported by [GitHub Code Scanning](https://docs.github.com/en/code-security/secure-coding/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning), [Secret Scanning](https://docs.github.com/en/code-security/secret-security/about-secret-scanning) and [Dependabot Security](https://docs.github.com/en/code-security/supply-chain-security/managing-vulnerabilities-in-your-projects-dependencies/configuring-dependabot-security-updates#about-configuring-dependabot-security-updates).


## Usage

### Action

Here is how you can quickly setup advanced-security-compliance. 

```yaml
# Compliance
- name: Advance Security Compliance Action
  uses: GeekMasher/advanced-security-compliance@main
```

##### Action with parameters

Here is a example Action with all the parameters with comments.

```yaml
# Compliance
- name: Advance Security Compliance Action
  uses: GeekMasher/advanced-security-compliance@main
  with:
    # Set the severity levels which to set the threshold. All previous 
    # severities are included so selecting 'error' also selects 'critical' and 
    # 'high' along with 'error'.
    severity: error
    # Repository owner/name.
    # This can be setup using a separate repository to the one being analysed 
    #  for security compliance
    repository: GeekMasher/advanced-security-compliance
    # GitHub Personal Access Token to access the GitHub API.
    # Secret Scanning and Dependabot do not allow their resources to be
    #  exposed to Actions so this might need to be set using a token that has 
    #  the ability to access the resources
    token: GITHUB_PAT
    # GitHub reference
    ref: refs/heads/main
    # What course of action to take upon discovering security issues that pass
    # threshold?
    action: break
    # Additional arguments
    argvs: '--disable-secret-scanning --disable-dependabot'
```

##### Policy as Code

Here is an example of using a simple yet cross-organization using Policy as Code:

```yaml
# Compliance
- name: Advance Security Compliance Action
  uses: GeekMasher/advanced-security-compliance@main
  with:
    # The owner/repo of where the policy is stored  
    policy: GeekMasher/security-queries
    # The local (within the workspace) or repository
    policy-path: policies/default.yml
    # The branch you want to target
    policy-branch: main
```


##### Full Example

```yaml
name: Compliance

on:
  push:
    branches: [ main, master, develop, release-* ]

jobs:
  # Code Scanning Steps
  # ...
  compliance:
    runs-on: ubuntu-latest
    # [optional] Run this job after a Code Scanning job
    # needs:
    #   - codeql
    steps:
      - uses: actions/checkout@v2

      # optional - The Action requires Python 3 to be installed on the runner
      - uses: actions/setup-python@v2
        with:
          python-version: '3.8'

      - name: Advance Security Compliance Action
        uses: GeekMasher/advanced-security-compliance@main
```
