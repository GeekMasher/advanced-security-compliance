<!-- Warning:
This issue was created and updated by advanced-security-compliance and changed to the body might be overwritten
-->
### Summary

- Repository: [{{owner}}/{{repository}}]({{ repository_url }})
- Risk Rating: {{risk_rating}}
- Last Update: {{date}}

### Details

|               Status               | Checker                                                               |       Total Reported Alerts       |          Reported Errors           |          Reported Warnings           | Details |
| :--------------------------------: | :-------------------------------------------------------------------- | :-------------------------------: | :--------------------------------: | :----------------------------------: | :------ |
|  {{ report.codescanning.status }}  | [Code Scanning]({{ repository_url }}/security/code-scanning)          |  {{ report.codescanning.total }}  |  {{ report.codescanning.errors }}  |  {{ report.codescanning.warnings }}  |         |
|  {{ report.dependencies.status }}  | [Dependencies]({{ repository_url }}/network/dependencies)             |  {{ report.dependencies.total }}  |  {{ report.dependencies.errors }}  |  {{ report.dependencies.warnings }}  |         |
|   {{ report.dependabot.status }}   | [Dependencies (security)]({{ repository_url }}/security/dependabot)   |   {{ report.dependabot.total }}   |   {{ report.dependabot.errors }}   |   {{ report.dependabot.warnings }}   |         |
|   {{ report.licensing.status }}    | [Dependencies (licensing)]({{ repository_url }}/network/dependencies) |   {{ report.licensing.total }}    |   {{ report.licensing.errors }}    |   {{ report.licensing.warnings }}    |         |
| {{ report.secretscanning.status }} | [Secret Scanning]({{ repository_url }}/security/secret-scanning)      | {{ report.secretscanning.total }} | {{ report.secretscanning.errors }} | {{ report.secretscanning.warnings }} |         |
