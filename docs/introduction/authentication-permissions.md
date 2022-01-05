# Authentication and Permissions

GHAS Compliance uses primarily the GitHub REST and GraphQL API's to perform specific tasks and actions.
This requires authenticating using a GitHub Access Token which can access various services endpoints.


## Permissions

The main use case using GitHub Action uses an [automatic token authentication](https://docs.github.com/en/actions/security-guides/automatic-token-authentication) which might [not have the permissions needed for every policy](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token).


### Code Scanning

[GitHub Code Scanning API](https://docs.github.com/en/rest/reference/code-scanning) requires the ability to read Code Scanning results which can be accessed using Action generated Tokens.


*Versions: GHES <= 3.0* 

### Dependencies

GitHub Dependency Graph & Dependabot requires various permissions to access the [GraphQL API](https://docs.github.com/en/graphql).

*Note:* Default Action generated Tokens don't support accessing this API.


### Secret Scanning

Secret Scanning requires a lot of permissions to access the content from the API.

> "To use this endpoint, you must be an administrator for the repository or organization, and you must use an access token with the repo scope or security_events scope."

Source: [GitHub docs](https://docs.github.com/en/rest/reference/secret-scanning#list-secret-scanning-alerts-by-organization)


*Note:* Default Action generated Tokens don't support accessing this API.

*Versions: GHES <= 3.1* 
