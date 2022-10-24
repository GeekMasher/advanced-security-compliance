# App-authentication

When working with this action at scale, you might want to use a GitHub App for authentication, rather than using a Personal Access Token.

This will allow you to roll this app out to an entire Organisation, without giving that entire organisation access to your PAT.


## Enabling GitHub App Authentication

Enabling this check only requires importing the built in list of known dependencies:

```yaml
name: GitHub App Authentication

# ...
    - name: Generate GitHub token
      uses: navikt/github-app-token-generator@2d70c12368d1958155af4d283f9f21c9a2a8cb98
      id: get-token
      with:
        private-key: ${{ secrets.GIT_APP_PEM }}
        app-id: ${{ secrets.GIT_APP_ID }}

    - name: Security Compliance Action
      uses: GeekMasher/advanced-security-compliance@v1.6.3
# ...

      with:

        # GitHub App Token generated from earlier step
        token: ${{ steps.get-token.outputs.token }}
        
        # Argv required to get GitHub App auth working
        argvs: '--is-github-app-token'
```

