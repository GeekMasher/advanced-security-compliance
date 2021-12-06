# Typo-squatting

A big issue that you might want to verify is that an application is using a dependency which is not vulnerable per say but is a know dependency which has been miss typed to get developers using it.
These dependencies might contain crypto miners all the way to code exfiltrating malware.


## Enabling built in list

Enabling this check only requires importing the built in list of known dependencies:

```yaml
name: Typo-squatting Policy

# ...
dependencies:
  conditions:
    imports:
      # Import text list of Typo-squatting dependencies.
      names: ghascompliance/defaults/typosquatting.txt
```

