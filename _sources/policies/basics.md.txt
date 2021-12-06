# Basics

This document describes the overview of the Policy as Code template schema.

## Policy Metadata

Each policy has metadata attached to help make it easy to name and tag other metadata.

<!-- TODO add other metadata when supported -->
```yaml
# Name of the policy
name: Default Policy
```

## General Policy Blocks

There are (as of v1.5) 5 different general policy blocks which dictate what policy applies to which to a particular technologies.

- `codescanning` - Code Scanning policy
- `dependabot` - Dependency Security Alerts (dependabot) policy
- `licensing` - Dependency Licensing Alerts (dependency graph) policy
- `dependencies` - Dependency usage Alerts (dependency graph) policy
- `secretscanning` - Secret Scanning Alerts policy

Each of these blocks have a `GeneralPolicyModel` used which consists of multiple parts; Severity level or Conditional.

### Severity Level Policy

The first and simplest of these is the `level` attribute which allows you to specify the severity level of a policy.
This checks the severity of the alert and reports an policy violation if the level matches or higher

```yaml
# Code Scanning policy setting level to error or above
codescanning:
  level: error
```

There are a number of levels are [specified in the standard and are constant](https://github.com/GeekMasher/advanced-security-compliance/blob/main/ghascompliance/consts.py#L2-L15):
<!-- TODO: update for v2.0 -->

- `critical`
- `high`
- `error`
- `errors`
- `medium`
- `moderate`
- `low`
- `warning`
- `warnings`
- `note`
- `notes`


### Conditional Policy

The conditional policy attributes allow users to write more complex conditional checks.
There are four main rules types to do everything you need to do for all things compliance.

```yaml
codescanning:
  # Warnings will always occur if the rule applies and continues executing to 
  #  other rules.
  warnings:
    ids:
      - Other
      - NA
  # Ignores are run next so if an ignored rule is hit that matches the level, 
  #  it will be skipped
  ignores:
    ids:
      - MIT License
  # Conditions will only trigger and raise an error when an exact match is hit
  conditions:
    ids:
      - GPL-2.0
    names:
      - tunnel-agent

  # The simplest and ultimate rule which checks the severity of the alert and
  #  reports an issue if the level matches or higher (see PaC Levels for more info)
  level: error
```
