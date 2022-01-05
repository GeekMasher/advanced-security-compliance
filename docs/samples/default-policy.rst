Default Policy
--------------

The simplest way to use GHASCompliance is to use the `Default Policy`_.


.. code-block:: yaml
  :linenos:
  
  name: Default Policy

  # Code Scanning policy
  codescanning:
    level: error

  # Dependency Security Alerts (dependabot) policy
  dependabot:
    level: high

  # Dependency Licensing Alerts (dependency graph) policy
  licensing:
    conditions:
      ids:
        - GPL-*
        - LGPL-*
        - AGPL-*

    warnings:
      # Warning is the dependency isn't known
      ids:
        - Other
        - NA
  
  # Dependency usage Alerts (dependency graph) policy
  # dependencies:

  # Secret Scanning Alerts policyS
  secretscanning:
    level: all


.. _Default Policy: https://github.com/GeekMasher/advanced-security-compliance/blob/main/ghascompliance/defaults/policy.yml
