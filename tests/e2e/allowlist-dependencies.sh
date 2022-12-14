#!/bin/bash

pipenv run main --debug --display \
    --github-policy-path examples/policies/allowlist-dependencies.yml \
    --github-repository GeekMasherOrg/Pixi \
    --github-ref refs/heads/master \
    --github-token $GITHUB_TOKEN \
    --action continue
