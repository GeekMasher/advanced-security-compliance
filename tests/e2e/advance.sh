#!/bin/bash

pipenv run main --debug \
    --github-policy-path examples/policies/advance.yml \
    --github-repository GeekMasherOrg/Pixi \
    --github-ref refs/heads/master \
    --github-token $GITHUB_TOKEN \
    --action continue
