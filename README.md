# Polaris Action

## Overview

The Polaris Github Action runs polaris scan, retrieves the scan results and generates SARIF report.

## Prerequisites

* To use this Action you **must be a licensed Polaris customer.**

| :exclamation: To get a demo and learn more about Polaris [click here](https://www.synopsys.com/software-integrity/polaris/demo-github.html).|
|-----------------------------------------|

## Example YAML config

```yaml
name: "Polaris Scan"

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

jobs:
  security:
    name: security scans
    runs-on: ubuntu-latest

    steps:
    - name: Checkout repository
      uses: actions/checkout@v2

    # If this run was triggered by a pull request event, then checkout
    # the head of the pull request instead of the merge commit.
    - run: git checkout HEAD^2
      if: ${{ github.event_name == 'pull_request' }}

    - name: Static Analysis with Polaris Action
      uses: devsecops-test/polaris-action@v1
      with:
        polarisServerUrl: ${{secrets.POLARIS_SERVER_URL}}
        polarisAccessToken: ${{secrets.POLARIS_ACCESS_TOKEN}}

    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v1
      with:
        # Path to SARIF file relative to the root of the repository
        sarif_file: polaris-results.sarif.json
```
