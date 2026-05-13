---
name: Release checklist
about: Track a BLA release from version bump to PyPI smoke test
title: "Release: vX.Y.Z"
labels: release
assignees: ""
---

## Version

- [ ] `bla/__version__.py` contains the target version
- [ ] `bla --version` shows the target version
- [ ] JSON/SARIF report metadata uses the target version
- [ ] README examples use the target version

## Validation

- [ ] `python3 -m compileall -q bla bla_cli.py setup.py tests`
- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `python3 bla_cli.py validate-rules --strict-metadata`
- [ ] sample log smoke tests pass with `--exit-on none`
- [ ] `python3 -m build`
- [ ] wheel/sdist include `bla/rules/web_attacks.yaml`

## Publishing

- [ ] Git tag created as `vX.Y.Z`
- [ ] GitHub Release created with notes and artifacts
- [ ] PyPI Trusted Publishing is configured for `.github/workflows/publish.yml` and the `pypi` GitHub environment
- [ ] Only one PyPI publish path is used for this version: GitHub Release workflow preferred, no prior manual `twine` upload
- [ ] PyPI publish workflow completed
- [ ] Fresh PyPI install smoke tested
