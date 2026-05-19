---
name: Release checklist
about: Track a BLA release from version bump to PyPI smoke test
title: "Release: vX.Y.Z"
labels: release
assignees: ""
---

## Version

- [ ] `bla/__version__.py` contains the target version
- [ ] Git tag is exactly `vX.Y.Z` and matches `bla.__version__`
- [ ] `bla --version` shows the target version
- [ ] JSON/SARIF report metadata uses the target version
- [ ] README examples use the target version

## Validation

- [ ] `python3 -m compileall -q bla bla_cli.py setup.py tests`
- [ ] `python3 -m pytest -q`
- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `python3 bla_cli.py validate-rules --strict-metadata`
- [ ] sample log smoke tests pass with `--exit-on none`
- [ ] P0 fixture smoke test passes with `--profile cn-hvv --out /tmp/bla-p0-smoke --exit-on none --no-color`
- [ ] `bla ssh --help` confirms Remote Workspace CLI wiring
- [ ] `python3 bla_cli.py benchmark --size-mb 1`
- [ ] `python3 bla_cli.py benchmark --size-mb 1 --memory`
- [ ] `python3 -m build`
- [ ] `python3 -m twine check dist/*` when `twine` is available
- [ ] wheel includes package code/rules; sdist includes release notes, sample logs, and P0 fixtures
- [ ] fresh wheel install smoke test passes

## Publishing

- [ ] Git tag created as `vX.Y.Z`
- [ ] GitHub Release created with notes and artifacts, marked Latest
- [ ] PyPI Trusted Publishing is configured for `.github/workflows/publish.yml` and the `pypi` GitHub environment
- [ ] Only one PyPI publish path is used for this version: GitHub Release workflow preferred, no prior manual `twine` upload
- [ ] PyPI publish workflow completed
- [ ] Fresh PyPI install smoke tested
