# BLA Release Checklist

Use this checklist before publishing a GitHub Release or uploading to PyPI.

## Version

- Confirm the release version in `bla/__version__.py`.
- Confirm `bla --version`, JSON report metadata, SARIF tool metadata, and README examples show the same version.
- Confirm `pyproject.toml` uses the dynamic version from `bla.__version__.__version__`.
- Confirm `setup.py` reads the same version source.

## Validation

- Run `python3 -m compileall -q bla bla_cli.py setup.py tests`.
- Run `python3 -m unittest discover -s tests -v`.
- Run `python3 bla_cli.py validate-rules --strict-metadata`.
- Run sample smoke tests with `--exit-on none`.
- Build the package with `python3 -m build`.
- Inspect the wheel and source distribution for `bla/rules/web_attacks.yaml`.

## GitHub Release

- Tag the release as `vX.Y.Z`.
- Use the release notes under `docs/releases/` as the body.
- Attach generated wheel and source distribution artifacts.
- Confirm the Release links to the relevant issue or PR.

## PyPI

- Confirm the package name is `blueteam-log-analyzer`.
- Confirm PyPI Trusted Publishing is configured for this GitHub repository, the `publish.yml` workflow, and the `pypi` GitHub environment.
- Publish by creating the GitHub Release, or run the publish workflow manually after the release has been validated.
- After upload, install from PyPI in a fresh environment and run `bla --version`.
- Smoke test `bla validate-rules` from the installed package.
