# BLA Release Checklist

Use this checklist before publishing a GitHub Release or uploading to PyPI.

## Version

- Confirm the release version in `bla/__version__.py`.
- Confirm `bla --version`, JSON report metadata, SARIF tool metadata, manifest metadata, and README examples show the same version.
- Confirm `pyproject.toml` uses the dynamic version from `bla.__version__.__version__`.
- Confirm `setup.py` reads the same version source.
- Confirm the Git tag is exactly `vX.Y.Z` and matches `bla.__version__`.

## Validation

- Run `python3 scripts/release_check.py` for the local release quality checks.
- Run `python3 scripts/release_check.py --build` before tagging when build/twine are available locally.
- Run `python3 -m compileall -q bla bla_cli.py setup.py tests`.
- Run `python3 -m pytest -q`.
- Run `python3 -m unittest discover -s tests -v`.
- Run `python3 bla_cli.py validate-rules --strict-metadata`.
- Run `python3 bla_cli.py ssh --help`.
- Run `python3 bla_cli.py remote-log --help`.
- Run sample smoke tests with `--exit-on none`, including Linux auth, Web access, Remote Workspace sample, Windows RDP sample, and P0 fixture.
- Confirm `--out` bundles contain `index.html`, `report.json`, `events.csv`, `iocs.txt`, `report.sarif`, and `manifest.json`.
- Run `python3 bla_cli.py benchmark --size-mb 1` and `python3 bla_cli.py benchmark --size-mb 1 --memory`.
- Build the package with `python3 -m build`.
- Run `python3 -m twine check dist/*` when `twine` is available.
- Inspect the wheel for package code/rules (`bla/rules/web_attacks.yaml`, `bla/remote/ssh_workspace.py`) and the source distribution for release notes, scripts, sample logs, and P0 fixtures.
- Install the built wheel in a fresh venv and run `bla --version`, `bla validate-rules --strict-metadata`, `bla ssh --help`, and `bla remote-log --help`.
- Review GitHub Actions annotations for runtime deprecation warnings, especially JavaScript action runtime changes such as the Node.js 24 migration.

## GitHub Release

- Tag the release as `vX.Y.Z`.
- Use the release notes under `docs/releases/` as the body.
- Attach generated wheel and source distribution artifacts.
- Confirm the Release links to the relevant issue or PR.
- Confirm GitHub marks this release as Latest.

## PyPI

- Confirm the package name is `blueteam-log-analyzer`.
- Confirm PyPI Trusted Publishing is configured for this GitHub repository, the `publish.yml` workflow, and the `pypi` GitHub environment.
- Prefer one publish path per version: create the GitHub Release and let the publish workflow upload to PyPI.
- Do not manually upload with `twine` before creating the GitHub Release unless the publish workflow is intentionally skipped.
- After upload, install from PyPI in a fresh environment and run `bla --version`.
- Smoke test `bla validate-rules` from the installed package.
- Smoke test `bla ssh --help`, `bla remote-log --help`, and one local sample analysis from the installed package.
