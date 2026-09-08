# Releasing

Publishing is automated. A single tag publishes both the Python package and
the VS Code extension.

## Release a new version

```bash
python scripts/set_version.py 0.2.0
git commit -am "release: 0.2.0"
git push

git tag v0.2.0
git push origin v0.2.0
```

The `Release` workflow then:

1. Verifies the tag matches the version in the files, and runs the smoke test
2. Publishes to PyPI
3. Publishes to the VS Code Marketplace
4. Creates a GitHub release with generated notes

Step 3 depends on step 2, because the extension runs `uvx idengraph` and would
fail for every user if the package did not yet exist.

If the tag and the file versions disagree, the workflow fails before publishing
anything — a mismatched tag would otherwise publish the wrong version under the
right name.

## One-time setup

### PyPI (no token required)

PyPI Trusted Publishing authenticates GitHub Actions over OIDC, so no API token
is stored anywhere. Configure it once at
<https://pypi.org/manage/project/idengraph/settings/publishing/>:

| Field | Value |
|---|---|
| Owner | `josimarh` |
| Repository name | `idengraph` |
| Workflow name | `release.yml` |
| Environment name | `release` |

### VS Code Marketplace

The Marketplace has no OIDC equivalent, so it needs a stored token:

```powershell
.\setup_github_secrets.ps1
```

Create the token at <https://dev.azure.com/josimarh/_usersSettings/tokens> with
**All accessible organizations** and the **Marketplace → Manage** scope. That
scope only appears after clicking *Show all scopes*.

Re-run the script when the token expires. Nothing else needs to change.

## Version numbers

`pyproject.toml` and `extension/package.json` must always agree.
`scripts/set_version.py` writes both, and CI fails if they drift:

```bash
python scripts/set_version.py --check
```

They drifted once before this was enforced — the package sat at `0.1.0` while
the extension was already at `0.1.2`.

## Manual publishing

Only needed if GitHub Actions is unavailable. Prefer the automated path: the
manual scripts handle tokens on your local machine, which is how a token once
ended up inside a published artifact.
