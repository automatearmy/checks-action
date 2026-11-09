# Automate Army Checks

Connect a project to [Checks](https://checks.apps.automatearmy.com/) by adding
a workflow. Trivy scans dependencies, configuration, and secrets, then uploads
the SBOM to Dependency-Track using short-lived GitHub OIDC authentication.

## Connect a project

In an `automatearmy` organization repository, create `.github/workflows/checks.yml`:

```yaml
name: Checks
on: [push, pull_request, workflow_dispatch]
permissions:
  contents: read
  id-token: write
jobs:
  security:
    uses: automatearmy/checks-action/.github/workflows/scan.yml@v1
```

You do not need a project UUID, an API secret, or an agent installed on your server.
The first run on the default branch automatically creates the `OWNER/REPO`
project. Each subsequent run updates that branch's inventory. GitHub records
the commit and displays the findings in the run summary.

You can also generate the workflow after cloning this repository:

```sh
python3 /path/to/checks-action/scripts/connect.py --project-dir /path/to/project
```

The installer preserves existing workflows and refuses to overwrite `checks.yml`.
To pin a reviewed release, add `--ref FULL_RELEASE_COMMIT_SHA`.
It does not use `curl | bash` or require an administrator credential in the project.

## Run on Carini

Checks uses the organization's Carini runner by default. You do not need to set
`runs_on` in the calling workflow. To use a GitHub-hosted runner instead:

```yaml
jobs:
  security:
    uses: automatearmy/checks-action/.github/workflows/scan.yml@v1
    with:
      runs_on: ubuntu-latest
```

Omit `runs_on` to keep the default `carini`. The workflow still runs through
GitHub Actions, with the same OIDC authentication, severity gate, and dashboard
uploads. The calling repository must have access to an available runner labelled
`carini`, running Linux with Python 3 and Docker available to the runner user.
For runners inside containers, `GITHUB_WORKSPACE` and `RUNNER_TEMP` must be shared
with the Docker host at the same paths. Reports and the scan cache use
`RUNNER_TEMP` when it is available.

## Behavior

- Pushes, manual runs, and scheduled runs on the default branch scan the project,
  authenticate through OIDC, create or update its inventory, and wait for analysis.
- Pull requests and other branches run a local scan and enforce the severity gate.
  They do not request a Checks OIDC token or update the default branch's inventory.
- The default gate blocks `HIGH` and `CRITICAL` vulnerabilities, misconfigurations,
  and secrets. The SBOM is uploaded before the gate runs, so findings reach the
  dashboard even when the job fails.
- Only the SBOM is uploaded. Source code and raw secret findings stay in a private
  directory on the runner. They are not published as artifacts or printed in logs.
- The client fails on network errors, processing failures, or a ten-minute timeout.
  A completed upload does not guarantee that all vulnerability sources are current.
- Linux runners with Docker and Python 3 are required. The workflow defaults to
  `carini`; use `runs_on: ubuntu-latest` to select a GitHub-hosted runner.
  Images are read from their registry without mounting the Docker socket inside the scanner.

To scan a published image instead of source code:

```yaml
jobs:
  security:
    uses: automatearmy/checks-action/.github/workflows/scan.yml@v1
    with:
      mode: image
      target: ghcr.io/automatearmy/my-project:version
    # For a private registry, pass read-only credentials:
    # secrets:
    #   registry-username: ${{ secrets.REGISTRY_USERNAME }}
    #   registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

Inputs: `runs_on` (default: `carini`; use `ubuntu-latest` for a GitHub-hosted runner),
`mode` (`fs` or `image`), `target` (default: `.`), and `fail-on` (default:
`HIGH,CRITICAL`; use `NONE` explicitly for a non-blocking scan).
Uploads follow the same default-branch rule.

## One-time organization setup

This step is for Checks administrators. Connected projects do not repeat this
process and never receive the administrator credential.

1. Allow organization repositories to use this private action under
   Settings → Actions → General → Access, or through the GitHub API.
2. Supply `CHECKS_ADMIN_KEY` or `CHECKS_ADMIN_TOKEN` in the operator's environment
   with `ACCESS_MANAGEMENT` permission. Never put its value in command arguments or Git.
3. Review the release and register its full commit SHA:

```sh
python3 scripts/configure.py --trusted-workflow-sha FULL_COMMIT_SHA
python3 scripts/configure.py --trusted-workflow-sha FULL_COMMIT_SHA --apply
```

Setup registers the official GitHub issuer, an audience unique to Checks,
15-minute sessions, and a service account with `BOM_UPLOAD`,
`PROJECT_CREATION_UPLOAD`, and `VIEW_PORTFOLIO`. It does not create an API key for that account.
Trust rules validate the organization's numeric ID, the workflow path, and the
exact approved release SHA. Both legacy and immutable `sub` formats are supported.
A workflow copied or modified in another repository cannot obtain this identity.

When upgrading, repeat `--trusted-workflow-sha` for each release that should remain
authorized. The command is idempotent and rejects existing providers or accounts
with incompatible configuration. After setup, discard the operator's temporary
credential. People continue signing in to the dashboard through Google SSO.

The shared identity serves organization projects; it is not a separate identity
for each project. The approved workflow sets the project name from the calling
repository. Project isolation requires dedicated accounts and ACLs.

## Use outside the automatearmy organization

Any GitHub organization or personal account can upload to Checks once an
administrator registers it. Each owner gets a dedicated service account
(`<owner>-checks`) whose trust rule pins that owner's numeric ID, so registering
another owner never changes the `automatearmy-checks` account.

This repository is private, and GitHub only lets repositories in the same
organization or enterprise call it. External owners therefore host a mirror:

```sh
gh repo create OWNER/checks-action --private
git clone https://github.com/automatearmy/checks-action && cd checks-action
sed -i 's#uses: automatearmy/checks-action@#uses: OWNER/checks-action@#' .github/workflows/scan.yml
git commit -am "build: run Checks from the OWNER mirror"
git push https://github.com/OWNER/checks-action HEAD:main
git tag v1 && git push https://github.com/OWNER/checks-action v1
git rev-parse HEAD   # the SHA to trust below
```

In the mirror, allow access under Settings → Actions → General → Access
(for a personal account: "Accessible from repositories owned by the user").
Use `runs_on: ubuntu-latest` unless the owner has its own `carini` runner.

A Checks administrator then reviews the mirror commit and registers the owner:

```sh
python3 scripts/configure.py --owner OWNER --workflow-repo OWNER/checks-action \
  --trusted-workflow-sha MIRROR_COMMIT_SHA          # prints the plan
python3 scripts/configure.py --owner OWNER --workflow-repo OWNER/checks-action \
  --trusted-workflow-sha MIRROR_COMMIT_SHA --apply
```

Projects of that owner connect with:

```sh
python3 scripts/connect.py --project-dir /path/to/project --workflow-repo OWNER/checks-action
```

If this repository is made public or shared through an enterprise, skip the mirror:
omit `--workflow-repo` and the owner calls `automatearmy/checks-action` directly.

Service accounts are not isolated by default: each one can view the whole portfolio
and upload to any project name. Register only trusted owners, or enable
Dependency-Track portfolio access control before onboarding third parties.

## Development

```sh
python3 -m unittest discover -s tests -v
```

The `Integration smoke test` workflow runs the real OIDC integration on demand.
You can run a local scan without authentication:

```sh
python3 scripts/checks.py --target /path/to/project --upload false
```

Implementation references: [Dependency-Track 5.2 workload identity](https://dependencytrack.github.io/docs/next/guides/administration/configuring-workload-identity-federation/),
[GitHub Actions OIDC](https://docs.github.com/en/actions/reference/security/oidc),
[Trivy SBOM](https://trivy.dev/docs/latest/guide/supply-chain/sbom/).
