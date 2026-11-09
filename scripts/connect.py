#!/usr/bin/env python3
"""Install the Checks workflow in a project; never overwrite an existing workflow."""
import argparse
from pathlib import Path
import re
import sys


def workflow(ref='v1'):
    if not re.fullmatch(r'v[0-9]+(?:\.[0-9]+){0,2}|[0-9a-f]{40}', ref):
        raise ValueError('Use a release tag or a full reviewed commit SHA.')
    return '''name: Checks
on:
  push:
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
  id-token: write
jobs:
  security:
    uses: automatearmy/checks-action/.github/workflows/scan.yml@''' + ref + '\n'


def install(directory, ref='v1'):
    text = workflow(ref)
    directory = Path(directory).resolve(strict=True)
    if not directory.is_dir():
        raise ValueError('Project directory is invalid.')
    path = directory / '.github/workflows/checks.yml'
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', default='.')
    parser.add_argument('--ref', default='v1')
    args = parser.parse_args()
    try:
        print('Created: ' + str(install(args.project_dir, args.ref)))
        print('Commit and push the workflow to start Checks. No project UUID or API key is needed.')
    except (ValueError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(2)
