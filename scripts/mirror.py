#!/usr/bin/env python3
"""Publish a private Checks mirror for a GitHub owner outside automatearmy."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

UPSTREAM = 'automatearmy/checks-action'
ACTION_USE = re.compile(r'uses: automatearmy/checks-action@[0-9a-f]{40}')
WORKFLOW_USE = re.compile(r'uses: automatearmy/checks-action/')


def rewrite(text, owner, source_sha):
    if not re.fullmatch(r'[A-Za-z0-9-]+', owner) or not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('Supply a GitHub owner and a full source commit SHA.')
    text = ACTION_USE.sub(f'uses: {owner}/checks-action@{source_sha}', text)
    return WORKFLOW_USE.sub(f'uses: {owner}/checks-action/', text)


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True).stdout.strip()


def publish(owner, ref, tag):
    root = Path(__file__).resolve().parents[1]
    source_sha = run('git', 'rev-parse', ref + '^{commit}', cwd=root)
    target = f'{owner}/checks-action'
    kind = json.loads(run('gh', 'api', 'users/' + owner))['type']
    if subprocess.run(['gh', 'repo', 'view', target], capture_output=True).returncode != 0:
        run('gh', 'repo', 'create', target, '--private', '--description', 'Mirror of ' + UPSTREAM)
    with tempfile.TemporaryDirectory() as work:
        run('git', 'clone', '--quiet', '--no-local', str(root), work)
        run('git', 'checkout', '--quiet', '--detach', source_sha, cwd=work)
        workflows = Path(work, '.github/workflows')
        for path in workflows.glob('*.yml'):
            path.write_text(rewrite(path.read_text(), owner, source_sha))
        run('git', 'add', '-A', cwd=work)
        run('git', '-c', 'user.name=Checks mirror', '-c', 'user.email=checks-mirror@users.noreply.github.com',
            'commit', '--quiet', '-m', f'build: run Checks from {target}', cwd=work)
        mirror_sha = run('git', 'rev-parse', 'HEAD', cwd=work)
        run('git', 'tag', tag, cwd=work)
        remote = run('gh', 'repo', 'view', target, '--json', 'url', '--jq', '.url') + '.git'
        # Never force: an existing tag must be moved deliberately after review.
        run('git', '-c', 'credential.helper=', '-c', 'credential.helper=!gh auth git-credential',
            'push', '--quiet', remote, 'HEAD:refs/heads/main', 'refs/tags/' + tag, cwd=work)
    level = 'organization' if kind == 'Organization' else 'user'
    run('gh', 'api', '-X', 'PUT', f'repos/{target}/actions/permissions/access', '-f', 'access_level=' + level)
    return source_sha, mirror_sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', required=True, help='GitHub organization or user that will host the mirror.')
    parser.add_argument('--ref', default='HEAD', help='Reviewed upstream commit or tag to mirror.')
    parser.add_argument('--tag', default='v1')
    args = parser.parse_args()
    if args.owner.lower() == 'automatearmy':
        raise ValueError('automatearmy repositories use the upstream workflow directly.')
    source_sha, mirror_sha = publish(args.owner, args.ref, args.tag)
    print(f'Mirror ready: {args.owner}/checks-action@{args.tag} ({mirror_sha}), built from {source_sha}.')
    print('A Checks administrator registers the owner once, after reviewing the mirror commit:')
    print(f'  python3 scripts/configure.py --owner {args.owner} --workflow-repo {args.owner}/checks-action '
          f'--trusted-workflow-sha {mirror_sha} --apply')
    print(f'Then each repository adds .github/workflows/checks.yml with:\n'
          f'    uses: {args.owner}/checks-action/.github/workflows/scan.yml@{args.tag}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, 'stderr', '') or ''
        print(f'Error: {exc} {detail}'.strip(), file=sys.stderr)
        sys.exit(2)
