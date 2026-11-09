#!/usr/bin/env python3
"""One-time setup for each GitHub owner (organization or user), run by a Checks administrator."""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse

from checks import PROVIDER, ORIGIN, ApiError, Client, account

WORKFLOW_REPO = 'automatearmy/checks-action'


def bindings(owner, owner_id, commits, workflow_repo=WORKFLOW_REPO):
    if (not re.fullmatch(r'[A-Za-z0-9-]+', owner) or not re.fullmatch(r'[0-9]+', owner_id)
            or not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', workflow_repo)
            or not commits or any(not re.fullmatch(r'[0-9a-f]{40}', sha) for sha in commits)):
        raise ValueError('Supply an owner, numeric owner ID, workflow repository, and full reviewed workflow SHAs.')
    rule = (f'claims.repository_owner_id == {json.dumps(owner_id)} && '
            f'claims.job_workflow_ref.startsWith({json.dumps(workflow_repo + "/.github/workflows/scan.yml@")}) && '
            f'claims.job_workflow_sha in {json.dumps(sorted(set(commits)))} && '
            'claims.event_name in ["push", "schedule", "workflow_dispatch"]')
    if len(rule) > 2048:
        raise ValueError('Too many trusted releases for one binding.')
    return [{'provider_name': PROVIDER, 'subject': subject, 'condition': rule}
            for subject in [f'repo:{owner}/*', f'repo:{owner}@{owner_id}/*']]


def configure(client, owner, owner_id, commits, workflow_repo=WORKFLOW_REPO):
    wanted = bindings(owner, owner_id, commits, workflow_repo)
    service_account = account(owner)
    provider_path = '/api/v2/workload-identity-providers/' + PROVIDER
    provider = {'name': PROVIDER, 'type': 'OIDC', 'issuer': 'https://token.actions.githubusercontent.com',
                'audience': client.origin, 'session_lifetime_seconds': 900}
    try:
        current = client.request(provider_path)
    except ApiError as exc:
        if exc.status != 404:
            raise
        client.request('/api/v2/workload-identity-providers', 'POST', payload=provider)
    else:
        if any(current.get(k) != v for k, v in provider.items()):
            raise RuntimeError('Existing identity provider differs; inspect it before replacing it.')
    account_path = '/api/v2/service-accounts/' + service_account
    try:
        svc = client.request(account_path)
    except ApiError as exc:
        if exc.status != 404:
            raise
        client.request('/api/v2/service-accounts', 'POST', payload={'name': service_account})
        svc = {'permissions': [], 'teams': []}
    required = {'BOM_UPLOAD', 'PROJECT_CREATION_UPLOAD', 'VIEW_PORTFOLIO'}
    if svc.get('suspended') or svc.get('teams') or set(svc.get('permissions', [])) - required:
        raise RuntimeError('Existing automation account has unexpected membership or privileges.')
    for permission in sorted(required - set(svc.get('permissions', []))):
        username = urllib.parse.quote('svc:' + service_account, safe='')
        try:
            client.request('/api/v1/permission/' + permission + '/user/' + username, 'POST')
        except ApiError as exc:
            if exc.status != 304:
                raise
    path = account_path + '/workload-identity-bindings'
    current = client.request(path + '?limit=1000')['items']
    # Only manage this dedicated account, never unrelated accounts or providers.
    wanted_subjects = {item['subject'] for item in wanted}
    if any(item['provider_name'] != PROVIDER or item['subject'] not in wanted_subjects for item in current):
        raise RuntimeError('Existing automation account has unexpected identity bindings.')
    for item in wanted:
        matches = [x for x in current if x['subject'] == item['subject']]
        if len(matches) == 1 and matches[0].get('condition') == item['condition']:
            continue
        for existing in matches:
            client.request(path + '/' + existing['uuid'], 'DELETE')
        client.request(path, 'POST', payload=item)
    print(f'{owner} connected with GitHub OIDC as {service_account}. No CI API key was created.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', '--organization', dest='owner', default='automatearmy',
                        help='GitHub organization or user whose repositories may upload.')
    parser.add_argument('--workflow-repo', default=WORKFLOW_REPO,
                        help='Repository hosting the approved scan.yml (a mirror when the caller cannot reach this one).')
    parser.add_argument('--trusted-workflow-sha', action='append', required=True)
    parser.add_argument('--apply', action='store_true', help='Apply the reviewed organization configuration.')
    args = parser.parse_args()
    owner_id = subprocess.check_output(['gh', 'api', 'users/' + args.owner, '--jq', '.id'], text=True).strip()
    plan = bindings(args.owner, owner_id, args.trusted_workflow_sha, args.workflow_repo)
    if not args.apply:
        print(json.dumps({'origin': ORIGIN, 'service_account': account(args.owner), 'bindings': plan}, indent=2))
        return
    key, token = os.environ.get('CHECKS_ADMIN_KEY', ''), os.environ.get('CHECKS_ADMIN_TOKEN', '')
    if not (key or token):
        raise ValueError('An administrator must supply CHECKS_ADMIN_KEY or CHECKS_ADMIN_TOKEN for this one-time setup.')
    configure(Client(token=token, api_key=key), args.owner, owner_id, args.trusted_workflow_sha, args.workflow_repo)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(2)
