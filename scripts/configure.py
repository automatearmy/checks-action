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


def bindings(owner, owner_id, commits, self_hosted=False, repository_ids=()):
    if (not re.fullmatch(r'[A-Za-z0-9-]+', owner) or not re.fullmatch(r'[0-9]+', owner_id)
            or not commits or any(not re.fullmatch(r'[0-9a-f]{40}', sha) for sha in commits)
            or any(not re.fullmatch(r'[0-9]+', rid) for rid in repository_ids)):
        raise ValueError('Supply an owner, numeric owner ID, and full reviewed workflow SHAs.')
    rule = (f'claims.repository_owner_id == {json.dumps(owner_id)} && '
            'claims.job_workflow_ref.startsWith("automatearmy/checks-action/.github/workflows/scan.yml@") && '
            f'claims.job_workflow_sha in {json.dumps(sorted(set(commits)))} && '
            'claims.event_name in ["push", "schedule", "workflow_dispatch"]')
    if repository_ids:
        rule += f' && claims.repository_id in {json.dumps(sorted(set(repository_ids)))}'
    if not self_hosted:
        # A self-hosted runner belongs to the caller, who could read the session token from memory.
        rule += ' && claims.runner_environment == "github-hosted"'
    if len(rule) > 2048:
        raise ValueError('Too many trusted releases for one binding.')
    return [{'provider_name': PROVIDER, 'subject': subject, 'condition': rule}
            for subject in [f'repo:{owner}/*', f'repo:{owner}@{owner_id}/*']]


def configure(client, owner, owner_id, commits, self_hosted=False, repository_ids=()):
    wanted = bindings(owner, owner_id, commits, self_hosted, repository_ids)
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
    teams = {t if isinstance(t, str) else t.get('name') for t in svc.get('teams') or []}
    if svc.get('suspended') or teams - {service_account} or set(svc.get('permissions', [])) - required:
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
    isolate(client, owner, service_account, service_account in teams)
    print(f'{owner} connected with GitHub OIDC as {service_account}. No CI API key was created.')


def isolate(client, owner, service_account, is_member):
    # Under portfolio access control a service account reaches only projects whose ACL lists its team,
    # and projects it creates get its first team, so each owner gets exactly one dedicated team.
    team = next((t for t in client.request('/api/v1/team') if t.get('name') == service_account), None)
    if team is None:
        team = client.request('/api/v1/team', 'PUT', payload={'name': service_account})
    others = [m for m in team.get('serviceAccounts') or [] if m.get('name', m.get('username')) not in (service_account, 'svc:' + service_account)]
    if others or any(team.get(k) for k in ['permissions', 'apiKeys', 'managedUsers', 'ldapUsers', 'oidcUsers',
                                             'mappedLdapGroups', 'mappedOidcGroups']):
        raise RuntimeError(f'Team {service_account} has unexpected members, keys, or permissions.')
    if not is_member:
        username = urllib.parse.quote('svc:' + service_account, safe='')
        client.request('/api/v1/user/' + username + '/membership', 'POST', payload={'uuid': team['uuid']})
    granted = {p['uuid'] for p in client.request('/api/v1/acl/team/' + team['uuid']) or []}
    prefix, page = owner.lower() + '/', 1
    while True:
        projects = client.request(f'/api/v1/project?pageSize=100&pageNumber={page}&excludeInactive=false') or []
        for project in projects:
            if project['name'].lower().startswith(prefix) and project['uuid'] not in granted:
                client.request('/api/v1/acl/mapping', 'PUT', payload={'team': team['uuid'], 'project': project['uuid']})
        if len(projects) < 100:
            return
        page += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', '--organization', dest='owner', default='automatearmy',
                        help='GitHub organization or user whose repositories may upload.')
    parser.add_argument('--trusted-workflow-sha', action='append', required=True)
    parser.add_argument('--allow-self-hosted', action='store_true',
                        help='Trust self-hosted runners such as carini; only for owners that run their own trusted runners.')
    parser.add_argument('--repository', action='append', default=[], metavar='OWNER/REPO',
                        help='Limit uploads to these repositories of the owner; omit to allow all of them.')
    parser.add_argument('--apply', action='store_true', help='Apply the reviewed organization configuration.')
    args = parser.parse_args()
    owner_id = subprocess.check_output(['gh', 'api', 'users/' + args.owner, '--jq', '.id'], text=True).strip()
    repository_ids = []
    for repository in args.repository:
        if not re.fullmatch(rf'{re.escape(args.owner)}/[A-Za-z0-9_.-]+', repository, re.IGNORECASE):
            raise ValueError(f'{repository} is not a repository of {args.owner}.')
        repository_ids.append(subprocess.check_output(['gh', 'api', 'repos/' + repository, '--jq', '.id'], text=True).strip())
    plan = bindings(args.owner, owner_id, args.trusted_workflow_sha, args.allow_self_hosted, repository_ids)
    if not args.apply:
        print(json.dumps({'origin': ORIGIN, 'service_account': account(args.owner), 'bindings': plan}, indent=2))
        return
    key, token = os.environ.get('CHECKS_ADMIN_KEY', ''), os.environ.get('CHECKS_ADMIN_TOKEN', '')
    if not (key or token):
        raise ValueError('An administrator must supply CHECKS_ADMIN_KEY or CHECKS_ADMIN_TOKEN for this one-time setup.')
    configure(Client(token=token, api_key=key), args.owner, owner_id, args.trusted_workflow_sha,
              args.allow_self_hosted, repository_ids)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(2)
