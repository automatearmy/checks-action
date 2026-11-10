#!/usr/bin/env python3
"""Scan repositories/images and publish inventories using GitHub workload identity."""
import argparse
import base64
import collections
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ORIGIN = 'https://checks.apps.automatearmy.com'
PROVIDER = 'github-actions-checks'
TRIVY = 'aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'
SEVERITIES = {'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}


class ApiError(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(f'Checks API request failed: HTTP {status}')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, origin=ORIGIN, token='', api_key=''):
        p = urllib.parse.urlsplit(origin)
        if (p.scheme != 'https' and not (p.scheme == 'http' and p.hostname in {'localhost', '127.0.0.1', '::1'})
                or not p.hostname or p.username or p.password or p.path not in {'', '/'} or p.query or p.fragment):
            raise ValueError('Checks requires an HTTPS origin; HTTP is limited to local tests.')
        if token and api_key:
            raise ValueError('Choose one authentication method.')
        self.origin, self.token, self.api_key = origin.rstrip('/'), token, api_key

    def request(self, path, method='GET', payload=None, form=None):
        if not path.startswith('/api/'):
            raise ValueError('Expected an API path.')
        headers = {'User-Agent': 'AutomateArmy-Checks/1.0'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        if self.api_key:
            headers['X-Api-Key'] = self.api_key
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        request = urllib.request.Request(self.origin + path, method=method, headers=headers, data=data)
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise ApiError(status) from None
        except (urllib.error.URLError, TimeoutError):
            raise RuntimeError('Checks API connection failed.') from None


def mask(value):
    if not isinstance(value, str) or not value or any(c in value for c in '\r\n'):
        raise ValueError('Invalid authentication token.')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        print('::add-mask::' + value, flush=True)
    return value


def github_token(audience):
    endpoint = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
    bearer = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    parsed = urllib.parse.urlsplit(endpoint)
    if (not bearer or parsed.scheme != 'https' or not parsed.hostname
            or not parsed.hostname.endswith('.actions.githubusercontent.com')
            or parsed.username or parsed.password or parsed.fragment):
        raise RuntimeError('GitHub OIDC is unavailable. Set permissions: id-token: write.')
    query = urllib.parse.parse_qsl(parsed.query) + [('audience', audience)]
    endpoint = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    req = urllib.request.Request(endpoint, headers={'Authorization': 'Bearer ' + bearer,
                                                   'User-Agent': 'AutomateArmy-Checks/1.0'})
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
            return mask(json.load(response)['value'])
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError):
        raise RuntimeError('GitHub OIDC token request failed.') from None


def account(owner):
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})', owner):
        raise ValueError('Invalid GitHub owner.')
    return owner.lower() + '-checks'


def exchange(client, subject, owner):
    result = client.request('/api/v2/oauth/token', 'POST', form={
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
        'subject_token': subject, 'workload_identity_provider': PROVIDER, 'service_account': account(owner)})
    if result.get('token_type') != 'Bearer':
        raise RuntimeError('Checks returned an invalid token type.')
    return mask(result['access_token'])


def upload(client, bom, repository, version, *, interval=3, timeout=600):
    payload = {'projectName': repository, 'projectVersion': version, 'autoCreate': True,
               'isLatest': True, 'bom': base64.b64encode(bom).decode()}
    result = client.request('/api/v1/bom', 'PUT', payload=payload)
    token = str(uuid.UUID(result['token']))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = client.request('/api/v1/bom/token/' + token)
        if type(status.get('processing')) is not bool:
            raise RuntimeError('Checks returned an invalid processing status.')
        if status.get('status') == 'FAILED':
            raise RuntimeError('Checks SBOM processing failed; check server workflow logs.')
        if status['processing'] is False and status.get('status') == 'COMPLETED':
            return
        time.sleep(interval)
    raise RuntimeError('Checks SBOM processing timed out.')


def can_upload(env):
    branch = env.get('CHECKS_DEFAULT_BRANCH', '')
    return (bool(branch) and env.get('GITHUB_EVENT_NAME') in {'push', 'workflow_dispatch', 'schedule'}
            and env.get('GITHUB_REF') == 'refs/heads/' + branch)


def summarize(report):
    summary = {name: collections.Counter() for name in ['vulnerabilities', 'misconfigurations', 'secrets']}
    for result in report.get('Results', []):
        for key, name in [('Vulnerabilities', 'vulnerabilities'), ('Misconfigurations', 'misconfigurations'), ('Secrets', 'secrets')]:
            for finding in result.get(key, []):
                if name == 'misconfigurations' and finding.get('Status') != 'FAIL':
                    continue
                summary[name][finding['Severity']] += 1
    return summary


def findings_snapshot(report, env):
    """Publish an allowlist of metadata, never raw code, secret matches or snippets."""
    findings = []
    for result in report.get('Results', []):
        for key, kind in [('Vulnerabilities', 'vulnerability'), ('Misconfigurations', 'misconfiguration'),
                          ('Secrets', 'secret')]:
            for finding in result.get(key, []):
                if kind == 'misconfiguration' and finding.get('Status') != 'FAIL':
                    continue
                item = {'kind': kind, 'severity': finding.get('Severity', 'UNKNOWN'),
                        'target': str(result.get('Target', ''))[:4000]}
                fields = {'id': 'VulnerabilityID' if kind == 'vulnerability' else 'ID',
                          'title': 'Title', 'description': 'Description', 'url': 'PrimaryURL',
                          'resolution': 'Resolution', 'package': 'PkgName',
                          'installed_version': 'InstalledVersion', 'fixed_version': 'FixedVersion'}
                if kind == 'secret':
                    fields = {'id': 'RuleID'}
                    item['title'] = 'Secret detected (value redacted)'
                for name, source in fields.items():
                    if finding.get(source):
                        item[name] = str(finding[source])[:4000]
                location = finding.get('CauseMetadata', {}) if kind == 'misconfiguration' else finding
                for name, source in [('start_line', 'StartLine'), ('end_line', 'EndLine')]:
                    if type(location.get(source)) is int and location[source] > 0:
                        item[name] = location[source]
                findings.append(item)
    return {'schema_version': 1, 'repository': env['GITHUB_REPOSITORY'],
            'branch': env['CHECKS_DEFAULT_BRANCH'], 'commit': env['GITHUB_SHA'],
            'run_id': int(env['GITHUB_RUN_ID']), 'run_attempt': int(env.get('GITHUB_RUN_ATTEMPT', '1')),
            'scanned_at': datetime.now(timezone.utc).isoformat(), 'findings': findings}


def upload_findings(client, project_id, snapshot):
    client.request('/api/trivy/v1/projects/' + str(uuid.UUID(project_id)), 'PUT', payload=snapshot)


def gate_failed(summary, severities):
    if severities.upper() == 'NONE':
        return False
    selected = {s.strip().upper() for s in severities.split(',')}
    if not selected or not selected <= SEVERITIES:
        raise ValueError('fail-on must contain severity names or NONE.')
    return any(count for counts in summary.values() for severity, count in counts.items() if severity in selected)


def scan(mode, target, directory):
    cache_root = Path(os.environ['RUNNER_TEMP']) if os.environ.get('RUNNER_TEMP') else Path.home()
    cache = cache_root / '.cache/aarmy-checks-trivy'
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    base = ['docker', 'run', '--rm', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--user', f'{os.getuid()}:{os.getgid()}', '--env', 'HOME=/tmp',
            '--mount', f'type=bind,src={directory},dst=/reports',
            '--mount', f'type=bind,src={cache},dst=/tmp/trivy-cache']
    for name in ['TRIVY_USERNAME', 'TRIVY_PASSWORD']:
        if os.environ.get(name):
            base += ['--env', name]
    options = ['--timeout', '15m', '--cache-dir', '/tmp/trivy-cache']
    if mode == 'fs':
        source = Path(target).resolve(strict=True)
        if not source.is_dir():
            raise ValueError('Filesystem target must be a directory.')
        if os.environ.get('GITHUB_WORKSPACE'):
            source.relative_to(Path(os.environ['GITHUB_WORKSPACE']).resolve())
        base += ['--mount', f'type=bind,src={source},dst=/source,readonly']
        target = '/source'
        options += ['--skip-dirs', '/source/.git', '--skip-dirs', '/source/node_modules', '--skip-dirs', '/source/reports']
    else:
        options += ['--image-src', 'remote']
    for format_name, scanners, filename in [('json', 'vuln,misconfig,secret', 'trivy.json'),
                                          ('cyclonedx', 'vuln', 'bom.cdx.json')]:
        subprocess.run(base + [TRIVY, mode] + options + ['--scanners', scanners, '--format', format_name,
                       '--output', '/reports/' + filename, '--', target], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['fs', 'image'], default='fs')
    parser.add_argument('--target', default='.')
    parser.add_argument('--fail-on', default='HIGH,CRITICAL')
    parser.add_argument('--upload', choices=['true', 'false'], default='false')
    args = parser.parse_args()
    gate_failed({}, args.fail_on)
    if args.upload == 'true' and not can_upload(os.environ):
        raise RuntimeError('Uploads are allowed only on the default branch for push, manual, or scheduled runs.')
    directory = Path(tempfile.mkdtemp(prefix='aarmy-checks-', dir=os.environ.get('RUNNER_TEMP') or None))
    scan(args.mode, args.target, directory)
    report = json.loads((directory / 'trivy.json').read_text())
    summary = summarize(report)
    print('Findings by severity: ' + json.dumps(summary))
    uploaded = False
    if args.upload == 'true':
        repository = os.environ['GITHUB_REPOSITORY']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('Invalid GitHub repository.')
        session = exchange(Client(), github_token(ORIGIN), repository.split('/')[0])
        client = Client(token=session)
        upload(client, (directory / 'bom.cdx.json').read_bytes(), repository, os.environ['CHECKS_DEFAULT_BRANCH'])
        query = urllib.parse.urlencode({'name': repository, 'version': os.environ['CHECKS_DEFAULT_BRANCH']})
        project = client.request('/api/v1/project/lookup?' + query)
        project_id = str(uuid.UUID(project['uuid']))
        upload_findings(client, project_id, findings_snapshot(report, os.environ))
        uploaded = True
        print('SBOM and sanitized Trivy findings processed by Checks. Project: ' + project_id)
    else:
        project_id = ''
        print('Local scan completed; upload disabled for this run.')
    result = {'repository': os.environ.get('GITHUB_REPOSITORY', ''), 'commit': os.environ.get('GITHUB_SHA', ''),
              'project_uuid': project_id, 'uploaded': uploaded, 'findings': summary}
    (directory / 'summary.json').write_text(json.dumps(result, indent=2))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write(f'project-uuid={project_id}\nuploaded={str(uploaded).lower()}\n')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
            link = ORIGIN + '/projects/' + project_id if uploaded else ORIGIN
            output.write(f'### Automate Army Checks\n\n[Dashboard]({link}) · SBOM and Trivy findings uploaded: {uploaded}\n\n')
            output.write('| Finding | Critical | High | Medium | Low |\n|---|---:|---:|---:|---:|\n')
            for name, counts in summary.items():
                output.write(f'| {name} | ' + ' | '.join(str(counts.get(s, 0)) for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) + ' |\n')
    print('Private reports: ' + str(directory))
    return 1 if gate_failed(summary, args.fail_on) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(2)
