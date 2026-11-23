"""Run pinned offline scanners on repository source and publish allowlisted metadata."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
import urllib.parse
import uuid
from datetime import datetime, timezone

# Python isolated mode excludes the current project from the module search path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from checks import Client, ORIGIN, can_upload, exchange, github_token

IMAGES = {
    'bandit': 'ghcr.io/pycqa/bandit/bandit@sha256:70c0d5de64db59de9b213348fc2bede3216c55fccb789386efe56440c384b29a',
    'checkov': 'bridgecrew/checkov@sha256:2df9b825a73bf4d09f0ab0d71b12844801454c3c35430162e7e2cf0e60e34e40',
}
FRAMEWORKS = ['terraform', 'cloudformation', 'kubernetes', 'dockerfile', 'github_actions']
LEVELS = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'}


def location(value):
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or '..' in path.parts or not path.parts or len(value) > 4000
            or any(ord(c) < 32 or c in '#?\\' for c in value)):
        raise ValueError('Invalid scanner source path.')
    return str(path)


def finding(kind, rule, severity, path, line=None):
    if not re.fullmatch(r'[a-zA-Z0-9_.:/-]{1,256}', rule):
        raise ValueError('Invalid scanner rule ID.')
    result = {'kind': kind, 'id': rule, 'severity': severity if severity in LEVELS else 'UNKNOWN', 'target': location(path)}
    if type(line) is int and 0 < line < 2**31:
        result['start_line'] = line
    return result


def normalize(tool, report):
    if tool == 'bandit':
        if report['errors'] or not isinstance(report['results'], list):
            raise ValueError('Bandit could not inspect all inputs.')
        findings = [finding('code', r['test_id'], r['issue_severity'], r['filename'], r.get('line_number'))
                    for r in report['results']]
        return findings, bool(report['metrics']['_totals']['loc'] or findings)
    checks = report if isinstance(report, list) else [report]
    findings, examined = [], 0
    for section in checks:
        summary, results = section['summary'], section['results']
        if summary['parsing_errors'] or results.get('parsing_errors'):
            raise ValueError('Checkov could not parse all inputs.')
        if len(results['failed_checks']) != summary['failed']:
            raise ValueError('Incomplete Checkov results.')
        examined += summary['passed'] + summary['failed']
        for r in results['failed_checks']:
            # Checkov prepends a slash to paths relative to its scan root.
            source = r['file_abs_path']
            path = str(PurePosixPath(source).relative_to('/workspace'))
            lines = r.get('file_line_range') or []
            findings.append(finding('misconfiguration', r['check_id'], r.get('severity'), path, lines[0] if lines else None))
    return findings, bool(examined)


def scan(tool, source, scratch):
    args = ['docker', 'run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=256', '--memory=3g', '--cpus=2',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
            '--env', 'HOME=/tmp', '--env', 'LOG_LEVEL=ERROR', '--workdir', '/workspace',
            '--mount', f'type=bind,src={source},dst=/workspace,readonly',
            '--entrypoint', tool, IMAGES[tool]]
    if tool == 'bandit':
        args += ['--ini', '/dev/null', '-r', '.', '-f', 'json', '--exit-zero', '-q']
    else:
        args += ['-d', '.', '--config-file', '/dev/null', '--framework', *FRAMEWORKS, '--skip-download',
                 '--compact', '--soft-fail', '-o', 'json']
    with (scratch / 'report.json').open('w+b') as output:
        subprocess.run(args, stdout=output, stderr=subprocess.DEVNULL, timeout=1200, check=True)
        if output.tell() > 128 * 1024 * 1024:
            raise ValueError('Scanner report exceeds the processing limit.')
        output.seek(0)
        return normalize(tool, json.load(output))


def publish(tool, status, findings, env):
    repo, branch = env['GITHUB_REPOSITORY'], env['CHECKS_DEFAULT_BRANCH']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or not can_upload(env):
        raise ValueError('Only default-branch project jobs may publish.')
    payload = {'schema_version': 1, 'tool': tool, 'status': status, 'findings': findings, 'repository': repo,
               'branch': branch, 'commit': env['GITHUB_SHA'], 'run_id': int(env['GITHUB_RUN_ID']),
               'run_attempt': int(env['GITHUB_RUN_ATTEMPT']), 'scanned_at': datetime.now(timezone.utc).isoformat()}
    if len(findings) > 20000 or len(json.dumps(payload).encode()) > 8 * 1024 * 1024:
        raise ValueError('Snapshot exceeds the Checks upload limit.')
    session = exchange(Client(), github_token(ORIGIN), repo.split('/')[0])
    client = Client(token=session)
    project = client.request('/api/v1/project/lookup?' + urllib.parse.urlencode({'name': repo, 'version': branch}))
    project_id = str(uuid.UUID(project['uuid']))
    result = client.request(f'/api/trivy/v1/projects/{project_id}/tools/{tool}', 'PUT', payload=payload)
    return result.get('stored') is True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', choices=IMAGES)
    tool = parser.parse_args().tool
    if not can_upload(os.environ):
        raise ValueError('Expected a default-branch job.')
    try:
        with TemporaryDirectory(dir=os.environ.get('RUNNER_TEMP')) as temp:
            findings, applicable = scan(tool, Path(os.environ['GITHUB_WORKSPACE']).resolve(), Path(temp))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        publish(tool, 'failed', [], os.environ)
        raise RuntimeError('Scanner failed. A failure snapshot was submitted to Checks.') from None
    if not applicable:
        print(f'{tool}: no applicable inputs were analyzed. No clean report was published.')
        return
    stored = publish(tool, 'completed', findings, os.environ)
    print(f'{tool}: {len(findings)} detections. ' + ('Published to Checks.' if stored else 'Checks already has a newer report.'))


if __name__ == '__main__':
    try:
        main()
    except (KeyError, ValueError, RuntimeError, OSError) as exc:
        # Raw source and scanner output must never enter CI logs.
        print('Checks source analysis failed (' + type(exc).__name__ + ').', file=sys.stderr)
        sys.exit(1)
