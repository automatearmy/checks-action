import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('checks', Path(__file__).resolve().parents[1] / 'scripts/checks.py')
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)

    def test_snapshot_includes_all_kinds_without_code_or_secret_matches(self):
        report = {'Results': [{'Target': 'infra/main.tf',
            'Misconfigurations': [
                {'ID': 'AVD-AWS-0082', 'Severity': 'HIGH', 'Status': 'FAIL', 'Title': 'Public database',
                 'Description': 'Database is public', 'Resolution': 'Restrict access',
                 'PrimaryURL': 'https://avd.aquasec.com/misconfig/avd-aws-0082',
                 'CauseMetadata': {'StartLine': 12, 'EndLine': 15, 'Code': {'Lines': ['private-source']}}},
                {'ID': 'passed', 'Severity': 'HIGH', 'Status': 'PASS'}],
            'Secrets': [{'RuleID': 'aws-key', 'Severity': 'CRITICAL', 'Title': 'AWS key',
                         'Match': 'private-secret', 'Code': 'private-source', 'StartLine': 20}],
            'Vulnerabilities': [{'VulnerabilityID': 'CVE-2026-1234', 'Severity': 'MEDIUM',
                                 'PkgName': 'example', 'InstalledVersion': '1', 'FixedVersion': '2'}]}]}
        env = {'GITHUB_REPOSITORY': 'boiseilabs/Good-Impulse', 'CHECKS_DEFAULT_BRANCH': 'main',
               'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        snapshot = self.m.findings_snapshot(report, env)
        self.assertEqual(snapshot['repository'], env['GITHUB_REPOSITORY'])
        self.assertEqual({f['kind'] for f in snapshot['findings']}, {'misconfiguration', 'vulnerability', 'secret'})
        self.assertEqual(len(snapshot['findings']), 3)
        config = next(f for f in snapshot['findings'] if f['kind'] == 'misconfiguration')
        self.assertEqual((config['id'], config['start_line'], config['resolution']), ('AVD-AWS-0082', 12, 'Restrict access'))
        self.assertNotIn('private-secret', json.dumps(snapshot))
        self.assertNotIn('private-source', json.dumps(snapshot))

    def test_upload_uses_existing_bearer_session_and_project_endpoint(self):
        from test_checks import server
        snapshot = {'findings': []}
        def respond(method, path, headers, body):
            self.assertEqual((method, path), ('PUT', '/api/trivy/v1/projects/00000000-0000-4000-8000-000000000001'))
            self.assertEqual(headers['Authorization'], 'Bearer temporary-token')
            self.assertEqual(json.loads(body), snapshot)
            return 200, {'stored': True}, {}
        with server(respond) as url:
            self.m.upload_findings(self.m.Client(url, 'temporary-token'), '00000000-0000-4000-8000-000000000001', snapshot)

    def test_main_publishes_configuration_high_before_failing_the_gate(self):
        from test_checks import server
        paths = []
        project = '00000000-0000-4000-8000-000000000001'
        def respond(method, path, headers, body):
            paths.append(path)
            if path == '/api/v2/oauth/token':
                return 200, {'token_type': 'Bearer', 'access_token': 'session'}, {}
            if path == '/api/v1/bom':
                return 200, {'token': project}, {}
            if path.startswith('/api/v1/bom/token/'):
                return 200, {'processing': False, 'status': 'COMPLETED'}, {}
            if path.startswith('/api/v1/project/lookup'):
                return 200, {'uuid': project}, {}
            if path == '/api/trivy/v1/projects/' + project:
                self.assertEqual(json.loads(body)['findings'][0]['severity'], 'HIGH')
                return 200, {'stored': True}, {}
            return 404, {}, {}
        def scan(mode, target, directory):
            (directory / 'trivy.json').write_text(json.dumps({'Results': [{'Target': 'main.tf',
                'Misconfigurations': [{'ID': 'AVD-AWS-0082', 'Severity': 'HIGH', 'Status': 'FAIL'}]}]}))
            (directory / 'bom.cdx.json').write_text('{}')
        env = {'GITHUB_REPOSITORY': 'boiseilabs/Good-Impulse', 'CHECKS_DEFAULT_BRANCH': 'main',
               'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
               'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main'}
        original_client = self.m.Client
        with tempfile.TemporaryDirectory() as directory, server(respond) as url:
            env['RUNNER_TEMP'] = directory
            with patch.dict(os.environ, env, clear=True), patch('sys.argv', ['checks', '--upload', 'true']), \
                    patch.object(self.m, 'scan', side_effect=scan), patch.object(self.m, 'github_token', return_value='github'), \
                    patch.object(self.m, 'Client', side_effect=lambda **kwargs: original_client(url, **kwargs)):
                self.assertEqual(self.m.main(), 1)
            summary = json.loads(next(Path(directory).glob('*/summary.json')).read_text())
            self.assertTrue(summary['uploaded'])
            self.assertEqual(summary['findings']['misconfigurations']['HIGH'], 1)
        self.assertEqual(paths[-1], '/api/trivy/v1/projects/' + project)


if __name__ == '__main__':
    unittest.main()
