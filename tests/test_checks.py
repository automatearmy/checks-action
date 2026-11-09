import contextlib
import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs


@contextlib.contextmanager
def server(respond):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_request(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            status, payload, headers = respond(self.command, self.path, self.headers, body)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        do_GET = do_POST = do_PUT = do_DELETE = handle_request

    httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{httpd.server_port}'
    finally:
        httpd.shutdown()
        thread.join()
        httpd.server_close()


class ChecksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / 'scripts/checks.py'
        assert path.exists(), 'Checks integration is not implemented'
        spec = importlib.util.spec_from_file_location('checks', path)
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)

    def test_exchange_uses_form_and_never_a_permanent_api_key(self):
        def respond(method, path, headers, body):
            self.assertEqual((method, path), ('POST', '/api/v2/oauth/token'))
            self.assertNotIn('Authorization', headers)
            form = parse_qs(body.decode())
            self.assertEqual(form['subject_token'], ['github-token'])
            self.assertEqual(form['service_account'], ['automatearmy-checks'])
            self.assertEqual(form['workload_identity_provider'], ['github-actions-checks'])
            return 200, {'access_token': 'short-session', 'token_type': 'Bearer', 'expires_in': 900}, {}

        with server(respond) as url:
            self.assertEqual(self.m.exchange(self.m.Client(url), 'github-token', 'automatearmy'), 'short-session')

    def test_authenticated_upload_autocreates_repo_and_waits_for_completed(self):
        paths = []
        def respond(method, path, headers, body):
            self.assertEqual(headers['Authorization'], 'Bearer temporary-token')
            paths.append(path)
            if method == 'PUT':
                payload = json.loads(body)
                self.assertEqual(payload['projectName'], 'automatearmy/example')
                self.assertEqual(payload['projectVersion'], 'main')
                self.assertTrue(payload['autoCreate'])
                return 200, {'token': '00000000-0000-4000-8000-000000000001'}, {}
            return 200, {'processing': len(paths) < 3, 'status': 'RUNNING' if len(paths) < 3 else 'COMPLETED'}, {}

        with server(respond) as url:
            self.m.upload(self.m.Client(url, 'temporary-token'), b'{}', 'automatearmy/example', 'main', interval=0)
        self.assertEqual(len(paths), 3)

    def test_failed_or_unknown_workflow_never_counts_as_success(self):
        for status in ['FAILED', None]:
            def respond(method, path, headers, body):
                if method == 'PUT':
                    return 200, {'token': '00000000-0000-4000-8000-000000000001'}, {}
                return 200, {'processing': False, 'status': status}, {}
            with self.subTest(status=status), server(respond) as url:
                with self.assertRaisesRegex(RuntimeError, 'failed|timed out'):
                    self.m.upload(self.m.Client(url, 'token'), b'{}', 'org/repo', 'main', interval=0, timeout=.05)

    def test_redirect_never_forwards_machine_credential(self):
        seen = []
        def respond(method, path, headers, body):
            seen.append(path)
            return 302, {}, {'Location': '/leak'}
        with server(respond) as url:
            with self.assertRaisesRegex(self.m.ApiError, 'HTTP 302'):
                self.m.Client(url, 'private-token').request('/api/v1/project')
        self.assertEqual(seen, ['/api/v1/project'])

    def test_errors_never_expose_response_body_or_credentials(self):
        with server(lambda *a: (401, {'secret': 'must-stay-private'}, {})) as url:
            with self.assertRaises(self.m.ApiError) as err:
                self.m.Client(url, 'private-token').request('/api/v1/project')
            self.assertNotIn('must-stay-private', str(err.exception))
            self.assertNotIn('private-token', str(err.exception))

    def test_rejects_unsafe_origins(self):
        for url in ['http://example.com', 'https://user:pass@example.com', 'https://example.com/api', 'https://example.com?x=1']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.m.Client(url)

    def test_summary_never_contains_secret_matches_and_gate_includes_misconfig(self):
        report = {'Results': [{'Vulnerabilities': [{'Severity': 'CRITICAL'}],
                               'Misconfigurations': [{'Severity': 'HIGH', 'Status': 'FAIL'}],
                               'Secrets': [{'Severity': 'HIGH', 'Match': 'private-secret'}]}]}
        summary = self.m.summarize(report)
        self.assertEqual(summary['vulnerabilities']['CRITICAL'], 1)
        self.assertEqual(summary['misconfigurations']['HIGH'], 1)
        self.assertEqual(summary['secrets']['HIGH'], 1)
        self.assertNotIn('private-secret', json.dumps(summary))
        self.assertTrue(self.m.gate_failed(summary, 'HIGH,CRITICAL'))

    def test_upload_trust_requires_default_branch_and_trusted_event(self):
        base = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main', 'CHECKS_DEFAULT_BRANCH': 'main'}
        self.assertTrue(self.m.can_upload(base))
        for changed in [{'GITHUB_EVENT_NAME': 'pull_request'}, {'GITHUB_EVENT_NAME': 'pull_request_target'},
                        {'GITHUB_REF': 'refs/heads/feature'}, {'CHECKS_DEFAULT_BRANCH': ''}]:
            self.assertFalse(self.m.can_upload({**base, **changed}))


if __name__ == '__main__':
    unittest.main()
