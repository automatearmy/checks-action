import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


class ConfigureTests(unittest.TestCase):
    def test_trust_pins_org_id_workflow_path_and_release_commit(self):
        import configure
        bindings = configure.bindings('automatearmy', '117208740', ['a' * 40])
        self.assertEqual({b['subject'] for b in bindings}, {'repo:automatearmy/*', 'repo:automatearmy@117208740/*'})
        for binding in bindings:
            rule = binding['condition']
            self.assertIn('claims.repository_owner_id == "117208740"', rule)
            self.assertIn('claims.job_workflow_sha in ["' + 'a' * 40 + '"]', rule)
            self.assertIn('automatearmy/checks-action/.github/workflows/scan.yml@', rule)
            self.assertIn('"push", "schedule", "workflow_dispatch"', rule)
            self.assertNotIn('pull_request', rule)

    def test_malformed_release_or_organization_is_rejected_before_mutations(self):
        import configure
        for org, owner_id, commits in [('org/other', '123', ['a' * 40]), ('org', 'not-a-number', ['a' * 40]),
                                       ('org', '123', ['main']), ('org', '123', [])]:
            with self.subTest(org=org, commits=commits), self.assertRaises(ValueError):
                configure.bindings(org, owner_id, commits)

    def test_external_owner_trusts_its_own_id_and_the_chosen_workflow_repo(self):
        import configure
        bindings = configure.bindings('Acme-Labs', '42', ['b' * 40], 'Acme-Labs/checks-action')
        self.assertEqual({b['subject'] for b in bindings}, {'repo:Acme-Labs/*', 'repo:Acme-Labs@42/*'})
        for binding in bindings:
            self.assertIn('claims.repository_owner_id == "42"', binding['condition'])
            self.assertIn('"Acme-Labs/checks-action/.github/workflows/scan.yml@"', binding['condition'])
        default = configure.bindings('acme', '42', ['b' * 40])
        self.assertIn('"automatearmy/checks-action/.github/workflows/scan.yml@"', default[0]['condition'])
        with self.assertRaises(ValueError):
            configure.bindings('acme', '42', ['b' * 40], 'not a repo')

    def test_each_owner_gets_a_dedicated_account(self):
        import checks
        self.assertEqual(checks.account('automatearmy'), 'automatearmy-checks')
        self.assertEqual(checks.account('Acme-Labs'), 'acme-labs-checks')
        for owner in ['', 'a/b', '-x', 'a' * 40]:
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                checks.account(owner)

    def test_configure_creates_a_separate_account_for_a_new_owner(self):
        import configure

        class FakeClient:
            origin = 'https://checks.example'

            def __init__(self):
                self.calls = []

            def request(self, path, method='GET', payload=None):
                self.calls.append((method, path, payload))
                if method == 'GET' and path.endswith('/github-actions-checks'):
                    return {'name': 'github-actions-checks', 'type': 'OIDC', 'audience': self.origin,
                            'issuer': 'https://token.actions.githubusercontent.com', 'session_lifetime_seconds': 900}
                if method == 'GET' and path == '/api/v2/service-accounts/acme-checks':
                    raise configure.ApiError(404)
                if method == 'GET' and path.endswith('/workload-identity-bindings?limit=1000'):
                    return {'items': []}
                return None

        client = FakeClient()
        configure.configure(client, 'acme', '42', ['c' * 40], 'acme/checks-action')
        touched = {path for _, path, _ in client.calls}
        self.assertIn(('POST', '/api/v2/service-accounts', {'name': 'acme-checks'}), client.calls)
        self.assertFalse(any('automatearmy-checks' in path for path in touched))
        posted = [p for m, path, p in client.calls if path.endswith('/workload-identity-bindings') and m == 'POST']
        self.assertEqual({b['subject'] for b in posted}, {'repo:acme/*', 'repo:acme@42/*'})

    def test_external_runners_must_be_github_hosted_unless_allowed(self):
        import configure
        hosted = configure.bindings('acme', '42', ['b' * 40])[0]['condition']
        self.assertTrue(hosted.endswith('claims.runner_environment == "github-hosted"'))
        carini = configure.bindings('automatearmy', '117208740', ['b' * 40], self_hosted=True)[0]['condition']
        self.assertNotIn('runner_environment', carini)

    def test_mirror_pins_its_own_action_and_reusable_workflow(self):
        import mirror
        scan = (Path(__file__).resolve().parents[1] / '.github/workflows/scan.yml').read_text()
        rewritten = mirror.rewrite(scan, 'acme', 'd' * 40)
        self.assertIn('uses: acme/checks-action@' + 'd' * 40, rewritten)
        self.assertNotIn('automatearmy/checks-action', rewritten)
        caller = mirror.rewrite('    uses: automatearmy/checks-action/.github/workflows/scan.yml@v1\n', 'acme', 'd' * 40)
        self.assertEqual(caller, '    uses: acme/checks-action/.github/workflows/scan.yml@v1\n')
        for owner, sha in [('a/b', 'd' * 40), ('acme', 'main')]:
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                mirror.rewrite(scan, owner, sha)


if __name__ == '__main__':
    unittest.main()
