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

    def test_external_owner_trusts_its_own_id_and_only_the_upstream_workflow(self):
        import configure
        bindings = configure.bindings('Acme-Labs', '42', ['b' * 40])
        self.assertEqual({b['subject'] for b in bindings}, {'repo:Acme-Labs/*', 'repo:Acme-Labs@42/*'})
        for binding in bindings:
            self.assertIn('claims.repository_owner_id == "42"', binding['condition'])
            self.assertIn('startsWith("automatearmy/checks-action/.github/workflows/scan.yml@")', binding['condition'])

    def test_each_owner_gets_a_dedicated_account(self):
        import checks
        self.assertEqual(checks.account('automatearmy'), 'automatearmy-checks')
        self.assertEqual(checks.account('Acme-Labs'), 'acme-labs-checks')
        for owner in ['', 'a/b', '-x', 'a' * 40]:
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                checks.account(owner)

    def test_configure_creates_a_separate_account_and_isolated_team_for_a_new_owner(self):
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
                if path == '/api/v1/team':
                    return [{'uuid': 'other', 'name': 'Administrators'}] if method == 'GET' else {'uuid': 'team-1', 'name': 'acme-checks'}
                if path.startswith('/api/v1/acl/team/'):
                    return [{'uuid': 'p-granted'}]
                if path.startswith('/api/v1/project?'):
                    return [{'uuid': 'p-new', 'name': 'acme/app'}, {'uuid': 'p-granted', 'name': 'ACME/api'},
                            {'uuid': 'p-other', 'name': 'automatearmy/app'}, {'uuid': 'p-lookalike', 'name': 'acme-labs/app'}]
                return None

        client = FakeClient()
        configure.configure(client, 'acme', '42', ['c' * 40])
        self.assertIn(('POST', '/api/v2/service-accounts', {'name': 'acme-checks'}), client.calls)
        self.assertFalse(any('automatearmy-checks' in path for _, path, _ in client.calls))
        posted = [p for m, path, p in client.calls if path.endswith('/workload-identity-bindings') and m == 'POST']
        self.assertEqual({b['subject'] for b in posted}, {'repo:acme/*', 'repo:acme@42/*'})
        self.assertIn(('PUT', '/api/v1/team', {'name': 'acme-checks'}), client.calls)
        self.assertIn(('POST', '/api/v1/user/svc%3Aacme-checks/membership', {'uuid': 'team-1'}), client.calls)
        acl = [p['project'] for m, path, p in client.calls if path == '/api/v1/acl/mapping']
        self.assertEqual(acl, ['p-new'])

    def test_team_with_other_automation_is_never_reused(self):
        import configure

        class FakeClient:
            def request(self, path, method='GET', payload=None):
                return [{'uuid': 't', 'name': 'acme-checks', 'apiKeys': [{'publicId': 'x'}]}]

        with self.assertRaises(RuntimeError):
            configure.isolate(FakeClient(), 'acme', 'acme-checks', False)

        class PeopleOnly:
            def __init__(self):
                self.calls = []

            def request(self, path, method='GET', payload=None):
                self.calls.append(path)
                if path == '/api/v1/team':
                    return [{'uuid': 't', 'name': 'acme-checks', 'oidcUsers': [{'username': 'a@acme.com'}],
                             'serviceAccounts': [{'username': 'svc:acme-checks'}]}]
                return []

        configure.isolate(PeopleOnly(), 'acme', 'acme-checks', True)

        class SharedTeam:
            def request(self, path, method='GET', payload=None):
                return [{'uuid': 't', 'name': 'acme-checks', 'serviceAccounts': [{'name': 'other-checks'}]}]

        with self.assertRaises(RuntimeError):
            configure.isolate(SharedTeam(), 'acme', 'acme-checks', True)

    def test_external_runners_must_be_github_hosted_unless_allowed(self):
        import configure
        hosted = configure.bindings('acme', '42', ['b' * 40])[0]['condition']
        self.assertTrue(hosted.endswith('claims.runner_environment == "github-hosted"'))
        carini = configure.bindings('automatearmy', '117208740', ['b' * 40], self_hosted=True)[0]['condition']
        self.assertNotIn('runner_environment', carini)
    def test_owner_can_be_limited_to_specific_repositories(self):
        import configure
        rule = configure.bindings('acme', '42', ['b' * 40], repository_ids=['7', '5'])[0]['condition']
        self.assertIn('claims.repository_id in ["5", "7"]', rule)
        self.assertNotIn('repository_id', configure.bindings('acme', '42', ['b' * 40])[0]['condition'])
        with self.assertRaises(ValueError):
            configure.bindings('acme', '42', ['b' * 40], repository_ids=['acme/repo'])


if __name__ == '__main__':
    unittest.main()
