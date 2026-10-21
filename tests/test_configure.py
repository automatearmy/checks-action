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


if __name__ == '__main__':
    unittest.main()
