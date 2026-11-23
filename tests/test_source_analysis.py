import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from source_analysis import normalize


class SourceAnalysisTests(unittest.TestCase):
    def test_bandit_discards_details_and_reports_partial_scans_as_failed(self):
        report = {'metrics': {'_totals': {'loc': 3}}, 'errors': [], 'results': [
            {'filename': './example.py', 'test_id': 'B105', 'issue_severity': 'LOW',
             'line_number': 2, 'code': 'private source', 'issue_text': 'private'}]}
        self.assertEqual(normalize('bandit', report), ([{'kind': 'code', 'id': 'B105',
                         'severity': 'LOW', 'start_line': 2, 'target': 'example.py'}], True))
        report['errors'] = ['parse failure']
        with self.assertRaises(ValueError):
            normalize('bandit', report)

    def test_checkov_unscored_findings_and_empty_inputs(self):
        section = {'results': {'failed_checks': []}, 'summary': {'failed': 0, 'passed': 0, 'parsing_errors': 0}}
        self.assertEqual(normalize('checkov', [section]), ([], False))
        section['summary']['failed'] = 1
        section['results']['failed_checks'] = [{'file_abs_path': '/workspace/Dockerfile', 'check_id': 'CKV_DOCKER_1'}]
        self.assertEqual(normalize('checkov', section), ([{'kind': 'misconfiguration', 'id': 'CKV_DOCKER_1',
                         'severity': 'UNKNOWN', 'target': 'Dockerfile'}], True))
        section['results']['failed_checks'][0]['file_abs_path'] = '/workspace/../outside'
        with self.assertRaises(ValueError):
            normalize('checkov', section)
