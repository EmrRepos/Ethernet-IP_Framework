import json
import tempfile
import unittest
from pathlib import Path

from modules.discovery import parse_identity_payload
from modules.security import REVIEW_STATUSES, SURFACES, SecurityAssessment
from reports.report import ReportGenerator
from test_discovery import identity_payload


class SecurityTests(unittest.TestCase):
    def test_catalog_unique_and_unassessed(self):
        catalog = SecurityAssessment().catalog()
        self.assertEqual(len({entry['identifier'] for entry in catalog}), len(SURFACES))
        self.assertTrue(all(entry['status'] == 'Not assessed' for entry in catalog))
        self.assertGreaterEqual(len(catalog), 14)

    def test_review_requires_evidence(self):
        assessment = SecurityAssessment()
        for status in REVIEW_STATUSES[1:]:
            with self.subTest(status=status), self.assertRaises(ValueError):
                assessment.record_review('EIP-01', status, ' ')
        for identifier, status in (('invalid', 'Not assessed'), ('EIP-01', 'Secure')):
            with self.assertRaises(ValueError):
                assessment.record_review(identifier, status, 'Notes')
        with self.assertRaises(ValueError):
            assessment.record_review('EIP-01', 'Needs review', 'x' * 10001)
        assessment.record_review('EIP-01', 'Needs review', 'ACL review pending')
        self.assertEqual(assessment.catalog()[0]['evidence'], 'ACL review pending')

    def test_observations_do_not_claim_vulnerability(self):
        assessment = SecurityAssessment()
        self.assertEqual(assessment.observations([]), [])
        result = assessment.observations(parse_identity_payload(identity_payload()))
        self.assertIn('not a confirmed vulnerability', result[0]['classification'])
        self.assertIn('Does not establish', result[0]['limits'])
        self.assertEqual(assessment.catalog()[0]['status'], 'Not assessed')

    def test_report_round_trip_and_sample_label(self):
        generator = ReportGenerator()
        report = generator.build('192.0.2.10', 'Lab / ticket 123', False, 'sample',
                                 'Synthetic data', parse_identity_payload(identity_payload()),
                                 SecurityAssessment())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            generator.save(str(path), report)
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), report)
        self.assertEqual(report['scope']['mode'], 'sample')
        self.assertFalse(report['scope']['authorization_attested'])
        self.assertEqual(len(report['attack_surface_reviews']), len(SURFACES))

    def test_report_scope_validation(self):
        for target, operator, authorized, mode in (
            ('example.com', 'Lab', True, 'live'),
            ('192.0.2.10', '', True, 'live'),
            ('192.0.2.10', 'Lab', False, 'live'),
            ('192.0.2.10', 'Lab', True, 'invalid'),
        ):
            with self.subTest(mode=mode, target=target), self.assertRaises(ValueError):
                ReportGenerator().build(target, operator, authorized, mode, 'test', [], SecurityAssessment())

    def test_suite_evidence_cannot_be_relabelled(self):
        run = {'target': '192.0.2.10', 'operator': 'Lab', 'authorization_attested': True}
        for target, operator, mode in (('192.0.2.11', 'Lab', 'live'),
                                       ('192.0.2.10', 'Other ticket', 'live'),
                                       ('192.0.2.10', 'Lab', 'sample')):
            with self.assertRaisesRegex(ValueError, 'match'):
                ReportGenerator().build(target, operator, True, mode, 'Test', [], SecurityAssessment(), live_run=run)


if __name__ == '__main__':
    unittest.main()