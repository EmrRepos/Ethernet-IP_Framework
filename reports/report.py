import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from modules.discovery import Identity, validate_target
from modules.live_tests import coverage_matrix
from modules.security import REFERENCES, SecurityAssessment


class ReportGenerator:
    def build(self, target: str, operator: str, authorized: bool, mode: str,
              outcome: str, identities: list[Identity], assessment: SecurityAssessment,
              observed_at: str | None = None, live_run: dict | None = None) -> dict:
        if mode not in ('live', 'sample', 'manual'):
            raise ValueError('Unknown evidence mode.')
        target = validate_target(target)
        if not operator.strip():
            raise ValueError('An operator and scope reference are required.')
        if mode == 'live' and not authorized:
            raise ValueError('Live evidence requires an authorization attestation.')
        if live_run is not None and (mode != 'live' or live_run.get('target') != target
                                     or live_run.get('operator') != operator.strip()
                                     or live_run.get('authorization_attested') is not True):
            raise ValueError('Live-suite evidence must match the authorized report scope.')
        candidates = []
        if live_run:
            for result in live_run['test_results']:
                if result['status'] == 'protocol_anomaly':
                    candidates.append({
                        'test_id': result['id'], 'title': result['title'],
                        'classification': 'Protocol anomaly requiring developer verification; not a confirmed vulnerability.',
                        'expected': 'A structurally valid response to the documented request, or a valid rejection.',
                        'actual': result['detail'], 'exchange_indices': result['exchange_indices'],
                        'next_action': 'Compare the captured bytes with applicable vendor/ODVA specifications; '
                                       'repeat only on approved isolated hardware and document operational impact.',
                    })
            candidates.extend({'classification': 'Identity consistency observation requiring developer review',
                               **item} for item in live_run['consistency_observations'])
        return {
            'schema_version': '1.1',
            'generated_at_utc': datetime.now(timezone.utc).isoformat(),
            'scope': {
                'target': target, 'operator_and_scope': operator.strip(),
                'authorization_attested': authorized, 'mode': mode,
                'transport': 'TCP 44818',
                'request': 'Bounded Identity/CIP baseline' if live_run else 'ListIdentity (0x0063)',
                'observed_at_utc': observed_at, 'outcome': outcome,
            },
            'identities': [asdict(identity) for identity in identities],
            'observations': assessment.observations(identities),
            'attack_surface_reviews': assessment.catalog(),
            'live_test_run': live_run,
            'coverage_matrix': coverage_matrix(),
            'developer_review_candidates': candidates,
            'reproduction': {
                'prerequisites': 'Same approved target, network vantage point, device build/configuration and maintenance conditions.',
                'cli_arguments': (['python', 'main.py', 'test', target, '--authorized', '--operator', operator.strip(),
                                   '--timeout', str(live_run['limits']['request_timeout_seconds'])]
                                  if live_run else None),
                'evidence': 'Live-suite exchanges contain exact bounded wire bytes, timestamps and timings. '
                            'Session handles and sender contexts will differ on subsequent runs.',
                'missing_context': 'Attach vendor/model, hardware series, exact firmware build, EDS/profile, '
                                   'expected access policy, topology, device logs and observed process impact.',
            },
            'limitations': [
                'Sample mode contains synthetic data, not device evidence.',
                'Authorization is an operator attestation, not independently verified.',
                'Read-only traffic can still affect fragile ICS devices; use an approved window.',
                'Live suites create at most one session and read Identity attributes 1-7; no writes, resets, '
                'I/O traffic, flooding or fuzzing are performed.',
                'A sent UnregisterSession and local socket closure do not prove remote session deletion.',
                'Packet evidence hashes detect changes only against a separately trusted hash; they are not signatures.',
                'No vulnerability, CVE applicability or compliance verdict is inferred from identity.',
                'A timeout, denial or empty response is inconclusive, not proof of security.',
                'Review decisions and evidence are operator supplied, not automated verification.',
                'The catalog is a starting point, not exhaustive or a standards conformance assessment.',
            ],
            'references': REFERENCES,
        }

    def save(self, path: str, report: dict) -> None:
        Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
