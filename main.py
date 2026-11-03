import argparse
import json
import sys
from datetime import datetime, timezone

from modules.discovery import Discovery, Identity
from modules.live_tests import LiveTestRunner, coverage_matrix
from modules.security import SecurityAssessment
from reports.report import ReportGenerator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EtherNet/IP Security Framework")
    parser.add_argument('command', nargs='?', default='gui', choices=('gui', 'discover', 'assess', 'coverage', 'test'))
    parser.add_argument('target', nargs='?', help='Target IP')
    parser.add_argument('--authorized', action='store_true', help='Attest authorization and an approved maintenance window')
    parser.add_argument('--operator', help='Operator name and scope/ticket reference')
    parser.add_argument('--timeout', type=float, default=3.0, help='Total request deadline, 0.2 to 5 seconds')
    parser.add_argument('--output', help='JSON report path (discover or test)')
    args = parser.parse_args(argv)
    if args.command == 'gui':
        from ui import launch
        launch()
        return 0
    if args.command == 'assess':
        print(json.dumps(SecurityAssessment().catalog(), indent=2))
        return 0
    if args.command == 'coverage':
        print(json.dumps(coverage_matrix(), indent=2))
        return 0
    if not args.target or not args.authorized or not args.operator or not args.operator.strip():
        parser.error(f'{args.command} requires a target, --authorized and --operator with a scope reference')
    if args.command == 'test':
        try:
            run = LiveTestRunner(args.timeout).run(args.target, args.operator, args.authorized)
            identities = [Identity(**item) for item in run['identities']]
            report = ReportGenerator().build(args.target, args.operator, True, 'live', run['outcome'],
                                             identities, SecurityAssessment(), run['started_at_utc'], live_run=run)
            if args.output:
                ReportGenerator().save(args.output, report)
            print(json.dumps(report, indent=2))
            return 0 if run['outcome'] == 'completed' else 1
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    observed_at = datetime.now(timezone.utc).isoformat()
    identities = []
    code = 0
    try:
        identities = Discovery().discover(args.target, args.timeout)
        outcome = 'Identity response received.' if identities else 'No identity items; inconclusive.'
    except (OSError, ValueError) as exc:
        outcome = f'Probe failed; inconclusive: {exc}'
        print(outcome, file=sys.stderr)
        code = 1
    try:
        generator = ReportGenerator()
        report = generator.build(args.target, args.operator, True, 'live', outcome,
                                 identities, SecurityAssessment(), observed_at)
        if args.output:
            generator.save(args.output, report)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return code

if __name__ == '__main__':
    raise SystemExit(main())
