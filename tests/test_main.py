import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from main import main
from modules.discovery import parse_identity_payload
from test_discovery import identity_payload


class CLITests(unittest.TestCase):
    def test_catalog_is_offline(self):
        output = io.StringIO()
        with redirect_stdout(output), patch('main.Discovery.discover') as discover:
            self.assertEqual(main(['assess']), 0)
            discover.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())[0]['identifier'], 'EIP-01')

    def test_missing_authorization_prevents_probe(self):
        with redirect_stderr(io.StringIO()), patch('main.Discovery.discover') as discover:
            with self.assertRaises(SystemExit) as error:
                main(['discover', '192.0.2.10'])
            self.assertEqual(error.exception.code, 2)
            discover.assert_not_called()

    def test_default_command_launches_ui(self):
        with patch('ui.launch') as launch:
            self.assertEqual(main([]), 0)
            launch.assert_called_once()

    def test_discovery_report(self):
        output = io.StringIO()
        with redirect_stdout(output), patch('main.Discovery.discover', return_value=parse_identity_payload(identity_payload())):
            code = main(['discover', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket'])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['scope']['mode'], 'live')
        self.assertEqual(report['identities'][0]['product_name'], 'Lab PLC')

    def test_network_failure_is_inconclusive(self):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()), patch(
            'main.Discovery.discover', side_effect=TimeoutError('timed out')
        ):
            code = main(['discover', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket'])
        self.assertEqual(code, 1)
        report = json.loads(output.getvalue())
        self.assertIn('inconclusive', report['scope']['outcome'])
        self.assertEqual(report['observations'], [])

    def test_live_suite_cli_authorization_and_report(self):
        from modules.live_tests import LiveTestRunner
        import threading
        cancel = threading.Event()
        cancel.set()
        run = LiveTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel)
        with redirect_stderr(io.StringIO()), patch('main.LiveTestRunner.run') as execute:
            with self.assertRaises(SystemExit):
                main(['test', '192.0.2.10'])
            execute.assert_not_called()
        output = io.StringIO()
        with redirect_stdout(output), patch('main.LiveTestRunner.run', return_value=run):
            self.assertEqual(main(['test', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket']), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report['live_test_run']['outcome'], 'cancelled')
        self.assertEqual(report['reproduction']['cli_arguments'][2], 'test')

    def test_coverage_command_is_offline(self):
        output = io.StringIO()
        with redirect_stdout(output), patch('core.connection.socket.create_connection') as connect:
            self.assertEqual(main(['coverage']), 0)
            connect.assert_not_called()
        self.assertTrue(any(item['coverage'] == 'not_implemented' for item in json.loads(output.getvalue())))


if __name__ == '__main__':
    unittest.main()