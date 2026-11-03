import struct
import threading
import unittest
from unittest.mock import patch

from modules.live_tests import LIVE_CASES, LiveTestRunner, coverage_matrix, parse_discovery_items
from modules.discovery import HEADER
from test_discovery import identity_payload
from test_protocol import SimulatedSocket


class DeviceSocket(SimulatedSocket):
    def __init__(self, cip_status=0, unsupported_interfaces=False):
        super().__init__()
        self.cip_status = cip_status
        self.unsupported_interfaces = unsupported_interfaces

    def sendall(self, request):
        super().sendall(request)
        command, size, session, status, context, options = HEADER.unpack(request[:24])
        payload = b'\x00\x00'
        if command == 0x0066:
            return
        if command == 0x0063:
            payload = identity_payload()
        elif command == 0x0004:
            data = struct.pack('<HH16s', 1, 0x20, b'Communications')
            payload = struct.pack('<HHH', 1, 0x100, len(data)) + data
        elif command == 0x0064 and self.unsupported_interfaces:
            status = 1
        elif command == 0x0065:
            payload, session = request[24:], 123
        elif command == 0x006F:
            attribute = request[-1]
            values = {1: b'\x01\x00', 2: b'\x0e\x00', 3: b'\x7b\x00', 4: b'\x02\x07',
                      5: b'\x00\x00', 6: bytes.fromhex('78563412'), 7: b'\x07Lab PLC'}
            cip = bytes((0x8E, 0, self.cip_status, 0)) + (values[attribute] if not self.cip_status else b'')
            payload = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0xB2, len(cip)) + cip
        self.buffer = HEADER.pack(command, len(payload), session, status, context, 0) + payload


class LiveSuiteTests(unittest.TestCase):
    def run_device(self, device):
        with patch('core.connection.socket.create_connection', return_value=device), patch('threading.Event.wait', return_value=False):
            return LiveTestRunner().run('192.0.2.10', 'Tester / lab ticket', authorized=True)

    def test_complete_live_suite_against_mock_device(self):
        device = DeviceSocket()
        run = self.run_device(device)
        self.assertEqual(run['outcome'], 'completed')
        self.assertEqual(len(run['test_results']), len(LIVE_CASES))
        self.assertTrue(all(result['status'] == 'observed' for result in run['test_results']))
        self.assertEqual(len(device.commands), 12)
        self.assertEqual(device.commands.count(0x65), 1)
        self.assertEqual(device.commands[-1], 0x66)
        self.assertTrue(device.closed)
        self.assertEqual(run['attribute_values']['product_name'], 'Lab PLC')
        self.assertEqual(run['consistency_observations'], [])
        self.assertEqual(len(run['evidence_sha256']), 64)

    def test_unsupported_discovery_does_not_prevent_reads(self):
        run = self.run_device(DeviceSocket(unsupported_interfaces=True))
        self.assertEqual(run['test_results'][2]['status'], 'unsupported')
        self.assertEqual(run['attribute_values']['vendor_id'], 1)

    def test_access_denial_and_unsupported_are_not_findings(self):
        for status, expected in ((0x0F, 'access_denied'), (0x14, 'unsupported'), (0x01, 'inconclusive')):
            run = self.run_device(DeviceSocket(cip_status=status))
            self.assertEqual(run['test_results'][4]['status'], expected)
            self.assertEqual(run['attribute_values'], {})

    def test_authorization_and_cancel_precede_connection(self):
        with patch('core.connection.socket.create_connection') as connect:
            with self.assertRaises(ValueError):
                LiveTestRunner().run('192.0.2.10', 'Lab', authorized=False)
            cancel = threading.Event()
            cancel.set()
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True, cancel)
            connect.assert_not_called()
        self.assertEqual(run['outcome'], 'cancelled')
        self.assertTrue(all(result['status'] == 'not_run' for result in run['test_results']))

    def test_unreachable_target_is_inconclusive(self):
        with patch('core.connection.socket.create_connection', side_effect=TimeoutError('timed out')):
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True)
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertEqual(run['exchanges'], [])
        self.assertTrue(all(result['status'] == 'not_run' for result in run['test_results']))

    def test_discovery_item_validation_and_coverage_gaps(self):
        for payload in (b'', b'\x01\x00', bytes.fromhex('01000001010000'), b'\x00\x00\x00'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_discovery_items(payload, services=True)
        matrix = coverage_matrix()
        self.assertEqual(len({entry['id'] for entry in matrix}), len(matrix))
        self.assertTrue(any(entry['coverage'] == 'requires_device_profile' for entry in matrix))

    def test_budget_expiry_after_pacing_sends_no_next_request(self):
        device = DeviceSocket()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'modules.live_tests.time.monotonic', return_value=0.0
        ) as clock:
            def expire(_delay):
                clock.return_value = 31.0
                return False
            with patch('threading.Event.wait', side_effect=expire):
                run = LiveTestRunner().run('192.0.2.10', 'Lab', True)
        self.assertEqual(device.commands, [0x63])
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertIn('budget', run['stop_reason'])

    def test_cancellation_after_read_still_cleans_up_session(self):
        device = DeviceSocket()
        cancel = threading.Event()
        original_send = device.sendall
        def send_and_cancel(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x6F:
                cancel.set()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ), patch.object(device, 'sendall', side_effect=send_and_cancel):
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True, cancel)
        self.assertEqual(run['outcome'], 'cancelled')
        self.assertEqual(device.commands, [0x63, 0x04, 0x64, 0x65, 0x6F, 0x66])
        self.assertTrue(device.closed)
        self.assertEqual(run['test_results'][5]['status'], 'not_run')

    def test_malformed_cip_response_becomes_developer_candidate(self):
        from modules.discovery import Identity
        from modules.security import SecurityAssessment
        from reports.report import ReportGenerator
        device = DeviceSocket()
        original_send = device.sendall
        def corrupt_cip(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x6F:
                packet = bytearray(device.buffer)
                packet[40] = 0x8F
                device.buffer = bytes(packet)
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ), patch.object(device, 'sendall', side_effect=corrupt_cip):
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True)
        self.assertEqual(run['test_results'][4]['status'], 'protocol_anomaly')
        self.assertEqual(device.commands[-1], 0x66)
        report = ReportGenerator().build('192.0.2.10', 'Lab', True, 'live', run['outcome'],
                                         [Identity(**item) for item in run['identities']], SecurityAssessment(), live_run=run)
        self.assertEqual(report['developer_review_candidates'][0]['test_id'], 'CIP-01')
        self.assertTrue(report['developer_review_candidates'][0]['exchange_indices'])


if __name__ == '__main__':
    unittest.main()