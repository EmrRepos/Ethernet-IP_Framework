import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from modules.discovery import (
    HEADER, LIST_IDENTITY, Discovery, DiscoveryError,
    parse_identity_payload, validate_target,
)


def identity_payload(name=b'Lab PLC'):
    item = (
        struct.pack('<H', 1)
        + struct.pack('>HH4s8s', socket.AF_INET, 44818, socket.inet_aton('192.0.2.10'), b'\x00' * 8)
        + struct.pack('<HHHBBHIB', 1, 14, 123, 2, 7, 0, 0x12345678, len(name))
        + name + b'\x03'
    )
    return struct.pack('<HHH', 1, 0x000C, len(item)) + item


class DiscoveryTests(unittest.TestCase):
    def test_identity_fields(self):
        identity = parse_identity_payload(identity_payload())[0]
        self.assertEqual(identity.address, '192.0.2.10')
        self.assertEqual(identity.port, 44818)
        self.assertEqual(identity.vendor_id, 1)
        self.assertEqual(identity.product_code, 123)
        self.assertEqual(identity.revision, '2.7')
        self.assertEqual(identity.serial_number, '12345678')
        self.assertEqual(identity.product_name, 'Lab PLC')
        self.assertEqual(identity.state, 3)

    def test_truncation_and_trailing_data(self):
        payload = identity_payload()
        for size in range(len(payload)):
            with self.subTest(size=size), self.assertRaises(DiscoveryError):
                parse_identity_payload(payload[:size])
        with self.assertRaises(DiscoveryError):
            parse_identity_payload(payload + b'\x00')

    def test_bad_name_length(self):
        payload = bytearray(identity_payload())
        payload[38] = 255
        with self.assertRaises(DiscoveryError):
            parse_identity_payload(bytes(payload))

    def test_unknown_item_and_empty_list(self):
        self.assertEqual(parse_identity_payload(struct.pack('<HHH', 1, 99, 0)), [])
        self.assertEqual(parse_identity_payload(b'\x00\x00'), [])

    def test_target_validation(self):
        self.assertEqual(validate_target(' 192.0.2.10 '), '192.0.2.10')
        for target in ('example.com', '192.0.2.0/24', '224.0.0.1', '0.0.0.0', '255.255.255.255', '::1'):
            with self.subTest(target=target), self.assertRaises(DiscoveryError):
                validate_target(target)

    def test_timeout_validation_precedes_network(self):
        with patch('modules.discovery.socket.create_connection') as connect:
            for timeout in (0, 6, float('nan')):
                with self.assertRaises(DiscoveryError):
                    Discovery().discover('192.0.2.10', timeout)
            connect.assert_not_called()

    def exchange(self, header=None, payload=None):
        if payload is None:
            payload = identity_payload()
        if header is None:
            header = HEADER.pack(LIST_IDENTITY, len(payload), 0, 0, b'context!', 0)
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [header[:5], header[5:], payload[:3], payload[3:]]
        return connection

    def test_single_request_fragmented_response_and_cleanup(self):
        connection = self.exchange()
        with patch('modules.discovery.secrets.token_bytes', return_value=b'context!'), patch(
            'modules.discovery.socket.create_connection', return_value=connection
        ) as connect:
            identities = Discovery().discover('192.0.2.10')
        self.assertEqual(len(identities), 1)
        connect.assert_called_once_with(('192.0.2.10', 44818), timeout=3.0)
        connection.sendall.assert_called_once_with(HEADER.pack(LIST_IDENTITY, 0, 0, 0, b'context!', 0))
        connection.__exit__.assert_called_once()

    def test_invalid_headers(self):
        for command, size, session, status, context, options in (
            (1, 0, 0, 0, b'context!', 0),
            (LIST_IDENTITY, 0, 0, 1, b'context!', 0),
            (LIST_IDENTITY, 0, 0, 0, b'invalid!', 0),
            (LIST_IDENTITY, 0, 1, 0, b'context!', 0),
            (LIST_IDENTITY, 0, 0, 0, b'context!', 1),
            (LIST_IDENTITY, 16385, 0, 0, b'context!', 0),
        ):
            connection = self.exchange(HEADER.pack(command, size, session, status, context, options))
            with self.subTest(command=command, status=status, size=size), patch(
                'modules.discovery.secrets.token_bytes', return_value=b'context!'
            ), patch('modules.discovery.socket.create_connection', return_value=connection):
                with self.assertRaises(DiscoveryError):
                    Discovery().discover('192.0.2.10')

    def test_early_eof(self):
        connection = self.exchange()
        connection.recv.side_effect = [b'']
        with patch('modules.discovery.socket.create_connection', return_value=connection):
            with self.assertRaises(DiscoveryError):
                Discovery().discover('192.0.2.10')


if __name__ == '__main__':
    unittest.main()