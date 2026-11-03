import struct
import unittest
from unittest.mock import patch

from core.cip import CIPClient, decode_identity_attribute, parse_cip_response, parse_rr_data
from core.connection import EIPConnection, ProtocolError
from core.session import SessionManager
from modules.discovery import HEADER


class SimulatedSocket:
    def __init__(self):
        self.buffer = b''
        self.commands = []
        self.requests = []
        self.closed = False

    def settimeout(self, _timeout):
        pass

    def sendall(self, request):
        command, size, session, status, context, options = HEADER.unpack(request[:24])
        self.commands.append(command)
        self.requests.append(request)
        if command == 0x0066:
            return
        payload = request[24:]
        if command == 0x0065:
            session = 123
        elif command == 0x006F:
            cip = b'\x8e\x00\x00\x00\x01\x00'
            payload = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0xB2, len(cip)) + cip
        self.buffer = HEADER.pack(command, len(payload), session, 0, context, 0) + payload

    def recv(self, size):
        result, self.buffer = self.buffer[:min(size, 3)], self.buffer[min(size, 3):]
        return result

    def close(self):
        self.closed = True


class ProtocolTests(unittest.TestCase):
    def test_fragmented_session_read_and_cleanup(self):
        connection_socket = SimulatedSocket()
        with patch('core.connection.socket.create_connection', return_value=connection_socket):
            with EIPConnection('192.0.2.10') as connection:
                session = SessionManager(connection)
                self.assertEqual(session.register(), 123)
                response = CIPClient(session).read_identity_attribute(1)
                self.assertEqual(decode_identity_attribute(1, response.data), 1)
                self.assertTrue(session.close())
                self.assertFalse(session.close())
        self.assertEqual(connection_socket.commands, [0x65, 0x6F, 0x66])
        self.assertTrue(connection_socket.closed)
        self.assertEqual(connection_socket.requests[1][-8:], b'\x0e\x03\x20\x01\x24\x01\x30\x01')
        self.assertTrue(all(entry['request_hex'] for entry in connection.exchanges))
        self.assertFalse(connection.exchanges[-1]['response_expected'])

    def test_allowlist_blocks_arbitrary_attribute_before_network(self):
        connection = EIPConnection('192.0.2.10')
        client = CIPClient(SessionManager(connection))
        for attribute in (0, 8, 255):
            with self.assertRaises(ValueError):
                client.read_identity_attribute(attribute)
        with self.assertRaises(ProtocolError):
            client.read_identity_attribute(1)
        self.assertEqual(connection.exchanges, [])

    def test_general_and_additional_status(self):
        response = parse_cip_response(bytes.fromhex('8e0005013412'))
        self.assertEqual(response.general_status, 5)
        self.assertEqual(response.additional_status, (0x1234,))
        for payload in (b'', bytes.fromhex('8e000001'), bytes.fromhex('8f000000'), bytes.fromhex('8e010000')):
            with self.subTest(payload=payload), self.assertRaises(ProtocolError):
                parse_cip_response(payload)

    def test_cpf_lengths_and_layout(self):
        cip = bytes.fromhex('8e0000000100')
        payload = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0xB2, len(cip)) + cip
        self.assertEqual(parse_rr_data(payload).data, b'\x01\x00')
        for size in range(len(payload)):
            with self.subTest(size=size), self.assertRaises(ProtocolError):
                parse_rr_data(payload[:size])
        with self.assertRaises(ProtocolError):
            parse_rr_data(payload + b'\x00')

    def test_identity_data_types(self):
        self.assertEqual(decode_identity_attribute(4, b'\x02\x07'), '2.7')
        self.assertEqual(decode_identity_attribute(6, bytes.fromhex('78563412')), '12345678')
        self.assertEqual(decode_identity_attribute(7, b'\x03PLC'), 'PLC')
        for attribute, data in ((1, b'\x00'), (7, b'\x04PLC'), (6, b'')):
            with self.assertRaises(ProtocolError):
                decode_identity_attribute(attribute, data)

    def test_bad_reply_records_error_and_closes(self):
        connection_socket = SimulatedSocket()
        with patch('core.connection.socket.create_connection', return_value=connection_socket):
            with EIPConnection('192.0.2.10') as connection:
                with patch.object(connection_socket, 'recv', return_value=b''):
                    with self.assertRaises(ProtocolError):
                        connection.exchange(0x0063)
                self.assertTrue(connection.broken)
                self.assertIsNotNone(connection.exchanges[0]['error'])
        self.assertTrue(connection_socket.closed)

    def test_partial_response_bytes_are_preserved(self):
        connection_socket = SimulatedSocket()
        with patch('core.connection.socket.create_connection', return_value=connection_socket):
            with EIPConnection('192.0.2.10') as connection:
                with patch.object(connection_socket, 'recv', side_effect=[b'\x63\x00', b'']):
                    with self.assertRaises(ProtocolError):
                        connection.exchange(0x63)
                self.assertEqual(connection.exchanges[0]['response_hex'], '6300')


if __name__ == '__main__':
    unittest.main()