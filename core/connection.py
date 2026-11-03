import secrets
import socket
import struct
import time
from datetime import datetime, timezone

from modules.discovery import HEADER, MAX_PAYLOAD, validate_target


class ProtocolError(ValueError):
    pass


class EncapsulationStatus(ProtocolError):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f'Encapsulation status 0x{status:08X}; not a vulnerability verdict.')


class EIPConnection:
    def __init__(self, target: str, timeout: float = 3.0) -> None:
        self.target = validate_target(target)
        if not 0.2 <= timeout <= 5.0:
            raise ValueError('Timeout must be between 0.2 and 5 seconds.')
        self.timeout = timeout
        self.socket = None
        self.broken = False
        self.exchanges: list[dict] = []

    def __enter__(self):
        self.socket = socket.create_connection((self.target, 44818), timeout=self.timeout)
        return self

    def __exit__(self, *_args):
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def _receive(self, size: int, deadline: float) -> bytes:
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Response deadline exceeded.')
            self.socket.settimeout(remaining)
            chunk = self.socket.recv(size - len(result))
            if not chunk:
                raise ProtocolError('Connection closed during response.')
            result.extend(chunk)
            self.exchanges[-1]['response_hex'] += chunk.hex()
        return bytes(result)

    def exchange(self, command: int, payload: bytes = b'', session: int = 0,
                 expect_response: bool = True) -> tuple[int, bytes]:
        if self.socket is None or self.broken:
            raise ProtocolError('Connection is unavailable.')
        if len(payload) > MAX_PAYLOAD:
            raise ValueError('Request exceeds the payload limit.')
        context = secrets.token_bytes(8)
        request = HEADER.pack(command, len(payload), session, 0, context, 0) + payload
        started = time.monotonic()
        deadline = started + self.timeout
        record = {
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'command': f'0x{command:04X}', 'request_hex': request.hex(),
            'response_hex': '', 'error': None,
        }
        self.exchanges.append(record)
        response = b''
        try:
            self.socket.settimeout(self.timeout)
            self.socket.sendall(request)
            if not expect_response:
                record['response_expected'] = False
                return session, b''
            response = self._receive(HEADER.size, deadline)
            reply_command, size, reply_session, status, reply_context, options = HEADER.unpack(response)
            if size > MAX_PAYLOAD:
                raise ProtocolError('Response exceeds the payload limit.')
            response += self._receive(size, deadline)
            if reply_command != command or reply_context != context or options:
                raise ProtocolError('Encapsulation command, context or options mismatch.')
            if status:
                raise EncapsulationStatus(status)
            if command != 0x0065 and reply_session != session:
                raise ProtocolError('Encapsulation session handle mismatch.')
            return reply_session, response[HEADER.size:]
        except EncapsulationStatus as exc:
            record['error'] = str(exc)
            raise
        except (OSError, ValueError) as exc:
            self.broken = True
            record['error'] = str(exc)
            raise
        finally:
            record['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
