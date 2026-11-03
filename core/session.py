import struct

from core.connection import EIPConnection, ProtocolError


class SessionManager:
    def __init__(self, connection: EIPConnection) -> None:
        self.connection = connection
        self.handle = 0

    def register(self) -> int:
        handle, payload = self.connection.exchange(0x0065, struct.pack('<HH', 1, 0))
        self.handle = handle
        if not handle or payload != struct.pack('<HH', 1, 0):
            raise ProtocolError('Invalid RegisterSession handle, version or options.')
        return handle

    def close(self) -> bool:
        handle, self.handle = self.handle, 0
        if handle and not self.connection.broken:
            self.connection.exchange(0x0066, session=handle, expect_response=False)
            return True
        return False
