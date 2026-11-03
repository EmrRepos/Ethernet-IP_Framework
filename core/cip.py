import struct
from dataclasses import dataclass

from core.connection import ProtocolError
from core.session import SessionManager


@dataclass(frozen=True)
class CIPResponse:
    general_status: int
    additional_status: tuple[int, ...]
    data: bytes


def parse_cip_response(payload: bytes) -> CIPResponse:
    if len(payload) < 4:
        raise ProtocolError('Truncated CIP response header.')
    service, reserved, status, words = struct.unpack_from('<BBBB', payload)
    if service != 0x8E or reserved:
        raise ProtocolError('Unexpected CIP response service or reserved byte.')
    end = 4 + words * 2
    if end > len(payload):
        raise ProtocolError('Truncated CIP additional status.')
    additional = struct.unpack_from(f'<{words}H', payload, 4) if words else ()
    return CIPResponse(status, additional, payload[end:])


def parse_rr_data(payload: bytes) -> CIPResponse:
    if len(payload) < 8:
        raise ProtocolError('Truncated SendRRData header.')
    interface, timeout, count = struct.unpack_from('<IHH', payload)
    if interface != 0 or count != 2:
        raise ProtocolError('Unexpected SendRRData interface or item count.')
    offset = 8
    items = []
    for _ in range(count):
        if offset + 4 > len(payload):
            raise ProtocolError('Truncated CPF item header.')
        item_type, size = struct.unpack_from('<HH', payload, offset)
        offset += 4
        if offset + size > len(payload):
            raise ProtocolError('Truncated CPF item.')
        items.append((item_type, payload[offset:offset + size]))
        offset += size
    if offset != len(payload) or items[0] != (0, b'') or items[1][0] != 0x00B2:
        raise ProtocolError('Unexpected CPF item layout or trailing data.')
    return parse_cip_response(items[1][1])


def decode_identity_attribute(attribute: int, data: bytes):
    sizes = {1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 4}
    if attribute in sizes:
        if len(data) != sizes[attribute]:
            raise ProtocolError('Identity attribute has an unexpected length.')
        if attribute == 4:
            return f'{data[0]}.{data[1]}'
        if attribute == 6:
            return f'{struct.unpack("<I", data)[0]:08X}'
        return struct.unpack('<H', data)[0]
    if attribute == 7:
        if not data or len(data) != data[0] + 1:
            raise ProtocolError('Invalid Identity product-name SHORT_STRING length.')
        return data[1:].decode('utf-8', errors='replace')
    raise ValueError('Only Identity attributes 1 through 7 are allowed.')


class CIPClient:
    def __init__(self, session: SessionManager) -> None:
        self.session = session

    def read_identity_attribute(self, attribute: int) -> CIPResponse:
        if attribute not in range(1, 8):
            raise ValueError('Only Identity attributes 1 through 7 are allowed.')
        if not self.session.handle:
            raise ProtocolError('RegisterSession is required before CIP reads.')
        request = bytes((0x0E, 3, 0x20, 1, 0x24, 1, 0x30, attribute))
        payload = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0x00B2, len(request)) + request
        _, response = self.session.connection.exchange(0x006F, payload, self.session.handle)
        return parse_rr_data(response)
