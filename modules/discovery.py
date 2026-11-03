import ipaddress
import secrets
import socket
import struct
import time
from dataclasses import dataclass


HEADER = struct.Struct('<HHII8sI')
LIST_IDENTITY = 0x0063
MAX_PAYLOAD = 16384


class DiscoveryError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    address: str
    port: int
    protocol_version: int
    vendor_id: int
    device_type: int
    product_code: int
    revision: str
    status: int
    serial_number: str
    product_name: str
    state: int


def validate_target(target: str) -> str:
    try:
        address = ipaddress.IPv4Address(target.strip())
    except ipaddress.AddressValueError as exc:
        raise DiscoveryError('Enter one literal IPv4 address, not a hostname or range.') from exc
    if address.is_multicast or address.is_unspecified or int(address) == 0xFFFFFFFF:
        raise DiscoveryError('A unicast IPv4 target is required.')
    return str(address)


def parse_identity_payload(payload: bytes) -> list[Identity]:
    if len(payload) < 2:
        raise DiscoveryError('Missing identity item count.')
    count = struct.unpack_from('<H', payload)[0]
    offset = 2
    identities = []
    for _ in range(count):
        if offset + 4 > len(payload):
            raise DiscoveryError('Truncated identity item header.')
        item_type, size = struct.unpack_from('<HH', payload, offset)
        offset += 4
        if offset + size > len(payload):
            raise DiscoveryError('Truncated identity item.')
        item = payload[offset:offset + size]
        offset += size
        if item_type != 0x000C:
            continue
        if len(item) < 34:
            raise DiscoveryError('Identity item is too short.')
        name_size = item[32]
        if len(item) != 34 + name_size:
            raise DiscoveryError('Invalid product name length.')
        family, port = struct.unpack_from('>HH', item, 2)
        if family != socket.AF_INET:
            raise DiscoveryError('Unsupported identity address family.')
        vendor, device, product = struct.unpack_from('<HHH', item, 18)
        identities.append(Identity(
            address=socket.inet_ntoa(item[6:10]),
            port=port,
            protocol_version=struct.unpack_from('<H', item)[0],
            vendor_id=vendor,
            device_type=device,
            product_code=product,
            revision=f'{item[24]}.{item[25]}',
            status=struct.unpack_from('<H', item, 26)[0],
            serial_number=f'{struct.unpack_from("<I", item, 28)[0]:08X}',
            product_name=item[33:33 + name_size].decode('utf-8', errors='replace'),
            state=item[33 + name_size],
        ))
    if offset != len(payload):
        raise DiscoveryError('Unexpected trailing identity data.')
    return identities


def _receive_exact(connection: socket.socket, size: int, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Identity response deadline exceeded.')
        connection.settimeout(remaining)
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise DiscoveryError('Connection closed before the response was complete.')
        chunks.extend(chunk)
    return bytes(chunks)


class Discovery:
    def discover(self, target: str, timeout: float = 3.0) -> list[Identity]:
        address = validate_target(target)
        if not 0.2 <= timeout <= 5.0:
            raise DiscoveryError('Timeout must be between 0.2 and 5 seconds.')
        context = secrets.token_bytes(8)
        request = HEADER.pack(LIST_IDENTITY, 0, 0, 0, context, 0)
        deadline = time.monotonic() + timeout
        with socket.create_connection((address, 44818), timeout=timeout) as connection:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Identity request deadline exceeded.')
            connection.settimeout(remaining)
            connection.sendall(request)
            header = _receive_exact(connection, HEADER.size, deadline)
            command, size, session, status, echoed_context, options = HEADER.unpack(header)
            if command != LIST_IDENTITY or echoed_context != context:
                raise DiscoveryError('Response does not match the identity request.')
            if status:
                raise DiscoveryError(f'Encapsulation error: 0x{status:08X}.')
            if session or options:
                raise DiscoveryError('Unexpected session or options in identity response.')
            if size > MAX_PAYLOAD:
                raise DiscoveryError('Identity response exceeds the size limit.')
            return parse_identity_payload(_receive_exact(connection, size, deadline))
