import hashlib
import json
import struct
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone

from core.cip import CIPClient, decode_identity_attribute
from core.connection import EIPConnection, EncapsulationStatus, ProtocolError
from core.session import SessionManager
from modules.discovery import parse_identity_payload, validate_target


ATTRIBUTE_NAMES = {1: 'vendor_id', 2: 'device_type', 3: 'product_code', 4: 'revision',
                   5: 'status', 6: 'serial_number', 7: 'product_name'}
LIVE_CASES = (
    ('ENIP-01', 'ListIdentity framing and metadata'),
    ('ENIP-02', 'ListServices response structure'),
    ('ENIP-03', 'ListInterfaces response structure'),
    ('ENIP-04', 'RegisterSession version, options and handle'),
    *((f'CIP-{attribute:02}', f'Identity instance 1 / {name}') for attribute, name in ATTRIBUTE_NAMES.items()),
    ('ENIP-05', 'UnregisterSession send and local socket cleanup'),
)
COVERAGE_GAPS = (
    ('UDP discovery and implicit I/O', 'not_implemented', 'Requires approved UDP/peer-specific tests.'),
    ('Connected messaging and ForwardOpen', 'not_implemented', 'Requires device ownership and connection policy.'),
    ('Routed CIP and backplane paths', 'not_implemented', 'Requires explicit approved routes and device profile.'),
    ('Vendor objects, tags and assemblies', 'requires_device_profile', 'Requires EDS/vendor service documentation.'),
    ('Authorization and negative-access assertions', 'requires_device_profile', 'Requires expected ACLs and approved client identities.'),
    ('CIP Security TLS/DTLS and certificates', 'manual_review', 'No secure transport handshake is implemented.'),
    ('Write, reset, controller mode and firmware services', 'excluded', 'Can change physical process state.'),
    ('Malformed requests, fuzzing and resource exhaustion', 'excluded', 'Requires separate instrumented isolated-lab scope.'),
    ('CIP Safety, Motion, Sync and other profiles', 'not_implemented', 'Requires applicable device/profile specifications.'),
    ('CVE applicability and firmware matching', 'manual_review', 'Identity revision is not sufficient evidence.'),
)


class RunStopped(Exception):
    pass


def coverage_matrix() -> list[dict[str, str]]:
    return ([{'id': identifier, 'area': title, 'coverage': 'implemented_live_read_only',
              'limits': 'Observation or protocol anomaly, not a vulnerability/conformance verdict.'}
             for identifier, title in LIVE_CASES]
            + [{'id': f'GAP-{index:02}', 'area': area, 'coverage': coverage, 'limits': limits}
               for index, (area, coverage, limits) in enumerate(COVERAGE_GAPS, 1)])


def parse_discovery_items(payload: bytes, services: bool = False) -> list[dict]:
    if len(payload) < 2:
        raise ProtocolError('Missing discovery item count.')
    count = struct.unpack_from('<H', payload)[0]
    offset = 2
    result = []
    for _ in range(count):
        if offset + 4 > len(payload):
            raise ProtocolError('Truncated discovery item header.')
        item_type, size = struct.unpack_from('<HH', payload, offset)
        offset += 4
        if offset + size > len(payload):
            raise ProtocolError('Truncated discovery item data.')
        data = payload[offset:offset + size]
        offset += size
        item = {'type': item_type, 'data_hex': data.hex()}
        if services and item_type == 0x0100:
            if len(data) != 20:
                raise ProtocolError('ListServices item length is not 20 bytes.')
            version, flags = struct.unpack_from('<HH', data)
            item.update(version=version, capability_flags=flags,
                        name=data[4:].split(b'\x00', 1)[0].decode('ascii', errors='replace'))
        result.append(item)
    if offset != len(payload):
        raise ProtocolError('Unexpected trailing discovery data.')
    return result


class LiveTestRunner:
    def __init__(self, timeout: float = 3.0) -> None:
        if not 0.2 <= timeout <= 5.0:
            raise ValueError('Timeout must be between 0.2 and 5 seconds.')
        self.timeout = timeout

    def run(self, target: str, operator: str, authorized: bool = False,
            cancel: threading.Event | None = None) -> dict:
        target = validate_target(target)
        if not authorized or not operator.strip():
            raise ValueError('Live tests require authorization and an operator/scope reference.')
        cancel = cancel if cancel is not None else threading.Event()
        started = time.monotonic()
        deadline = started + 30.0
        connection = EIPConnection(target, self.timeout)
        results = {identifier: {'id': identifier, 'title': title, 'status': 'not_run',
                                'detail': 'Not reached.', 'exchange_indices': []}
                   for identifier, title in LIVE_CASES}
        identities = []
        attribute_values = {}
        consistency = []
        session = SessionManager(connection)
        run = {'suite': 'bounded-identity-baseline-v1', 'target': target, 'operator': operator.strip(),
               'authorization_attested': True, 'started_at_utc': datetime.now(timezone.utc).isoformat(),
               'outcome': 'completed', 'stop_reason': None,
               'limits': {'max_requests': 12, 'max_sessions': 1, 'max_payload_bytes': 16384,
                          'request_timeout_seconds': self.timeout,
                          'minimum_request_interval_seconds': 0.25, 'work_budget_seconds': 30,
                          'cleanup_send_budget_seconds': self.timeout, 'automatic_retries': 0}}
        last_request = None

        def before_request():
            nonlocal last_request
            if cancel.is_set():
                raise RunStopped('Cancelled by operator; no further test requests sent.')
            now = time.monotonic()
            delay = 0 if last_request is None else max(0.0, 0.25 - (now - last_request))
            if now + delay >= deadline:
                raise RunStopped('30-second work budget reached.')
            if delay and cancel.wait(delay):
                raise RunStopped('Cancelled by operator; no further test requests sent.')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunStopped('30-second work budget reached.')
            connection.timeout = min(self.timeout, remaining)
            last_request = time.monotonic()

        def execute(identifier, operation):
            before_request()
            result = results[identifier]
            index = len(connection.exchanges)
            try:
                value = operation()
                result.update(status='observed', detail='Valid response observed; no security verdict.')
                return value
            except EncapsulationStatus as exc:
                result.update(status='unsupported' if exc.status == 1 else 'inconclusive', detail=str(exc))
                if exc.status != 1:
                    raise
            except OSError as exc:
                result.update(status='inconclusive', detail=str(exc))
                raise
            except ValueError as exc:
                result.update(status='protocol_anomaly', detail=str(exc))
                raise
            finally:
                result['exchange_indices'] = list(range(index, len(connection.exchanges)))

        try:
            if cancel.is_set():
                raise RunStopped('Cancelled before connecting.')
            with connection:
                try:
                    def identity_read():
                        _, payload = connection.exchange(0x0063)
                        return parse_identity_payload(payload)
                    identities = execute('ENIP-01', identity_read) or []
                    if results['ENIP-01']['status'] == 'observed' and not identities:
                        results['ENIP-01'].update(status='inconclusive', detail='No identity items returned.')
                    for identifier, command, services in (('ENIP-02', 0x0004, True), ('ENIP-03', 0x0064, False)):
                        def discovery_read(command=command, services=services):
                            _, payload = connection.exchange(command)
                            return parse_discovery_items(payload, services)
                        items = execute(identifier, discovery_read)
                        if items is not None:
                            results[identifier]['items'] = items
                    handle = execute('ENIP-04', session.register)
                    if handle:
                        client = CIPClient(session)
                        for attribute, name in ATTRIBUTE_NAMES.items():
                            identifier = f'CIP-{attribute:02}'
                            decoded = {}
                            def cip_read(attribute=attribute):
                                response = client.read_identity_attribute(attribute)
                                if response.general_status == 0:
                                    decoded['value'] = decode_identity_attribute(attribute, response.data)
                                return response
                            response = execute(identifier, cip_read)
                            if response is None:
                                continue
                            result = results[identifier]
                            result.update(general_status=f'0x{response.general_status:02X}',
                                          additional_status=list(response.additional_status), data_hex=response.data.hex())
                            if response.general_status:
                                status = ('access_denied' if response.general_status == 0x0F else
                                          'unsupported' if response.general_status in (0x05, 0x08, 0x14, 0x16) else 'inconclusive')
                                result.update(status=status, detail='CIP rejection observed; check vendor policy and status definition.')
                            else:
                                result['value'] = decoded['value']
                                attribute_values[name] = decoded['value']
                finally:
                    if session.handle and not connection.broken:
                        result = results['ENIP-05']
                        index = len(connection.exchanges)
                        try:
                            if last_request is not None:
                                threading.Event().wait(max(0.0, 0.25 - (time.monotonic() - last_request)))
                            connection.timeout = self.timeout
                            session.close()
                            result.update(status='observed', detail='UnregisterSession sent; no reply is specified. '
                                          'Local socket closure does not prove remote session deletion.')
                        except (OSError, ValueError) as exc:
                            result.update(status='inconclusive', detail=f'Cleanup send failed: {exc}')
                        finally:
                            result['exchange_indices'] = list(range(index, len(connection.exchanges)))
        except (RunStopped, OSError, ValueError) as exc:
            run['outcome'] = 'cancelled' if cancel.is_set() else 'incomplete'
            run['stop_reason'] = str(exc)
        for result in results.values():
            if result['status'] == 'not_run':
                result['detail'] = run['stop_reason'] or 'Dependency unavailable or no session was established.'
        if len(identities) == 1:
            identity_values = asdict(identities[0])
            for name, value in attribute_values.items():
                if name == 'status':
                    continue
                if identity_values[name] != value:
                    consistency.append({'field': name, 'list_identity_value': identity_values[name], 'cip_value': value,
                                        'classification': 'Needs developer review; a gateway or changing state may explain differences.'})
        evidence = connection.exchanges
        run.update(completed_at_utc=datetime.now(timezone.utc).isoformat(),
                   elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                   identities=[asdict(identity) for identity in identities], attribute_values=attribute_values,
                   test_results=list(results.values()), consistency_observations=consistency,
                   exchanges=evidence, coverage=coverage_matrix(),
                   evidence_sha256=hashlib.sha256(json.dumps(evidence, sort_keys=True).encode('utf-8')).hexdigest())
        return run