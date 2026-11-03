from dataclasses import asdict, dataclass

from modules.discovery import Identity


REVIEW_STATUSES = (
    'Not assessed', 'Needs review', 'Control verified', 'Finding recorded', 'Not applicable',
)
REFERENCES = {
    'ODVA EtherNet/IP': 'https://www.odva.org/technology-standards/key-technologies/ethernet-ip/',
    'ODVA CIP Security': 'https://www.odva.org/technology-standards/key-technologies/cip-security/',
    'NIST SP 800-82r3': 'https://csrc.nist.gov/pubs/sp/800/82/r3/final',
    'CISA ICS advisories': 'https://www.cisa.gov/news-events/ics-advisories',
}


@dataclass(frozen=True)
class AttackSurface:
    identifier: str
    title: str
    plane: str
    potential_impact: str
    method: str
    exposure: str
    verification: str
    mitigation: str


SURFACES = (
    AttackSurface('EIP-01', 'Identity disclosure', 'Encapsulation / TCP 44818', 'Informational',
                  'Implemented: ListIdentity and live discovery baseline',
                  'Device metadata may be readable without authentication.',
                  'Run the authorized identity probe; record the network vantage point. '
                  'This is not a test of CIP object access or authorization.',
                  'Restrict industrial protocol access to approved engineering and control hosts.'),
    AttackSurface('EIP-02', 'Discovery and asset visibility', 'UDP 44818', 'Moderate', 'Passive / manual',
                  'Broadcast discovery can expose assets across an overbroad broadcast domain.',
                  'Review approved packet captures, VLAN boundaries and discovery ACLs. '
                  'The framework does not broadcast or scan subnets.',
                  'Constrain broadcast domains and inventory approved device peers.'),
    AttackSurface('EIP-03', 'Session lifecycle', 'RegisterSession / TCP 44818', 'High', 'Implemented: one session lifecycle',
                  'Unbounded or poorly cleaned-up sessions may affect availability.',
                  'Run the bounded live suite to check registration and send cleanup; inspect device logs '
                  'to verify remote cleanup. Resource limits remain manual/lab-only; no session exhaustion is implemented.',
                  'Apply vendor fixes, source restrictions and connection monitoring.'),
    AttackSurface('EIP-04', 'Explicit read authorization', 'CIP object services', 'Moderate', 'Implemented: Identity attributes 1-7 only',
                  'Object attributes, tags and configuration may be exposed to untrusted clients.',
                  'The live suite reads class 0x01, instance 1, attributes 1-7 via GetAttributeSingle. '
                  'Compare results with the approved access policy. Other objects/tags require device-specific coverage.',
                  'Apply least-privilege object access and engineering network restrictions.'),
    AttackSurface('EIP-05', 'Write and control authorization', 'CIP write / reset / mode services', 'Critical',
                  'Manual policy review; active tests excluded',
                  'Unauthorized changes could alter process values, controller mode or availability.',
                  'Inspect access controls, physical mode switches and change logs. '
                  'Do not validate with production writes, resets or start/stop requests.',
                  'Enforce change authorization, protected operating modes and physical safeguards.'),
    AttackSurface('EIP-06', 'CIP Security and downgrade paths', 'Secure explicit / implicit transport', 'High',
                  'Manual configuration review',
                  'Missing peer authentication, integrity or confidentiality may expose trusted traffic.',
                  'Review device-supported CIP Security profiles, TLS/DTLS policy, certificate trust, '
                  'identity mapping and whether legacy plaintext paths remain permitted. '
                  'ListIdentity alone cannot determine these controls.',
                  'Use supported CIP Security profiles, managed trust and deny unintended legacy access.'),
    AttackSurface('EIP-07', 'Implicit I/O trust', 'UDP 2222 / cyclic I/O', 'Critical', 'Passive / manual',
                  'Untrusted I/O peers or multicast reachability can threaten process integrity.',
                  'Review approved producer/consumer captures, peer restrictions, multicast boundaries '
                  'and secure I/O capabilities. No I/O packets are generated.',
                  'Restrict I/O peers and multicast scope; use authenticated secure I/O where supported.'),
    AttackSurface('EIP-08', 'Connection ownership', 'Connection Manager / ForwardOpen', 'High',
                  'Manual review; contention tests excluded',
                  'Improper connection ownership or resource policy can interrupt legitimate I/O.',
                  'Review exclusive-owner/listen-only policy and documented connection limits. '
                  'No ForwardOpen, ownership takeover or connection contention is implemented.',
                  'Restrict originators, monitor connection changes and apply vendor guidance.'),
    AttackSurface('EIP-09', 'Routing and trust boundaries', 'Backplane / bridged CIP paths', 'High',
                  'Manual architecture review',
                  'A reachable bridge may extend access into otherwise segmented controller networks.',
                  'Review chassis routes, gateways and conduits against approved zone diagrams. '
                  'No routed object enumeration or pivoting is performed.',
                  'Enforce explicit conduit allowlists at bridges and industrial firewalls.'),
    AttackSurface('EIP-10', 'Parser robustness', 'Encapsulation / CPF / CIP lengths and paths', 'High',
                  'Lab-only planning',
                  'Malformed service data can trigger device-specific parser defects.',
                  'Review vendor advisories and existing robustness evidence. Any fuzzing requires '
                  'isolated hardware, backups, monitoring and a stop plan; no fuzzing is implemented.',
                  'Apply vendor updates and restrict protocol exposure.'),
    AttackSurface('EIP-11', 'Firmware and advisories', 'Device lifecycle', 'High', 'Manual advisory matching',
                  'An affected product and firmware build may have published vulnerabilities.',
                  'Match vendor, exact model, hardware series and firmware build against vendor/CISA '
                  'advisories. Identity revision alone is insufficient to confirm a CVE.',
                  'Track advisories and test vendor-approved patches within maintenance procedures.'),
    AttackSurface('EIP-12', 'Adjacent management services', 'HTTP(S) / SNMP / SSH / vendor engineering', 'High',
                  'Manual inventory review',
                  'Management interfaces may expose weak credentials, unsafe services or project files.',
                  'Review the approved asset inventory, management configuration and credentials policy. '
                  'No port scans, credential guessing or project downloads are performed.',
                  'Disable unused services, isolate management and enforce unique managed credentials.'),
    AttackSurface('EIP-13', 'Segmentation and remote access', 'ICS zones and conduits', 'Critical',
                  'Manual architecture review',
                  'IT, remote-access or vendor paths may provide unintended access to control traffic.',
                  'Review firewall rules, remote access approvals and source/destination paths. '
                  'A successful probe only establishes reachability from the operator host.',
                  'Use deny-by-default conduits, controlled jump hosts and monitored remote access.'),
    AttackSurface('EIP-14', 'Detection and recovery', 'Operational resilience', 'High', 'Manual operations review',
                  'Undetected engineering changes or unavailable recovery assets amplify incidents.',
                  'Review protocol-aware alerts, time synchronization, configuration baselines, '
                  'offline backups and tested restoration procedures.',
                  'Monitor identity/session/configuration changes and exercise recovery in a safe environment.'),
)


class SecurityAssessment:
    def __init__(self) -> None:
        self.reviews: dict[str, dict[str, str]] = {}

    def record_review(self, identifier: str, status: str, evidence: str) -> None:
        if identifier not in {surface.identifier for surface in SURFACES}:
            raise ValueError('Unknown attack-surface identifier.')
        if status not in REVIEW_STATUSES:
            raise ValueError('Unknown review status.')
        evidence = evidence.strip()
        if status != 'Not assessed' and not evidence:
            raise ValueError('Evidence or rationale is required for a review decision.')
        if len(evidence) > 10000:
            raise ValueError('Keep evidence within 10,000 characters.')
        self.reviews[identifier] = {'status': status, 'evidence': evidence}

    def catalog(self) -> list[dict[str, str]]:
        return [dict(asdict(surface), **self.reviews.get(
            surface.identifier, {'status': 'Not assessed', 'evidence': ''}
        )) for surface in SURFACES]

    @staticmethod
    def observations(identities: list[Identity]) -> list[dict[str, str]]:
        if not identities:
            return []
        return [{
            'identifier': 'OBS-01',
            'classification': 'Informational observation, not a confirmed vulnerability',
            'summary': 'A plaintext ListIdentity request returned device identity metadata.',
            'evidence': f'{len(identities)} identity item(s) returned without registering a session.',
            'limits': 'Does not establish CIP read/write access, absent CIP Security, '
                      'firmware vulnerability, process state or overall security posture.',
        }]
