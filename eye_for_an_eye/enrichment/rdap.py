from dataclasses import asdict, dataclass
from importlib.metadata import version
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class NetworkRegistration:
    status: str
    asn: int | None = None
    network_name: str | None = None
    cidr: str | None = None
    country: str | None = None
    source: str = 'rdap'
    data_source: str = 'ipwhois-rdap'
    data_version: str | None = None
    identity_claim: bool = False


def normalize_rdap(result):
    data = result if isinstance(result, dict) else {}
    network = data.get('network') if isinstance(data.get('network'), dict) else {}
    def text(value):
        return value[:256] if isinstance(value, str) else None
    raw_asn = data.get('asn')
    try:
        asn = int(raw_asn) if type(raw_asn) in (str, int) else None
        if asn is not None and not 0 <= asn <= 0xffffffff:
            asn = None
    except ValueError:
        asn = None
    return NetworkRegistration('ok' if network or asn is not None else 'not_found', asn,
                               text(network.get('name')), text(network.get('cidr')), text(network.get('country')))


def lookup_rdap(ip, timeout):
    try:
        from ipwhois import IPWhois
        result = normalize_rdap(IPWhois(ip, timeout=timeout).lookup_rdap(depth=0, retry_count=0))
        return {**asdict(result), 'data_version': version('ipwhois'),
                'data_timestamp': datetime.now(timezone.utc).isoformat(), 'description': 'registered network; not source identity'}
    except Exception:
        return {'status': 'unavailable', 'reason': 'lookup_failed', 'data_source': 'ipwhois-rdap', 'data_version': None,
                'data_timestamp': datetime.now(timezone.utc).isoformat()}
