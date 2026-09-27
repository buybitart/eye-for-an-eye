"""Providers load optional dependencies only inside an explicitly started job."""
import ipaddress
from .geoip import normalize_geoip, lookup_geoip
from .rdap import lookup_rdap

__all__ = ['lookup', 'normalize_geoip', 'normalize_whois']


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _text(value):
    return value[:256] if isinstance(value, str) else None


def normalize_whois(result):
    nets = _mapping(result).get('nets')
    if not isinstance(nets, list) or not nets:
        return {'status': 'not_found'}
    network = _mapping(nets[0])
    return {'status': 'ok', 'network_name': _text(network.get('name')),
            'description': _text(network.get('description')), 'identity_claim': False}


def lookup(ip, options):
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {'status': 'not_found', 'reason': 'non_global_address'}
    result = {'status': 'ok'}
    if options.get('mmdb_path'):
        result['geoip'] = lookup_geoip(ip, options['mmdb_path'])
    if options.get('rdap_enabled', False):
        result['rdap'] = lookup_rdap(ip, options.get('timeout', 2))
    if len(result) == 1:
        return {'status': 'not_found', 'reason': 'no_provider_configured'}
    if any(isinstance(value, dict) and value.get('status') == 'unavailable' for value in result.values()):
        result['status'] = 'unavailable'
    elif all(value.get('status') == 'not_found' for value in result.values() if isinstance(value, dict)):
        result['status'] = 'not_found'
    return result
