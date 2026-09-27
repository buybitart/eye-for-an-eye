"""Operator-managed MMDB with visible provenance, no bundled data or updater."""
from pathlib import Path
from datetime import datetime, timezone


def normalize_geoip(result, language='ru'):
    if not isinstance(result, dict) or not result:
        return {'status': 'not_found'}
    def field(name):
        value = result.get(name)
        return value if isinstance(value, dict) else {}
    def display(name):
        names = field(name).get('names', {})
        value = (names.get(language) or names.get('en')) if isinstance(names, dict) else None
        return value[:256] if isinstance(value, str) else None
    code = field('country').get('iso_code')
    return {'status': 'ok', 'country': display('country'), 'city': display('city'),
            'country_code': code[:8] if isinstance(code, str) else None}


def lookup_geoip(ip, filename):
    provenance = {'data_source': 'maxmind-mmdb', 'data_version': None, 'database_mtime_ns': None,
                  'data_timestamp': datetime.now(timezone.utc).isoformat(),
                  'description': 'IP geolocation estimate; not person location'}
    try:
        stat = Path(filename).stat()
        provenance.update(database_mtime_ns=stat.st_mtime_ns, data_version=f'{stat.st_mtime_ns}:{stat.st_size}')
        import maxminddb
        with maxminddb.open_database(filename) as reader:
            result = normalize_geoip(reader.get(ip))
            provenance['build_epoch'] = reader.metadata().build_epoch
        return {**result, **provenance}
    except FileNotFoundError:
        return {'status': 'unavailable', 'reason': 'database_missing', **provenance}
    except Exception:
        return {'status': 'unavailable', 'reason': 'database_unavailable', **provenance}
