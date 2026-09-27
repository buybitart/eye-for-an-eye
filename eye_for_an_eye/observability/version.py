from pathlib import Path
from .. import __version__
from ..events import SCHEMA_VERSION
from ..deception.profiles import CATALOGUE_VERSION
from ..storage.sqlite import SCHEMA_VERSION as DB_VERSION
from ..config import CONFIG_VERSION


def version_info(config):
    def data_info(filename):
        if not filename:
            return {'status': 'not_configured'}
        try:
            stat = Path(filename).stat()
            return {'status': 'present', 'mtime': stat.st_mtime, 'size': stat.st_size,
                    'version': 'operator_data_version_unknown'}
        except OSError:
            return {'status': 'unavailable'}
    return {'application': __version__, 'config_schema': CONFIG_VERSION, 'event_schema': SCHEMA_VERSION, 'profile_catalogue': CATALOGUE_VERSION,
            'database_schema': DB_VERSION, 'p0f_data': data_info(config.capture.p0f_db),
            'geoip_data': data_info(config.enrichment.mmdb_path)}
