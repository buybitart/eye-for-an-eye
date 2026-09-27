"""The normalised web request this project is willing to look at.

A `WebEvent` is deliberately much smaller than an HTTP request. It carries what
behaviour analysis needs — how many, how fast, how varied, how many failures —
and nothing that would make the file dangerous to keep.

What is refused, always, at construction:

    Authorization headers      cookies and session tokens
    request bodies             passwords and form data
    query parameter values     full paths, unless explicitly enabled

The last one deserves its own sentence. A URL routinely contains a password
reset token, an account id, an email address or a search term. Storing paths by
default would turn a security tool into a log of what every visitor read. So the
default is derived features — depth, length, extension, entropy — plus a keyed
digest for counting repeats, and the path itself is dropped.

The other reason this module exists is that the values inside a request are
written by whoever sent it. Every string here is length-bounded and stripped of
control characters, because a log line that can carry a newline can carry a
forged second log line.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import math
import re

WEB_EVENT_SCHEMA_VERSION = 1

#: Bounds. Every one of these is applied to attacker-controlled input.
MAX_PATH_CHARS = 2048
MAX_QUERY_CHARS = 2048
MAX_METHOD_CHARS = 16
MAX_HOST_CHARS = 253
MAX_AGENT_CHARS = 512
MAX_PATH_SEGMENTS = 32

#: Methods this project recognises. Anything else is recorded as `OTHER` rather
#: than stored, so a made-up method cannot become a cardinality problem.
KNOWN_METHODS = ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS',
                 'TRACE', 'CONNECT', 'PROPFIND')
OTHER_METHOD = 'OTHER'

#: Extension families. Coarse on purpose: the question is "was this a page, an
#: asset, or something that looks like a file that should not be served", not
#: "which file".
STATIC_EXTENSIONS = frozenset((
    'css', 'js', 'mjs', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'ico',
    'woff', 'woff2', 'ttf', 'otf', 'eot', 'map', 'mp4', 'webm', 'mp3', 'wav'))
DOCUMENT_EXTENSIONS = frozenset(('html', 'htm', 'xhtml', 'txt', 'xml', 'json', 'pdf'))
SCRIPT_EXTENSIONS = frozenset(('php', 'asp', 'aspx', 'jsp', 'cgi', 'pl', 'py', 'rb'))
ARCHIVE_EXTENSIONS = frozenset(('zip', 'tar', 'gz', 'tgz', 'bz2', 'rar', '7z', 'bak',
                                'old', 'swp', 'sql', 'dump'))

EXTENSION_CATEGORIES = ('none', 'static', 'document', 'script', 'archive', 'other')

#: Bounded probe categories. These are *categories*, not a signature database:
#: six ideas, each explainable in one line, each contributing evidence and never
#: a decision on its own. A single request to any of them is normal somewhere.
SENSITIVE_CATEGORIES = ('configuration', 'admin', 'backup', 'version_control',
                        'cms', 'database_admin')

_SENSITIVE_PATTERNS = (
    ('configuration', re.compile(
        r'(^|/)(\.env(\.|$)|config\.(php|json|ya?ml)|settings\.py|web\.config|\.aws/|'
        r'\.ssh/|id_rsa|\.npmrc|\.htpasswd)', re.I)),
    ('admin', re.compile(
        r'(^|/)(admin|administrator|manager|console|dashboard|cpanel|webadmin)(/|$)', re.I)),
    ('backup', re.compile(
        r'\.(bak|old|swp|save|orig|tar|tar\.gz|tgz|zip|sql|dump)$|(^|/)backups?(/|$)', re.I)),
    ('version_control', re.compile(r'(^|/)(\.git|\.svn|\.hg|\.bzr)(/|$)', re.I)),
    ('cms', re.compile(
        r'(^|/)(wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php|'
        r'administrator/index\.php|typo3|joomla|drupal)(/|$|\.)', re.I)),
    ('database_admin', re.compile(
        r'(^|/)(phpmyadmin|pma|adminer|myadmin|dbadmin|sqlmanager)(/|$|\.)', re.I)),
)

#: Field names that must never appear in a stored web event, whatever a caller
#: passes. Checked at construction so a mistake fails loudly rather than quietly
#: writing a credential to disk.
FORBIDDEN_FIELDS = ('authorization', 'cookie', 'set_cookie', 'password', 'passwd',
                    'token', 'session', 'body', 'payload', 'api_key', 'apikey',
                    'secret', 'credentials', 'auth_header')

_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_PERCENT = re.compile(r'%[0-9a-fA-F]{2}')


class WebEventError(ValueError):
    """A web event could not be built safely. Refusing is the safe outcome."""


def clean_text(value, limit):
    """Bound a string and strip anything that could forge a log line.

    Control characters are removed rather than escaped: nothing downstream needs
    them, and removing them means a newline cannot survive into a log, a report
    or a terminal.
    """
    if value is None:
        return ''
    text = str(value)[:limit]
    return _CONTROL.sub('', text)


def normalise_method(value):
    """A method name, or `OTHER`. Never an arbitrary attacker-chosen string."""
    text = clean_text(value, MAX_METHOD_CHARS).upper().strip()
    return text if text in KNOWN_METHODS else OTHER_METHOD


def normalise_path(value):
    """One well-defined normalisation pass, for analysis only.

    This never tells the web server what to do; the server already decided. It
    exists so that `/a/./b`, `/a/b` and `/a/%2e/b` produce the same behavioural
    features, because to a person watching a scanner they are the same request.

    Percent-decoding happens **once**. Repeated decoding is how a normaliser ends
    up seeing something different from the server that served it, which is the
    classic way a security analyser and a web server disagree.
    """
    text = clean_text(value, MAX_PATH_CHARS)
    if not text:
        return '/'
    text = text.split('#', 1)[0].split('?', 1)[0]
    try:
        from urllib.parse import unquote
        decoded = unquote(text, errors='replace')
    except (ValueError, UnicodeDecodeError):
        decoded = text
    decoded = _CONTROL.sub('', decoded).replace('\\', '/')
    segments = []
    for segment in decoded.split('/')[:MAX_PATH_SEGMENTS + 1]:
        if segment in ('', '.'):
            continue
        if segment == '..':
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return '/' + '/'.join(segments)


def extension_category(path):
    """Which family the last path segment belongs to."""
    tail = path.rsplit('/', 1)[-1]
    if '.' not in tail:
        return 'none'
    extension = tail.rsplit('.', 1)[-1].lower()[:12]
    if not extension:
        return 'none'
    if extension in STATIC_EXTENSIONS:
        return 'static'
    if extension in DOCUMENT_EXTENSIONS:
        return 'document'
    if extension in SCRIPT_EXTENSIONS:
        return 'script'
    if extension in ARCHIVE_EXTENSIONS:
        return 'archive'
    return 'other'


def sensitive_categories(path):
    """Which bounded probe categories this path matches. Evidence, never a verdict.

    A request to `/wp-admin` might be an administrator, a scanner, a monitoring
    check, or somebody's bookmark. What matters is what else the same source did,
    and that is decided far away from here.
    """
    return tuple(name for name, pattern in _SENSITIVE_PATTERNS if pattern.search(path))


def shannon_entropy(text):
    """Entropy per character, bounded to [0, 1] against a 64-symbol alphabet.

    A generated path (`/a8f3k2/x91z`) scores high; a real one (`/blog/about`)
    scores low. It is one weak feature among many, not a detector.
    """
    if not text:
        return 0.0
    counts = {}
    for character in text[:MAX_PATH_CHARS]:
        counts[character] = counts.get(character, 0) + 1
    total = len(text[:MAX_PATH_CHARS])
    entropy = -sum((n / total) * math.log2(n / total) for n in counts.values())
    return min(1.0, entropy / 6.0)


def encoded_ratio(text):
    """How much of this string is percent-encoded. Bounded, cheap, weak evidence."""
    if not text:
        return 0.0
    encoded = sum(len(match.group(0)) for match in _PERCENT.finditer(text[:MAX_QUERY_CHARS]))
    return min(1.0, encoded / max(1, len(text[:MAX_QUERY_CHARS])))


def query_shape(value):
    """Bounded metadata about a query string. The values are never kept.

    A query string carries search terms, tokens and account identifiers. Its
    *shape* — how many parameters, how long, how much encoding — is behavioural
    and safe; its content is not.
    """
    text = clean_text(value, MAX_QUERY_CHARS)
    if not text:
        return {'query_present': False, 'query_length': 0, 'query_parameters': 0,
                'query_encoded_ratio': 0.0, 'query_duplicate_parameters': False}
    parts = text.split('&')[:64]
    names = [part.split('=', 1)[0][:64] for part in parts if part]
    return {'query_present': True,
            'query_length': len(text),
            'query_parameters': len(names),
            'query_encoded_ratio': round(encoded_ratio(text), 4),
            'query_duplicate_parameters': len(names) != len(set(names))}


def path_digest(path, secret):
    """A keyed digest for counting repeats without keeping the path.

    Truncated and keyed, so the file says "this source asked for the same thing
    nine times" without saying what the thing was. It is a counting key. It is
    never a model feature and carries no meaning of its own.
    """
    if not secret:
        return ''
    return hmac.new(secret, path.encode()[:MAX_PATH_CHARS], hashlib.sha256).hexdigest()[:16]


def agent_shape(value):
    """Derived User-Agent features. The string itself is never stored.

    A User-Agent is a claim, not an identity: anything can say it is Googlebot.
    So what is kept is shape — present or missing, how long, which broad family —
    and even that is weak evidence deliberately kept away from strong actions.
    """
    text = clean_text(value, MAX_AGENT_CHARS).strip()
    if not text or text == '-':
        return {'agent_present': False, 'agent_length': 0, 'agent_family': 'none',
                'agent_digest': ''}
    lowered = text.lower()
    if 'bot' in lowered or 'crawler' in lowered or 'spider' in lowered:
        family = 'declared_bot'
    elif any(name in lowered for name in ('curl', 'wget', 'python', 'go-http', 'java/',
                                          'libwww', 'okhttp', 'axios', 'httpx')):
        family = 'declared_tool'
    elif any(name in lowered for name in ('mozilla', 'chrome', 'safari', 'firefox', 'edge')):
        family = 'declared_browser'
    else:
        family = 'other'
    return {'agent_present': True, 'agent_length': len(text), 'agent_family': family,
            'agent_digest': hashlib.sha256(text.encode()).hexdigest()[:12]}


@dataclass(frozen=True)
class WebEvent:
    """One web request, reduced to what is safe to keep and useful to analyse."""

    timestamp: datetime
    client: str
    peer: str
    identity_confidence: str
    network_enforceable: bool
    method: str
    status: int
    path_depth: int
    path_length: int
    path_entropy: float
    extension: str
    sensitive: tuple = ()
    path_key: str = ''
    host_key: str = ''
    protocol: str = ''
    request_bytes: int = 0
    response_bytes: int = 0
    duration_ms: float | None = None
    referer_present: bool = False
    auth_outcome: str = ''
    query: dict = field(default_factory=dict)
    agent: dict = field(default_factory=dict)
    service: str = ''
    #: The normalised path, kept only when an operator explicitly asked for it.
    #: Empty by default, and nothing downstream is allowed to require it: a URL
    #: routinely carries a reset token, an account id or a search term.
    stored_path: str = ''
    schema_version: int = WEB_EVENT_SCHEMA_VERSION

    def __post_init__(self):
        if self.schema_version != WEB_EVENT_SCHEMA_VERSION:
            raise WebEventError('unsupported web event schema')
        if self.method not in KNOWN_METHODS + (OTHER_METHOD,):
            raise WebEventError(f'unnormalised method: {self.method!r}')
        if not isinstance(self.status, int) or not 0 <= self.status <= 599:
            raise WebEventError('status must be an integer between 0 and 599')
        if self.identity_confidence not in ('HIGH', 'MEDIUM', 'LOW'):
            raise WebEventError('unknown identity confidence')
        for name in self.sensitive:
            if name not in SENSITIVE_CATEGORIES:
                raise WebEventError(f'unknown sensitive category: {name!r}')
        if self.auth_outcome not in ('', 'success', 'failure'):
            raise WebEventError('auth_outcome must be empty, success or failure')
        for container in (self.query, self.agent):
            for key in container:
                if any(bad in str(key).lower() for bad in FORBIDDEN_FIELDS):
                    raise WebEventError(f'a web event must not carry {key!r}')

    @property
    def status_family(self):
        return f'{self.status // 100}xx' if self.status else 'none'

    @property
    def is_static(self):
        return self.extension == 'static'

    def explain(self):
        """What a person or a report may see. No path, no query values, no agent."""
        return {'web_event_schema_version': WEB_EVENT_SCHEMA_VERSION,
                'at': self.timestamp.isoformat().replace('+00:00', 'Z'),
                'client': self.client, 'identity_confidence': self.identity_confidence,
                'network_enforceable': self.network_enforceable,
                'method': self.method, 'status': self.status,
                'path_depth': self.path_depth, 'path_length': self.path_length,
                'path_entropy': round(self.path_entropy, 4),
                'extension': self.extension, 'sensitive': list(self.sensitive),
                'protocol': self.protocol, 'response_bytes': self.response_bytes,
                'duration_ms': self.duration_ms, 'referer_present': self.referer_present,
                'auth_outcome': self.auth_outcome or 'unknown',
                'query': dict(self.query), 'agent': dict(self.agent),
                'contents': ('behavioural metadata only; no path, no query values, no '
                             'header, no body, no credential')}


def build(*, timestamp, identity, method, path, query='', status=0, host='',
          protocol='', request_bytes=0, response_bytes=0, duration_ms=None,
          referer='', user_agent='', auth_outcome='', service='', secret=None,
          store_path=False):
    """Turn raw request metadata into a `WebEvent`. The one place redaction happens.

    Every caller — the Nginx reader, a test fixture, a future Apache reader —
    comes through here, so there is exactly one place to audit for "could this
    store a secret".
    """
    normalised = normalise_path(path)
    host_text = clean_text(host, MAX_HOST_CHARS).lower()
    return WebEvent(
        timestamp=timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc),
        client=identity.address, peer=identity.peer_address,
        identity_confidence=identity.confidence,
        network_enforceable=identity.network_enforceable,
        method=normalise_method(method),
        status=int(status) if str(status).isdigit() and 0 <= int(status) <= 599 else 0,
        path_depth=min(MAX_PATH_SEGMENTS, normalised.count('/')),
        path_length=len(normalised),
        path_entropy=shannon_entropy(normalised),
        extension=extension_category(normalised),
        sensitive=sensitive_categories(normalised),
        path_key=path_digest(normalised, secret),
        host_key=(hashlib.sha256(host_text.encode()).hexdigest()[:12] if host_text else ''),
        protocol=clean_text(protocol, 16),
        request_bytes=max(0, int(request_bytes or 0)),
        response_bytes=max(0, int(response_bytes or 0)),
        duration_ms=(None if duration_ms is None else max(0.0, float(duration_ms))),
        referer_present=bool(clean_text(referer, 16).strip() not in ('', '-')),
        auth_outcome=auth_outcome if auth_outcome in ('success', 'failure') else '',
        query=query_shape(query), agent=agent_shape(user_agent),
        service=clean_text(service, 64),
        stored_path=normalised if store_path else '')

