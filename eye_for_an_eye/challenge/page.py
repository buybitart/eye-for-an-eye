"""The challenge response: a cookie, a small page, and a safe way back.

Three things here are easy to get wrong, and each has taken real sites down or
opened real holes:

**Open redirect.** The challenge sends a client back where it was going. If the
destination comes from the request unchecked, the challenge page becomes an open
redirector — a phishing tool hosted on the protected site. So a return target is
accepted only as a local path, and everything else is discarded in favour of `/`.

**HTML injection.** The return path comes from the client. Putting it into a page
unescaped is a cross-site scripting hole in the security tool. Nothing
attacker-controlled reaches the HTML at all; the return target travels in a
`Location` header and is percent-encoded.

**Shared caching.** A challenge is meant for one client. If a CDN caches it,
every visitor gets somebody else's challenge, and the site breaks. So every
challenge response is `no-store`, and the documentation says what that does not
cover.

The page itself is deliberately dull: static, tiny, no JavaScript, no external
request, no third-party anything, and readable by a screen reader.
"""
from html import escape
from urllib.parse import quote

from .token import COOKIE_NAME, TOKEN_SCHEME

CHALLENGE_PAGE_VERSION = 1

#: A return path longer than this is dropped. It is attacker-controlled.
MAX_RETURN_CHARS = 512
#: Hard ceiling on the response. The page is under 2 KB; this is the refusal.
MAX_RESPONSE_BYTES = 8192

#: Schemes that must never appear in a redirect target.
_DANGEROUS_PREFIXES = ('javascript:', 'data:', 'vbscript:', 'file:', 'blob:',
                       'http:', 'https:', '//', '\\\\', 'mailto:')

#: Methods a redirect challenge may be used on. A redirect replays the request,
#: and replaying a POST can charge a card twice or submit a form twice.
SAFE_METHODS = ('GET', 'HEAD')


def safe_return_path(raw):
    """A local path to come back to, or `/`.

    Anything that could leave this site becomes `/`. That is a small loss — the
    client lands on the home page — against an open redirect, which is not small.
    """
    if not raw:
        return '/'
    text = str(raw)[:MAX_RETURN_CHARS]
    # Control characters first: a newline in a Location header is response
    # splitting, and a tab or NUL can smuggle a scheme past a naive check.
    text = ''.join(character for character in text if 0x20 <= ord(character) < 0x7f)
    if not text:
        return '/'
    stripped = text.strip()
    lowered = stripped.lower().replace('\t', '').replace(' ', '')
    if any(lowered.startswith(prefix) for prefix in _DANGEROUS_PREFIXES):
        return '/'
    if not stripped.startswith('/'):
        return '/'
    # `/\evil.test` and `//evil.test` are both protocol-relative in browsers.
    if stripped.startswith('//') or stripped.startswith('/\\'):
        return '/'
    if '\\' in stripped:
        return '/'
    return stripped


def encode_location(path):
    """Percent-encode a return path for a `Location` header.

    The path has already been validated; encoding is belt and braces, and it
    keeps anything unusual from reaching a header parser raw.
    """
    return quote(safe_return_path(path), safe='/?=&%-._~:@!$\'()*+,;')


def cookie_header(token, *, secure=True, max_age=900, path='/', same_site='Lax',
                  name=COOKIE_NAME):
    """The `Set-Cookie` value for a challenge token.

    `HttpOnly` because no script needs to read it, and a script that can read it
    can steal it. `SameSite=Lax` because a challenge is a first-party thing;
    `None` would be needed only for a cross-site embed and would widen exposure
    for no benefit here. `Secure` whenever the site is HTTPS.
    """
    if same_site not in ('Lax', 'Strict', 'None'):
        raise ValueError('SameSite must be Lax, Strict or None')
    if same_site == 'None' and not secure:
        raise ValueError('SameSite=None requires Secure')
    parts = [f'{name}={token}', f'Path={path}', f'Max-Age={max(0, int(max_age))}',
             'HttpOnly', f'SameSite={same_site}']
    if secure:
        parts.insert(3, 'Secure')
    return '; '.join(parts)


def clear_cookie_header(*, path='/', name=COOKIE_NAME, secure=True):
    """Expire the cookie. Used when a token is rejected, so a bad one is replaced."""
    parts = [f'{name}=', f'Path={path}', 'Max-Age=0', 'HttpOnly', 'SameSite=Lax']
    if secure:
        parts.insert(3, 'Secure')
    return '; '.join(parts)


#: Restrictive headers. No script may run, nothing may frame the page, and no
#: referrer leaks the protected URL onwards.
SECURITY_HEADERS = {
    'Content-Security-Policy': ("default-src 'none'; style-src 'unsafe-inline'; "
                                "form-action 'none'; frame-ancestors 'none'; "
                                "base-uri 'none'"),
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
}

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{delay};url={target}">
<title>Checking this request</title>
<style>
body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
margin:0;padding:2rem;line-height:1.6;color:#1a1a1a;background:#fafafa}}
main{{max-width:32rem;margin:4rem auto}}
h1{{font-size:1.25rem;font-weight:600;margin:0 0 .75rem}}
p{{margin:0 0 .75rem}}
a{{color:#0b5cad}}
@media(prefers-color-scheme:dark){{body{{color:#e8e8e8;background:#141414}}a{{color:#7db3e8}}}}
</style>
</head>
<body>
<main>
<h1>Checking this request</h1>
<p>Your browser will continue in a moment.</p>
<p>This check needs cookies to be enabled. If nothing happens,
<a href="{target}">continue here</a>.</p>
</main>
</body>
</html>
"""


def render(return_path='/', *, delay=1):
    """The challenge page. Static, small, no script, nothing third-party.

    The return path is validated, then escaped for HTML, then escaped again for
    the attribute context it sits in. It is the only variable on the page.
    """
    target = escape(encode_location(return_path), quote=True)
    body = _PAGE.format(target=target, delay=max(0, min(10, int(delay))))
    encoded = body.encode('utf-8')
    if len(encoded) > MAX_RESPONSE_BYTES:
        # Cannot happen with a bounded return path, but a page that grew past its
        # budget would be a bug worth failing on rather than serving.
        raise ValueError('challenge page exceeded its size budget')
    return body


class ChallengeResponse:
    """Everything a web server needs to answer one challenged request."""

    __slots__ = ('status', 'headers', 'body', 'shadow', 'reason')

    def __init__(self, status, headers, body='', *, shadow=False, reason=''):
        self.status = status
        self.headers = dict(headers)
        self.body = body
        self.shadow = shadow
        self.reason = reason

    @property
    def bytes_sent(self):
        return len(self.body.encode('utf-8'))

    def explain(self):
        return {'challenge_page_version': CHALLENGE_PAGE_VERSION,
                'token_scheme': TOKEN_SCHEME,
                'status': self.status,
                'shadow': self.shadow,
                'reason': self.reason,
                'bytes': self.bytes_sent,
                # The token is deliberately absent. It is the one value in the
                # flow that must not reach a log or a report.
                'headers': {name: ('[set-cookie omitted]' if name == 'Set-Cookie' else value)
                            for name, value in self.headers.items()}}


def build(token, return_path='/', *, secure=True, max_age=900, cookie_path='/',
          same_site='Lax', shadow=False, reason=''):
    """The full challenge response: cookie, headers, page.

    In shadow mode this returns what *would* have been sent, with a status of 0
    and no cookie, so impact can be measured before anyone is inconvenienced.
    """
    headers = dict(SECURITY_HEADERS)
    headers['Content-Type'] = 'text/html; charset=utf-8'
    if shadow:
        return ChallengeResponse(0, headers, '', shadow=True,
                                 reason=reason or 'challenge shadow mode: nothing was sent')
    headers['Set-Cookie'] = cookie_header(token, secure=secure, max_age=max_age,
                                          path=cookie_path, same_site=same_site)
    return ChallengeResponse(200, headers, render(return_path), reason=reason)


def rate_limited(retry_after=30):
    """A 429 with a bounded `Retry-After`. Used when the budget is spent."""
    headers = dict(SECURITY_HEADERS)
    headers['Content-Type'] = 'text/plain; charset=utf-8'
    headers['Retry-After'] = str(max(1, min(3600, int(retry_after))))
    return ChallengeResponse(429, headers, 'Too many requests. Please try again shortly.\n',
                             reason='challenge budget exhausted')
