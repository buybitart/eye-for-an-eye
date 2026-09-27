# Bounded protocol emulation

"Protocol emulation" means pretending to be a real network service, like a
web server or an FTP server, without really being one. "Bounded" means every
part of it has a fixed, limited size. This page describes exactly what each
fake service can and cannot do. Read this page if you want to know what the
deception part of Eye for an Eye actually does on the wire.

All parsers only accept a limited number of bytes, held in memory. There is
no shell, no subprocess, no filesystem lookup, no DNS resolver, no proxy, no
outbound connection, and no code generated on the fly.

Every conversation follows this shape: CONNECTED → COMMAND → RESPONSE →
COMMAND or CLOSED. It is bounded by a total time deadline, a maximum number
of messages, a maximum number of state changes, and a total byte limit.
The HTTP and SSH handlers each end the conversation after just one command.

## HTTP

Implemented: `GET`, `HEAD`, `OPTIONS`; an origin-form target (a path
starting with `/`) and `OPTIONS *`; both HTTP/1.0 and HTTP/1.1 request
framing (the rules for how a request is laid out). HTTP/1.1 requires a
non-empty `Host` header.

`GET` always returns one fixed body, the text "OK" with a newline. `HEAD`
returns the same headers as `GET`, but without a body. `OPTIONS` returns
status 204 and an `Allow` header. Every other method returns 405 (Method
Not Allowed). Every response includes `Connection: close`. Nothing from the
request is echoed back in the response.

The server rejects: broken request or header lines, duplicate header
names, a missing `Host` header, a `Transfer-Encoding` header, a
`Content-Length` header that is negative or ambiguous, and any `Upgrade` or
`Expect` header. A partial request simply waits, up to the byte and time
limits. Data sent after the first block of headers does not start a second
request.

Not supported: a request body, keep-alive connections, HTTP/2 or HTTP/3,
TLS (encrypted HTTPS), chunked decoding, real files, uploads, CGI
(server-side scripts), templates, outbound fetches, or acting as a proxy. A
`HEAD` or `GET` request using a path-traversal-like URL (for example, one
containing `../`) gets the exact same fixed response as any other path.

What is recorded (telemetry): the method's class, request lengths, a flag
for credential-like headers or patterns, and any parsing anomaly. The URL,
the `Host` header, cookies, authorization headers, and the body are never
stored.

The framing follows [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html).
The method, `HEAD`, and 204 behavior follow
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html). This is a limited
decoy (a fake target meant to attract and study attackers) — it is not a
full implementation of the HTTP standard.

## FTP

Implemented: a `220` greeting; `USER` replies `331`; `PASS` after `USER`
replies `530` (otherwise `503`); `SYST` replies `215`; `FEAT` replies `211`
listing no extra features; `PWD` replies `530`; `QUIT` replies `221` and
closes the connection.

The username is immediately turned into either a redacted marker or an
HMAC value (a way to turn data into a short code using a secret key, so the
original value cannot be recovered from it). The password sent with `PASS`
is never stored. Login always fails — there is no logged-in state at all.

The line parser requires CRLF line endings (the standard network line
ending), printable ASCII text, and at most 512 bytes per line. It correctly
handles TCP data arriving in small pieces, and several commands arriving in
one chunk, as long as the total stays within the message budget.

Unknown commands — including `PORT`, `PASV`, `SITE`, `RETR`, and `STOR` —
all get a fixed rejection reply. No filesystem access and no data
connection are ever created. `PWD` never lies about a successful login, and
`FEAT` never advertises a file-transfer feature that does not exist.

What is recorded: the command's class, credential flags, a pseudonym for
the username (only when that policy is turned on), later commands sent,
anomalies, and the disconnect. The reply and state behavior follow
[RFC 959](https://www.rfc-editor.org/rfc/rfc959.html). Real file transfers,
TLS, Telnet option negotiation, and a fully working FTP server are not
implemented.

## SSH

Implemented: a correct, fixed identification line,
`SSH-2.0-OpenSSH_9.6`, ending with CRLF. After sending this, the parser
accepts exactly one bounded client identification line (up to 255 bytes),
marks it valid or invalid, and closes the connection. No real SSH key
exchange happens.

There are no keys, no authentication, no shell, no command execution, no
port forwarding, no SCP or SFTP (file transfer over SSH), no agent
forwarding, and no proxying. A real SSH client, which expects a key
exchange to follow, will simply see the connection close. A thorough SSH
scanner may notice that this is a banner-only decoy (it shows the greeting
text but nothing else). Showing this product name in the banner is not a
promise of full OpenSSH behavior.

What is recorded: the class and length of the identification line, any
anomaly, and whether the connection continued or closed. The client's
software name string, and the binary handshake data, are never stored. The
identification line's framing and length rules follow [RFC 4253, section
4.2](https://datatracker.ietf.org/doc/html/rfc4253#section-4.2).

## Protocols left out on purpose

SMTP (email), a Redis-like protocol, and MySQL are not implemented. Phase
P3 is limited to the three finite handlers described above. There is no
SMTP relay, no mail or MX record lookup, no Redis storage, scripting, or
replication, and no MySQL SQL or plugin support. UDP-based decoy profiles
are also absent — an empty UDP datagram (a single UDP packet) never
triggers a response.

Adding any new protocol to this catalogue needs its own separate protocol
and safety review, plus its own bounded tests.

## See also

* [Deception](DECEPTION.md)
* [Deception safety](DECEPTION_SAFETY.md)
* [Service profiles](SERVICE_PROFILES.md)
* [Fingerprinting](FINGERPRINTING.md)
