"""P10 web protection: HTTP behaviour as evidence for the existing decision system.

This package does not implement a web application firewall and does not try to
recognise exploits. It reads safe request metadata that a local web server has
already parsed, turns it into bounded behavioural features, and hands those to
the same mathematical risk engine, fusion and policy that network behaviour uses.

Two things it must never do, and the whole package is shaped around them:

* Treat a forwarded header as identity without validating the peer it came from.
* Block a reverse proxy or CDN address, which would take the site off the air for
  everyone behind it.
"""
