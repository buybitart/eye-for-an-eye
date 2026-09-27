# Reverse Proxies, CDNs and Client Identity

This is the most security-critical page in the web layer. Two things can go
wrong, and both are serious.

Status: **Beta.**

## Problem One: A Header Anyone Can Write

`X-Forwarded-For` is a string the client sends. Anyone on the Internet can put
anything in it.

If a system believes it without checking, then an attacker can:

* **frame somebody else**: send `X-Forwarded-For: <your customer's address>`
  while probing, and get your customer blocked;
* **hide**: claim to be an address the system trusts and never be acted on.

So this project holds one rule:

> A forwarded address is believed only when the machine that sent it to us is one
> we were explicitly told to trust.

Nothing is trusted by default. With no configuration, forwarded headers are read
and ignored, and the address that actually connected is used.

## Problem Two: Blocking the Proxy

When a site is behind Nginx, a load balancer or a CDN, every request arrives from
the proxy's address. The real client is only known at the HTTP layer.

A network-level block on that address does not block the client. It blocks the
**proxy**, and the proxy is carrying every other visitor.

> A client that reached us through a proxy is never blocked at the network layer.

The strongest action available for such a client is a rate limit, and the reason
is written into the decision:

```text
Reduced because:
  - the client is behind a proxy; blocking its address at the network layer
    would hit the proxy and every other visitor behind it
```

This is a regression test, not a policy setting. There is no way to turn it off.

## How the Client Is Resolved

```text
direct peer  +  forwarded chain  +  trusted proxy networks  ->  client identity
```

The peer is the only address observed directly, so it is the anchor. The chain is
walked **right to left**, stepping over addresses that are themselves trusted
proxies. The first address that is not one of ours is the closest thing to a real
client our own infrastructure vouched for.

The left-most address is never taken blindly. That is the address the client
wrote, and it is exactly what an attacker controls.

## What Comes Out

| Origin | Confidence | Blockable at the network layer |
| --- | --- | --- |
| `direct_peer` | HIGH | yes |
| `trusted_proxy_chain` | HIGH | **no** |
| `partial_proxy_chain` | MEDIUM | **no** |
| a proxy with no forwarded address | LOW | no |
| unparseable | LOW | no |

`partial_proxy_chain` means the client appended addresses of its own before ours.
The address our proxy observed is still used; the chain is not clean, and that is
recorded.

Low confidence reduces the strongest action available: an address the system is
not sure about is not an address to act on.

## Configuring It

```toml
[web]
trusted_proxy_networks = ["10.0.0.0/8", "203.0.113.0/24"]
trust_forwarded_headers = true
```

List only the networks your own proxy actually uses.

**Do not** list a wide public range. Anyone inside it can then set the client
address to anything. `web doctor` warns when a configured range is very large.

**Do not** trust a CDN because its header name looks familiar. Trust comes from
the address the connection arrived from, and you must state it. CDN-specific
helpers may come later; today it is explicit configuration.

If the site is directly exposed with no proxy, leave the list empty. That is not
a limitation: it is the correct configuration.

## NAT and Shared Addresses

One public address can be many people: an office, a mobile network, a university.
So a block is never permanent, always short at first, and lengthens only on
repeat. See [WEB_ENFORCEMENT.md](WEB_ENFORCEMENT.md).

The project never says "source address" and means "person". A source is a source.

## IPv6

Fully supported. IPv6 proxy chains, bracketed addresses with ports
(`[2001:db8::1]:443`), and IPv6 trusted networks all work and are tested.

## Tested Attacks

Each of these is a test, not a claim:

* a spoofed header from an untrusted peer is ignored
* an attacker cannot make the system name a third-party address as the client
* an attacker cannot hide by claiming to be a trusted proxy address
* a client-prepended chain behind a real proxy is marked partial, and the address
  our proxy saw is used
* a hundred clients behind one proxy stay a hundred distinct sources
* one suspicious client behind a CDN never makes the CDN address blockable
* malformed, empty, oversized and control-character-laden headers do not raise
* obfuscated RFC 7239 identifiers (`for=_hidden`) are not treated as addresses

## Related

* [WEB_ENFORCEMENT.md](WEB_ENFORCEMENT.md): what may be acted on
* [NGINX.md](NGINX.md): where the header comes from
* [WEB_PROTECTION.md](WEB_PROTECTION.md): the wider picture
