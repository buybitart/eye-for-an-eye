# Cross-site Security

Threats that exist because one server protects several sites, what is done about
each, and what is left over.

## The Four Rules

1. **The Host header is untrusted.** Sites are resolved from local
   configuration. A header can select a site; it can never create one.
2. **Site web behaviour does not leak across sites.** Site A's counters are site
   A's.
3. **Challenge tokens are site-isolated.** A token for one site does not verify
   for another.
4. **Network blocks reach every site on the machine.** This one is a limitation,
   not a mitigation, and it is stated rather than hidden.

## Threats

### Host Header Spoofing

**Impact.** A client picks which site's policy and which site's cryptographic
key apply to it, most likely the most permissive one.

**Mitigation.** A SiteID never comes from the request. The normalised host is a
lookup key into the operator's table, and a miss goes to `unknown-site`.

**Remaining.** If you configure a site with a domain you do not actually
control, traffic claiming that host reaches that site's profile. Configure the
domains you serve.

### Host Cardinality Attack

**Impact.** An attacker changes `Host:` on every request. If each new host
created state, that is an unbounded memory allocator with a network interface.

**Mitigation.** Every unresolvable host maps to one bounded bucket. The resolver
has no method that adds a site. Measured: 200,000 invented hosts produced zero
new sites and no growth in the site table.

**Remaining.** The unknown bucket itself holds state, bounded by the same
per-site limits as any other site. Traffic to a genuinely unconfigured site
shares that bucket with the attack.

### Cross-site State Contamination

**Impact.** A scanner probing site A raises site B's risk, and site B acts
against a source that never touched it.

**Mitigation.** Per-site state tables. There is no code path that reads site A's
counters while scoring site B.

**Remaining.** Host-level *network* evidence is shared, deliberately. A source
that port-scanned the machine is a fact both sites may use. That is a different
observation about a different layer, not HTTP state leaking sideways.

### Cross-site Challenge Reuse

**Impact.** A token earned on a low-value site opens a high-value one.

**Mitigation.** Per-site key derivation with HKDF from one master secret. A
token signed with site A's key does not verify under site B's, and this is
tested for every pair of configured sites. Cookies are host-only (no `Domain`
attribute), so a browser does not send one site's cookie to another.

**Remaining.** Sites sharing a hostname share a scope by definition. If two
"sites" in your configuration serve the same domain, the configuration is
rejected; if they genuinely share a domain, they are one site.

### Site Configuration Confusion

**Impact.** A domain mapped to two sites. Whichever wins is a silent decision
about where a real website's traffic goes.

**Mitigation.** Refused at startup, in every spelling, case, port and trailing
dot are normalised before comparison. The whole configuration is validated
together, so a bad site stops startup rather than half-applying.

**Remaining.** Partial application is prevented; a *wrong but valid*
configuration is not. `sites doctor` prints the domain map for you to check.

### One Site Starving the Others

**Impact.** A busy site consumes the shared budget and a quiet site never
accumulates enough evidence to decide anything. The symptom is not an error.
It is a small site where the tool seems not to work.

**Mitigation.** Every site has a reserved floor it can always claim. When the
shared pool is full, eviction is charged to whichever site is furthest over its
fair share. Measured: under a 200,000-request flood on one site, the quiet site
lost nothing and the busy site absorbed every eviction.

**Remaining.** The floors are small. A site needing more than its floor during
a neighbour's flood competes for what is left.

### Site Model Mix-up

**Impact.** A model built for site A loaded for site B. It runs, returns a
confident score, and is wrong in a way nothing downstream can detect.

**Mitigation.** Every manifest declares a scope. A registry refuses to publish a
model whose scope does not match, and the resolver checks again at load time in
case the files changed underneath.

**Remaining.** Scope is a name in a manifest. Someone with write access to the
registry can write any name they like.

### Wrong Baseline Selection

**Impact.** Site A judged against site B's idea of normal, which is the whole
failure this stage exists to prevent, arriving by the back door.

**Mitigation.** A baseline carries its site, and installing one under a
different site raises.

**Remaining.** Nothing prevents an operator from building a baseline while an
incident is in progress. That is why activation is deliberate and provenance is
recorded.

### A Network Block Affecting Every Site

**Impact.** Site A sees a scanner, asks for a block, and site B's visitors lose
access. This is the most serious cross-site failure available, and it is not
preventable. It is what a network-layer block *is*.

**Mitigation.** Honesty and consent. The two are named separately
(`SITE_WEB_ACTION`, `NETWORK_HOST_BLOCK`), a site must be explicitly configured
to ask for the host-wide one, the default is off, and `sites doctor` flags any
site that has it enabled. The decision record says which was chosen and who it
reaches.

**Remaining.** Real and unavoidable. If you enable it, a source blocked because
of one site is blocked for all of them. Prefer site-local actions (a challenge
or a rate limit), which reach only the site that asked.

### Dataset Site Leakage

**Impact.** A model learns "traffic to the admin site is malicious". It scores
beautifully on the data it was trained on and is worthless on the first site it
has not seen.

**Mitigation.** `site_group`, `site_id`, `domain`, `host` and `profile_type` are
all registered as never-model-input, each with a recorded reason. None appears
in the feature vector.

**Remaining.** Behavioural features can still correlate with a site. A global
model should be evaluated per site, and leave-one-site-out where there are
enough sites. See [SITE_DATASETS.md](SITE_DATASETS.md).

## What Is Not Isolated

Sites share a process, a filesystem and a configuration file. This is not
hosting-provider tenancy and there is no security boundary between sites beyond
what is described here. An operator who can configure one site can configure all
of them, and a bug in the engine affects every site at once.

The isolation here is about *behaviour and evidence*, keeping one site's
traffic from being judged as another's. It is not a sandbox.
