# Related Projects

This page compares Eye for an Eye with existing open-source work. The goal is an
honest position, not a sales argument. Every project listed here is good at
something this project is not.

**Method and limits.** The projects below were checked by web search on
2026-09-09. Only their public homepages and repositories were consulted, and
feature details were not tested. Treat this as a map, not a benchmark. Re-verify
before using it in an application.

## Categories

### Log-based Intrusion Prevention

**Fail2ban** (<https://github.com/fail2ban/fail2ban>
**SSHGuard**) <https://www.sshguard.net/>

They watch log files for lines matching a pattern and ban the address for a
time.

* Stronger than this project at: maturity, packaging in every distribution,
  breadth of service support, and being already installed.
* Different: they read application logs; this project reads network behaviour
  over time windows. A slow scan that never writes a matching log line is
  invisible to a pattern matcher.
* This project **complements** them. Running both is reasonable.

### Community Reputation Systems

**CrowdSec**: <https://www.crowdsec.net/> ·
<https://github.com/crowdsecurity/crowdsec>

Local detection plus a shared, curated blocklist built from what other
participants report.

* Stronger than this project at: everything about the network effect. A
  community list sees an attacker before you do. It is far more mature.
* Different: the shared model requires sending signals off the machine. For a
  newsroom or a human rights organisation, that is a decision with real
  consequences, and it is the reason this project is local-only.
* This project does not try to replace it. A user who is comfortable sharing
  signals will probably get more value from a community system.

### Web Application Firewalls

**OWASP ModSecurity** (<https://github.com/owasp-modsecurity/ModSecurity>
**Coraza**) <https://coraza.io/>
**OWASP Core Rule Set**, <https://coreruleset.org/>

They inspect HTTP requests against rules and block matching requests.

* Stronger at: stopping a specific attack in a specific request, such as SQL injection,
  cross-site scripting, path traversal.
* Different: a WAF judges one request. This project judges a source's behaviour
  across 10, 60 and 900 second windows. They answer different questions.
* Complementary. A WAF plus behaviour analysis is a reasonable pair.

### Network Intrusion Detection

**Suricata** (<https://suricata.io/>
**Zeek**) <https://zeek.org/>

Deep protocol analysis, signatures, rich network logs.

* Stronger at: nearly everything about network visibility. Both are mature,
  fast, and far more capable analytically.
* Different: they are built for someone who will read and tune them. The target
  user here has hours per month. This project makes a decision and explains it,
  instead of producing data for an analyst.
* Zeek in particular can do everything the correlation engine here does, and
  much more, given a person to write the scripts.

### Host-based Monitoring

**Wazuh**: <https://wazuh.com/>

Agent-based host monitoring, file integrity, log analysis, with a management
server.

* Stronger at: coverage of the whole host and fleet management.
* Different: it expects a server and a console. This project is one process on
  one machine with no central component.

### Honeypots

**Cowrie** (<https://github.com/cowrie/cowrie>
**OpenCanary**) <https://github.com/thinkst/opencanary>
**T-Pot**: <https://github.com/telekom-security/tpotce>

Fake services that record what attackers do.

* Stronger at: depth of interaction. Cowrie emulates a full shell session and
  collects the attacker's commands and uploads.
* Different, and deliberately weaker: the deception here has **no shell and no
  command execution**, and answers come from a fixed list of three profiles. It
  is a signal source for the decision engine, not a research honeypot.
* Anyone whose goal is collecting attacker tooling should use Cowrie.

### Machine Learning for Intrusion Detection

There is a large research literature, and a long history of models that score
well on public datasets and poorly in production. The usual causes are label
leakage, a train/test split that puts the same session on both sides, and a
distribution that does not match a real network.

This project's response is procedural rather than novel: group-based splits, a
frozen test set, explicit leakage checks (port, timing, generator fingerprint,
source type, single feature), a published data card and model card, and a
recommendation to run in shadow. See [Dataset](DATASET.md).

## What Is Actually Different Here

No claim of being first or unique. The combination is:

1. **Local-only by design.** No shared reputation, no cloud inference, no
   account. This is a deliberate trade against effectiveness, made because of
   who the intended users are.
2. **A maths engine that is the floor, not the fallback.** The model can only
   ever take part of the weight, and only when confident. Most ML security tools
   put the model in charge.
3. **A model that cannot reach the firewall.** Enforcement requires the
   hand-written engine to agree, independently.
4. **Shadow Mode as the default state**, with reports designed to be checked by
   a non-specialist.
5. **A documented, auditable learning loop** with a human step, instead of
   automatic retraining.
6. **A2-level English documentation**, because the intended users are not
   security engineers and often not native English speakers.

## Where This Project Is Weaker

Stated plainly:

* It is far less mature than every project on this page.
* It has no user base and no production deployments.
* Its enforcement path is lab-only.
* Its model has not been tested on real production traffic.
* It supports fewer protocols than any real IDS.
* It has no community, no packages, no distribution presence.
* It has had no external security audit.

A reader deciding what to install today should probably install Fail2ban or
CrowdSec. This project is worth watching, not yet worth depending on.

## See Also

* [Limitations](LIMITATIONS.md)
