# Users

This page describes who the project is for. It separates what is **intended**
from what is **evidenced**.

## USER RESEARCH NOT YET COMPLETED

No interviews have been done. No organisation has deployed the software. Nothing
below comes from a study. The profiles are the project's design assumptions,
written down so they can be tested and corrected.

A plan for fixing this is at the end of the page.

## Intended beneficiaries

The project's stated intent is to help **independent media organisations and
NGOs** that run their own small servers.

## Profile 1: administrator of a small independent news site

| Question | Assumed answer |
| --- | --- |
| Problem | The site is scanned and probed constantly. A successful login compromise would be serious. |
| Current workflow | A VPS, a web server, maybe `fail2ban`, and reading logs when something feels wrong. |
| Technical skill | Comfortable with SSH and a config file. Not a security specialist. |
| Time available | Hours per month, not per week. |
| Budget | Very small. A monthly security subscription is out of reach. |
| Install problem | Anything with more than a few steps will not get installed. |
| Expected benefit | Sees who is probing the site, and gets a documented way to slow them down later. |

## Profile 2: system administrator at a small NGO

| Question | Assumed answer |
| --- | --- |
| Problem | Several small services on one or two machines, and no security monitoring at all. |
| Current workflow | Keeps things running. Security is whatever the distribution does by default. |
| Technical skill | Good general Linux. Little security tooling experience. |
| Time available | Shared with every other IT job in the organisation. |
| Budget | Grant funded, so a recurring vendor cost is hard to justify. |
| Install problem | Must be able to explain what it does to a director who will ask. |
| Expected benefit | Evidence of what is happening, in a form that can go into a report. |

## Profile 3: owner of a small business website or VPS

| Question | Assumed answer |
| --- | --- |
| Problem | Bots, scraping, and login attempts. Mostly noise, occasionally real. |
| Current workflow | A hosting control panel. |
| Technical skill | Can follow instructions carefully. |
| Time available | Almost none. |
| Install problem | One command, or it does not happen. |
| Expected benefit | Fewer surprises, and something to show when asked. |

This group is not an internet-freedom beneficiary. It is listed because it is a
realistic early adopter and a source of feedback.

## Profile 4: security researcher or home-lab user

| Question | Assumed answer |
| --- | --- |
| Problem | Wants to study scanning behaviour with a readable code base. |
| Technical skill | High. |
| Expected benefit | A small, documented decision engine, a dataset pipeline and a model card that can be argued with. |

This group is the most likely source of the first bug reports and the first
independent review.

## What every profile needs

This is the design pressure that produced the current defaults:

* One command to install.
* Safe by default, because a mistake here takes a site off the Internet.
* No account, no key, no subscription.
* Documentation in simple English, because not every reader has English as a
  first language.
* Small resource use, because the machine is a small VPS.
* A way to see **why** a decision was made.

## Feedback plan

Feedback must be opt-in and must never collect traffic automatically.

Planned channels:

* A public issue tracker with a short template: install problems, false
  positives, resource use, confusing documentation, model behaviour.
* A manual shadow-report export the user chooses to send, with an explicit
  redaction option.
* Direct contact with a small number of early users, if any agree.

The software will never phone home. See [Privacy](PRIVACY.md).

## Plan to close the user-research gap

1. Publish a public alpha with an honest status.
2. Ask three to five small self-hosted operators to install it and record where
   they stop.
3. Watch one full Shadow Mode cycle with each of them, and record every false
   positive.
4. Rewrite the documentation from what they misunderstood, not from what the
   author assumed.
5. Only then approach media or civil-society support organisations, with
   something that has already survived contact with real users.

Until step 5 produces results, the internet-freedom beneficiary claim stays
marked as a gap.

## See also

* [Distribution](DISTRIBUTION.md)
