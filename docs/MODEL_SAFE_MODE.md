# Model Safe Mode

The state the system enters when it no longer trusts its own model handling.

## What It Is

Safe mode is stronger than a freeze. A freeze stops promotion. Safe mode stops
promotion *and* candidate authority, and runs on a known-good model.

| | Freeze | Safe mode |
| --- | --- | --- |
| Automatic promotion | stopped | stopped |
| Guarded stage advancement | stopped | stopped |
| Candidate shadow scoring | continues | stopped |
| Active model | unchanged | known-good, or none |
| Manual rollback | available | available |
| Mathematical engine and PolicyGuard | unaffected | unaffected |

That last row is the important one. **Neither a freeze nor safe mode leaves your
site undefended.** The deterministic mathematical engine has never depended on a
model, and PolicyGuard is unchanged. A site in safe mode is a site running the
way it ran before any model existed, which is a supported configuration and
always has been.

## What Puts It There

- a rollback that itself failed; the system tried to go back and could not;
- model registry inconsistency;
- governance state that cannot be read;
- a promotion left in an ambiguous state after a crash, where the journal and
  the registry pointer disagree in a way that cannot be resolved.

The common thread is not "the model is bad". It is "the system cannot currently
establish which model it should be running", and the honest response to that is
to stop changing things.

## What Puts It There Manually

```
eye-for-an-eye model governance freeze --reason "investigating false positives"
```

A reason is required. A freeze with no reason is a freeze nobody can safely lift,
because the next person to look has no way to tell whether the thing that caused
it was resolved.

## Getting Out

```
eye-for-an-eye model governance status
eye-for-an-eye model governance audit
eye-for-an-eye model governance unfreeze
```

Read the status and the audit log first. `unfreeze` also clears the consecutive
failure count. An operator who has looked and fixed the cause should not be
frozen again within minutes, because that teaches people to stop using the
command.

## Automatic Freezing

Three consecutive promotion failures freeze the installation automatically.

Repeated failure means something a fourth attempt will not fix. The system stops
and asks for a person rather than retrying, which is also what keeps a broken
candidate from consuming the daily promotion budget every day forever.

## What Safe Mode Does Not Do

It does not change your firewall. It does not change your thresholds. It does not
delete anything. It does not stop the sensor, the challenge, the storage or the
API.

It stops model *changes*. Everything else carries on.

## See Also

- [AUTO_ROLLBACK.md](AUTO_ROLLBACK.md)
- [MODEL_GOVERNANCE.md](MODEL_GOVERNANCE.md)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
