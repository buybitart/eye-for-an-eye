# Static analysis decisions, P6

Bandit runs at medium/high severity. The six findings below were reviewed on
2026-09-08. The gate keys each exception by rule, normalized filename and hash
of the exact reported code (including location). A changed/new finding fails.
Low-severity warnings are outside this gate; no claim of a clean exhaustive audit.

* B104, capture_helper: the string 0.0.0.0 is removed from local addresses.
  It is not a socket bind or a service exposure.
* B608, Reader.events/summaries/stats: index and clauses come only from
  Reader.where's fixed field/index lists. All query values, cursor and limit
  are SQLite parameters. P4 malicious query/limit tests cover the boundary.
* B608, SQLiteStore.open: schema DDL interpolates only the module's integer
  application ID; no operator/network values enter the script.
* B608, SQLiteStore.write_many: the constructed part is a bounded list of
  question-mark placeholders. All event IDs are parameter values.

Do not regenerate the exception file to hide a finding. Review the code first.
The source secret scanner detects private-key headers and common cloud/token
formats, plus long literal credentials and committed secret files. It does not
inspect Git history, every token format, or prove the absence of secrets.
CI dependencies (audit tools) are separate from the runtime dependency audit.
