"""P11 adaptive web challenge: a step between watching and blocking.

A challenge asks a client to complete an ordinary web flow — receive a cookie,
repeat the request — and records whether it did. That is all it is.

What it is not, and the whole package is written so these stay true:

* It is **not authentication.** A valid token means "this client completed this
  challenge recently". It grants no account access and bypasses nothing.
* It is **not proof of anything.** Passing does not make a client trusted;
  a capable bot handles cookies. Failing does not make a client malicious; a
  privacy browser, an API client or a broken proxy can fail one.
* It is **not a label.** A challenge outcome never becomes training ground truth.
  That rule comes from P9 and P11 does not weaken it.

A challenge outcome is evidence, and evidence is what the decision system was
built to weigh.
"""
