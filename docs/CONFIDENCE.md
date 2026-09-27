# Confidence Levels for Detections

This page explains how the system marks how sure it is about a detection. Read this if you look at alerts, or if you write or change detection rules.

## Three Different Things

The system keeps three different things apart: an **observation**, a **hypothesis**, and an **attribution**. These are not the same:

- An observation is a value the system reads, for example a value in a packet header.
- A hypothesis is a guess about why that value looks this way.
- An attribution would be a claim about who caused the behavior. The system does not make this claim.

The system stores the observation and the hypothesis in different places. A "classification" is only about the visible behavior of one address, seen by one sensor, during one time window. It is not a claim about a real person or organization.

## Confidence Table

| Confidence | When the system uses it |
| --- | --- |
| UNKNOWN | There is not enough evidence. The data is broken, missing, or not supported. Or the result is just a raw measurement, with no guess attached. |
| LOW | The system used a weak signal. Examples: a guess from TTL (Time To Live, a counter field in a packet) or from timestamp or IP ID (a number in an IP packet header); a "fuzzy" (not exact) match from p0f (a tool that guesses an operating system from network traffic); or a pattern marked suspicious, locally focused, or distributed. |
| MEDIUM | The system found an exact p0f signature match, or several matching scanner or bot signals at the same time, with no sample limit reached. |
| HIGH | The system never gives this confidence level. It would need extra strong proof, plus a formal calibration and validation rule that does not exist yet. |

The code that builds a fingerprint result (`FingerprintResult`) blocks HIGH confidence by design. The current rules have no way to raise a TTL-plus-p0f feature to HIGH. A MEDIUM label does not mean the system knows the exact operating system. It does not mean a known percentage of correct results.

## What a Score Means

A score is the sum of weighted features that the system can explain. Every score is capped between 0 and 100. A score of 78 does **not** mean "78% chance this is true." It is not a probability.

The "probe similarity ratio" (how close a request looks to a known probe pattern) is also not a probability.

Precision and recall numbers from offline evaluation (testing the system against labeled test data) mean something different again. They are measurements taken on one specific labeled data set, with a clear number of test cases (the "denominator"). They are not a general accuracy claim.

## What Each Detection Includes

Every detection result has:

- reasons (why the system flagged it)
- supporting events (the raw events behind the decision)
- a time window
- known limitations

A result of "noise" or "UNKNOWN" means the system did not see enough matching signals. It does **not** mean the source is safe.

A result of "targeted-hypothesis" means only that the same address kept acting the same way against this one sensor. It says nothing about whether that address is targeting other sensors too.

When the system has to cut ("cap") the number of stored samples, "targeted-hypothesis" is not allowed at all. Every other positive classification then drops to LOW at most.

## How to Change These Rules

To safely change confidence rules in the future, the project would need:

- real, representative labeled network captures, collected with clear origin and consent records
- separate data sets for training, validation, and testing
- checks for false positives
- checks that features do not just repeat each other (independence)
- checks for "drift" (the environment changing over time, so old rules stop matching)

Two labels from synthetic (artificially made) test fixtures are not enough proof to call these rules "calibrated" (tuned and checked against real data). The system does not fit weights automatically. This kind of automatic tuning does not exist at this stage of the project.

## See Also

- [CORRELATION.md](CORRELATION.md): how the system groups events and computes scores
- [LIMITATIONS.md](LIMITATIONS.md): known limits of the analysis
- [MATH_MODEL.md](MATH_MODEL.md): the math behind scoring and the model
- [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md): project-wide risks and limits
