# ONNX Model Contract and Safe Loading

This page explains the file format Eye for an Eye uses for a machine-learning model, called ONNX, and the safety checks it runs before it will trust one. It is for developers and reviewers who want to know exactly how a model file is verified.

## What ONNX Is, and the Exact Versions Used

ONNX (Open Neural Network Exchange) is a standard file format for a trained machine-learning model, so different tools can load the same file.

Eye for an Eye uses a locked set of versions, in its optional "ml" extra: ONNX Runtime 1.29.0 (the engine that actually runs the model), ONNX 1.22.0 (the library that reads and checks the file format), and numpy 2.5.3, all on Python 3.12.

* The model always runs on CPU only (`CPUExecutionProvider`): never on a GPU.
* Execution is **sequential**: steps run one after another, not in parallel.
* Both the "intra-op" and "inter-op" thread counts are fixed at 1, and automatic thread "spinning" is turned off. Normally, a thread pool can busy-wait ("spin") while looking for new work, which wastes CPU time; this setting disables that.
* Automatic usage reporting ("telemetry") from ONNX Runtime is disabled.

These settings follow the official [Python API](https://onnxruntime.ai/docs/api/python/api_summary.html) and [threading guide](https://onnxruntime.ai/docs/performance/tune-performance/threading.html) from the ONNX Runtime project.

## How the Model Is Loaded Safely

One piece of code, called `OnnxRiskModel`, is the only place in the whole project that calls the real `onnxruntime` library. `IsolatedModel` wraps it inside a separate, killable child process (see [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md)), "killable" means the main process can forcibly stop it if something goes wrong.

There is also a benchmark-only helper that copies an already-checked model into memory just to test different batch sizes. It never exports this copy, and it never makes it the real, active model.

## The Manifest: A Strict Contract File

Every model file needs a matching JSON manifest file next to it. A manifest is a small file that describes exactly what the model is and what it must look like. Eye for an Eye checks every one of these fields before it will load the model file itself:

| Field | Required value |
|---|---|
| `manifest_version` | `1` |
| `model_version` | a name and version string, for example `risk-logreg-v1` |
| `feature_schema_version` | `1` |
| `feature_order` | the exact list of feature names, in the exact order (see [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md)) |
| `input_name` | `features` |
| `input_shape` | `[1, 36]` |
| `input_dtype` | `float32` |
| `output_names` | `[label, probabilities]` |
| `classes` | `[benign-like, malicious-automation-like]` |
| `dataset version` | which dataset trained this model |
| `created_at` | a timestamp |
| `sha256` | the model file's fingerprint (see below) |
| `score_semantics` | `uncalibrated_model_score`: an explicit label saying this number is not a calibrated probability |

Beyond the manifest, the model's real output is also checked directly: the `label` output must be a whole number (`int64`) with exactly one value, either `0` or `1`; the `probabilities` output must have exactly two numbers (`float32`), both finite, non-negative, and normalised (adding up to 1, within a tiny rounding tolerance).

The model must also pass a **warmup** run (one full test prediction) before it is trusted.

Eye for an Eye never silently reorders features to try to match a slightly different file, and it never guesses at a "close enough" schema. If anything about the manifest, the file, or a test run does not match exactly, the model is rejected.

## Size Limits and File Safety Checks

* Model file size: 16 MiB by default, 32 MiB maximum (configurable up to that ceiling).
* Manifest file size: 32 KiB maximum.
* Only local, regular files are accepted. Network paths (UNC paths, which look like `\\server\share`) are rejected, and a symbolic link at the very end of the path is rejected too. This stops a link from quietly pointing somewhere else.
* On Linux and macOS ("POSIX" systems), the file must be owned by the account running the service, or by root, and it must not be writable by "group" or "everyone." This stops another, less-trusted account on the same machine from tampering with it.
* The operator is responsible for keeping model files only in directories that are already trusted, and, on Windows, for setting the folder's Windows ACLs (access control lists, Windows's permission system) correctly; Eye for an Eye's own file-ownership checks above are written for POSIX systems.

## SHA-256, and What It Actually Proves

SHA-256 is a one-way "fingerprint" function: running it on a file always produces the exact same, unique-looking string for that exact content, but even a tiny change to the file completely changes the result.

Eye for an Eye computes the SHA-256 of the real model file, and checks that it matches the `sha256` field written inside the manifest.

**A matching hash only proves the file has not changed since the manifest was written. It does NOT prove the file came from a trustworthy source, and it does NOT make an unsafe model file safe.** The manifest itself must come from a trusted, offline release process that the operator already trusts. Because of this, only operator-reviewed, trusted model files should ever be used; a model file must never be picked up from something that arrived over the network without review.

## What the Model File Itself Is Allowed to Contain

Even after the manifest and the hash both match, Eye for an Eye still inspects the model's internal structure (its "graph") before it will run it:

* External tensor data (numbers stored outside the main file, in a separate file) is rejected.
* Nested graphs (a model containing another whole model inside it) are rejected.
* Any operator (a mathematical building block) outside a small, explicit, allowed list is rejected. This allowed list is written directly into the loading code.
* Oversized starting weight tensors are rejected.

## How Eye for an Eye Avoids the Classic "Unsafe Model File" Problem

Some common Python formats for saving a machine-learning model, called **pickle** and **joblib**, are well known for a serious risk: opening one of these files can run arbitrary code, not just load data. Eye for an Eye never loads either format, anywhere.

The model runs inside its own separate ("child") process, started using Python's "spawn" method. That method only ever passes it configuration this application itself created, never anything taken from the network. Communication with that child process only ever uses small, length-limited JSON messages containing plain numbers: the feature numbers going in, and the result numbers coming back. Nothing that looks like a program, and nothing taken directly from network data, is ever turned back into a live object this way.

Running the model in its own process gives Eye for an Eye a timeout and crash boundary: if the model hangs or crashes, only that one process is affected. It gets killed, and the model is reported as unavailable. This is **not** a full operating-system-level sandbox that could contain a truly malicious model graph. The real protection is using the existing unprivileged service account, its resource limits, and loading only model files that have already been reviewed and trusted.

## How to Add or Change a Model File

1. Put both the model file and its manifest, as brand-new files, into a directory the operator already owns and trusts.
2. Verify their SHA-256 hashes against copies you have already reviewed and trust yourself. Do not simply trust whatever the manifest file itself claims.
3. Point `model_path` and `manifest_path` at these files in the local configuration.
4. Restart the service in shadow mode (see [SHADOW_MODE.md](SHADOW_MODE.md)).

Eye for an Eye does **not** watch these files for later changes, and it does **not** auto-update a model on its own. If a required software package or file is missing, if something does not match, if a `NaN` (not-a-number, an invalid numeric result) turns up, or if an unexpected error happens, the result is simply an "unavailable" or "degraded" status, and Eye for an Eye falls back to the math-only score (see [DECISION_ENGINE.md](DECISION_ENGINE.md)). The only setting that turns a failed machine-learning startup into a fatal error is `required = true`.

## See Also

* [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md): the 36-number tensor this model reads.
* [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md): how this model fits into the running pipeline.
* [MODEL_TRAINING.md](MODEL_TRAINING.md): how a model file like this is built.
* [MODEL_EVALUATION.md](MODEL_EVALUATION.md): measured results for models built this way.
* [SHADOW_MODE.md](SHADOW_MODE.md): running a new model safely, without enforcement.
* [DECISION_ENGINE.md](DECISION_ENGINE.md): how a model's score is combined with the math score.
* [SECURITY_REVIEW_SCOPE.md](SECURITY_REVIEW_SCOPE.md): what a security review of this project should cover.
