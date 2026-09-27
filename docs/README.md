# Documentation

Read in this order. Simple first, technical depth later.

Everything here is about a program that, by default, watches and records and
blocks nothing. The pages that describe blocking say so in their first lines.

---

## 1. Start

| Page | What it is for |
| --- | --- |
| [../START_HERE.md](../START_HERE.md) | The shortest path. One screen |
| [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md) | The same steps, with help at each one |
| [INSTALL_LINUX.md](INSTALL_LINUX.md) | Every Linux installation option, and what goes where |
| [QUICKSTART.md](QUICKSTART.md) | The administrator's first hour |
| [WEBSITE_QUICKSTART.md](WEBSITE_QUICKSTART.md) | Protecting a website specifically |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | When something does not work |

## 2. Install and Deploy

| Page | What it is for |
| --- | --- |
| [INSTALL.md](INSTALL.md) | Installation reference, including offline and containers |
| [DISTRIBUTION.md](DISTRIBUTION.md) | What the release artifacts are |
| [SYSTEMD.md](SYSTEMD.md) | Running it as a service, and the unit hardening |
| [PRIVILEGES.md](PRIVILEGES.md) | Which component needs what, and why nothing runs as root |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Deployment shapes |
| [DOCKER.md](DOCKER.md) | The container template |
| [UPGRADE.md](UPGRADE.md) | Upgrading, and what is not promised |

## 3. Safe Monitoring

| Page | What it is for |
| --- | --- |
| [SHADOW_MODE.md](SHADOW_MODE.md) | Watching and deciding without acting |
| [WEB_PROTECTION.md](WEB_PROTECTION.md) | Reading a web server access log |
| [NGINX.md](NGINX.md) | The Nginx side of it |
| [TRUSTED_PROXIES.md](TRUSTED_PROXIES.md) | CDNs and reverse proxies. Read before blocking anything |
| [MULTI_SITE.md](MULTI_SITE.md) | More than one website |

## 4. Configuration and Operations

| Page | What it is for |
| --- | --- |
| [CONFIGURATION.md](CONFIGURATION.md) | Every setting |
| [OPERATIONS.md](OPERATIONS.md) | Day-to-day running |
| [OPERATOR_CHECKLIST.md](OPERATOR_CHECKLIST.md) | What to check, and when |
| [STORAGE.md](STORAGE.md) | The local database |
| [BACKUP_RESTORE.md](BACKUP_RESTORE.md) | Backups |
| [LOGGING.md](LOGGING.md) | Where operational logs go |
| [METRICS.md](METRICS.md) · [OBSERVABILITY.md](OBSERVABILITY.md) | What it reports about itself |
| [API.md](API.md) · [API_CLIENTS.md](API_CLIENTS.md) | The local read-only API |
| [CAPACITY.md](CAPACITY.md) · [PERFORMANCE.md](PERFORMANCE.md) · [BACKPRESSURE.md](BACKPRESSURE.md) | Limits, and what happens at them |

## 5. Autonomous Protection: Advanced

Read [VALIDATION_STATUS.md](VALIDATION_STATUS.md) first. Real-world validation of
autonomous blocking is **pending**.

| Page | What it is for |
| --- | --- |
| [AUTONOMOUS_MODE.md](AUTONOMOUS_MODE.md) | Turning it on, and everything that must be true first |
| [AUTONOMOUS_DECISION.md](AUTONOMOUS_DECISION.md) | How a decision is reached |
| [AUTONOMOUS_SAFETY_INVARIANTS.md](AUTONOMOUS_SAFETY_INVARIANTS.md) | What must never happen |
| [AUTONOMOUS_FAILURE_RECOVERY.md](AUTONOMOUS_FAILURE_RECOVERY.md) | What happens when a part fails |
| [GUARDED_ACTIVATION.md](GUARDED_ACTIVATION.md) | The gates before enforcement starts |
| [ENFORCEMENT.md](ENFORCEMENT.md) · [HOST_ENFORCEMENT.md](HOST_ENFORCEMENT.md) · [FIREWALL.md](FIREWALL.md) | What a block actually is |
| [COST_SENSITIVE_POLICY.md](COST_SENSITIVE_POLICY.md) | Why a wrong block is priced, not just counted |
| [PROGRESSIVE_DEFENSE.md](PROGRESSIVE_DEFENSE.md) · [CHALLENGE.md](CHALLENGE.md) | Asking before blocking |
| [REVIEW_QUEUE.md](REVIEW_QUEUE.md) | Human review |

## 6. Security and Privacy

| Page | What it is for |
| --- | --- |
| [../SECURITY.md](../SECURITY.md) | How to report a vulnerability |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What this defends against, and what it does not |
| [PRIVACY.md](PRIVACY.md) · [WEB_PRIVACY.md](WEB_PRIVACY.md) · [CHALLENGE_PRIVACY.md](CHALLENGE_PRIVACY.md) | What stays local, what is stored, what can leave |
| [SECURITY_DEPLOYMENT.md](SECURITY_DEPLOYMENT.md) · [GITHUB_SECURITY.md](GITHUB_SECURITY.md) | Deployment and repository hardening |
| [DECEPTION.md](DECEPTION.md) · [DECEPTION_SAFETY.md](DECEPTION_SAFETY.md) | The finite deception listener and its bounds |
| [LIMITATIONS.md](LIMITATIONS.md) · [RISKS_AND_LIMITATIONS.md](RISKS_AND_LIMITATIONS.md) | What it cannot do |

## 7. How It Decides

| Page | What it is for |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The shape of the whole thing |
| [MATH_MODEL.md](MATH_MODEL.md) · [SCIENTIFIC_BASIS.md](SCIENTIFIC_BASIS.md) | The mathematics, and where it comes from |
| [DECISION_ENGINE.md](DECISION_ENGINE.md) · [DECISION_UNCERTAINTY.md](DECISION_UNCERTAINTY.md) | Evidence into a decision |
| [FEATURE_SCHEMA.md](FEATURE_SCHEMA.md) · [HTTP_FEATURES.md](HTTP_FEATURES.md) | What it measures |
| [CONFIDENCE.md](CONFIDENCE.md) · [ANOMALY_DETECTION.md](ANOMALY_DETECTION.md) · [OOD.md](OOD.md) · [DRIFT.md](DRIFT.md) | Uncertainty, unusualness, and knowing when it is out of its depth |
| [CORRELATION.md](CORRELATION.md) · [FINGERPRINTING.md](FINGERPRINTING.md) | Linking observations |

## 8. Models and Data

| Page | What it is for |
| --- | --- |
| [DATA_AND_MODELS.md](DATA_AND_MODELS.md) | What ships, and what it was fitted on |
| [AI.md](AI.md) · [ML_ARCHITECTURE.md](ML_ARCHITECTURE.md) · [ONNX_MODEL.md](ONNX_MODEL.md) | The optional local model |
| [MODEL_GOVERNANCE.md](MODEL_GOVERNANCE.md) · [MODEL_REGISTRY.md](MODEL_REGISTRY.md) · [MODEL_LINEAGE.md](MODEL_LINEAGE.md) | Which artifact is in use, and where it came from |
| [MODEL_VALIDATION.md](MODEL_VALIDATION.md) · [MODEL_EVALUATION.md](MODEL_EVALUATION.md) | How a model is judged |
| [MODEL_PROMOTION.md](MODEL_PROMOTION.md) · [AUTO_PROMOTION.md](AUTO_PROMOTION.md) · [MODEL_ROLLBACK.md](MODEL_ROLLBACK.md) · [AUTO_ROLLBACK.md](AUTO_ROLLBACK.md) | Changing the model in a running deployment |
| [MODEL_SAFE_MODE.md](MODEL_SAFE_MODE.md) | What happens when the model cannot be trusted |
| [MODEL_TRAINING.md](MODEL_TRAINING.md) · [TRAINING_JOBS.md](TRAINING_JOBS.md) · [RETRAINING.md](RETRAINING.md) | Training, which never runs as root |
| [DATASET.md](DATASET.md) · [DATA_CARD_v1.md](DATA_CARD_v1.md) · [WEB_DATASET.md](WEB_DATASET.md) · [SITE_DATASETS.md](SITE_DATASETS.md) | The corpora |
| [DATA_QUALITY.md](DATA_QUALITY.md) · [THIRD_PARTY_DATA.md](THIRD_PARTY_DATA.md) | Quality gates, and data this project did not produce |

## 9. Validation and Status

| Page | What it is for |
| --- | --- |
| [VALIDATION_STATUS.md](VALIDATION_STATUS.md) | **The canonical current status.** Start here for any claim |
| [SHADOW_VALIDATION_PLAN.md](SHADOW_VALIDATION_PLAN.md) | How real-world validation is meant to happen |
| [BENCHMARKING.md](BENCHMARKING.md) · [MONITORING_EVALUATION.md](MONITORING_EVALUATION.md) | Measuring it |
| [P0_P12_STATUS.md](P0_P12_STATUS.md) | Where the earlier phases got to |
| [../reports/](../reports/) | Phase reports. Historical: read [../reports/README.md](../reports/README.md) first |

## 10. Development and Release

| Page | What it is for |
| --- | --- |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Setting up to develop, tests, style, and what not to send |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Read before changing anything structural |
| [DEPENDENCIES.md](DEPENDENCIES.md) | What it depends on, and what it deliberately does not |
| [SCHEMA_COMPATIBILITY.md](SCHEMA_COMPATIBILITY.md) | Changing a schema without breaking a deployment |
| [MODULE_GRADUATION.md](MODULE_GRADUATION.md) | How experimental code becomes real |
| [RELEASE.md](RELEASE.md) · [RELEASE_CONTENTS.md](RELEASE_CONTENTS.md) | The release process, and what is in a release |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | The notes for the current release |
| [GITHUB_RELEASE.md](GITHUB_RELEASE.md) | Publishing: About text, topics, release metadata, owner actions |
| [DISTRIBUTION.md](DISTRIBUTION.md) | Which artifacts exist and how they are built |
| [GOVERNANCE.md](GOVERNANCE.md) · [SUSTAINABILITY.md](SUSTAINABILITY.md) | Who decides, and how this keeps going |
| [MIGRATION_FROM_LEGACY.md](MIGRATION_FROM_LEGACY.md) | The old `+name.py` entry points |
| [LAB_TEST_PLAN.md](LAB_TEST_PLAN.md) | The tests that need an isolated lab |

---

Pages not listed above are reference material for a specific component; the
directory listing is the index for those.
