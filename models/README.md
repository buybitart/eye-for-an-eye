# Trusted local models

No active production model is included or configured by default, and nothing here is
downloaded at runtime. The wheel contains runtime code, not training code or these models.

| artifact | what it is |
|---|---|
| `risk-logreg-v1.onnx` / `.json` | first ONNX risk baseline and its manifest; **shadow only**, quality gate failed |
| `MODEL_CARD_risk-logreg-v1.md` | intended use, non-use, metrics, limitations, deployment recommendation |
| `risk-logreg-v1-training.json` | training run record: grid, selection, ablation, coefficients, parity, environment |
| `risk-logreg-v1-evaluation.json` | measured evaluation of the exported artifact |
| `risk-logreg-v1-shadow.json` | shadow replay through fusion and policy, with model/math disagreements |
| `risk-logreg-v1-pcap.json` | offline replay of the labelled lab captures through the full packet-to-decision chain |
| `research-v2/` | earlier P7 synthetic LR and GBT research exports and their reports |

None of these is a production maliciousness model. `risk-logreg-v1` separates synthetic
behaviour it was trained on and does not generalise to behaviour it has not seen; its
manifest carries `quality_gate_passed=false` and `recommended_mode=shadow`. Read
[the model card](MODEL_CARD_risk-logreg-v1.md) and
[the report](../reports/model-risk-logreg-v1.md) before considering any candidate.

Reproduce with the locked `ml` and `ml-training` extras and the commands in
[MODEL_TRAINING](../docs/MODEL_TRAINING.md). Output paths must be new; the exporter
refuses to overwrite. Model files and manifests have matching hashes; obtain both through
a trusted offline channel. Operator review of provenance is required, because SHA-256
alone is not authenticity. Provision files read-only to other users and set local
`model_path` / `manifest_path` in shadow configuration. Review
[ONNX_MODEL](../docs/ONNX_MODEL.md), [MODEL_EVALUATION](../docs/MODEL_EVALUATION.md) and
[SHADOW_MODE](../docs/SHADOW_MODE.md) before choosing a candidate. No automatic activation
or promotion endpoint exists.
