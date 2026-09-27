"""Render the measured training report. Every number comes from the JSON artifacts."""
import json
from pathlib import Path


def _fmt(value, digits=4):
    if value is None:
        return 'n/a'
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, float):
        return f'{value:.{digits}f}'
    return str(value)


def _table(header, rows):
    lines = ['| ' + ' | '.join(str(c) for c in header) + ' |', '|' + '|'.join(['---'] * len(header)) + '|']
    lines += ['| ' + ' | '.join(str(cell) for cell in row) + ' |' for row in rows]
    return '\n'.join(lines)


def _confusion(matrix):
    (tn, fp), (fn, tp) = matrix
    return _table(['', 'predicted benign_like', 'predicted malicious_automation_like'],
                  [['**actual benign_like**', tn, fp], ['**actual malicious_automation_like**', fn, tp]])


def _dataset(out, run, validation):
    out.append('## 2. Dataset\n')
    out.append(_table(['field', 'value'], [
        ['version', run['dataset_version']],
        ['content hash', f"`{run['dataset_sha256']}`"],
        ['source', 'locally generated synthetic scenarios; no capture, no live traffic, no Internet'],
        ['label source', 'generator intent (`synthetic_scenario`); never a risk score, action or firewall state'],
        ['label schema', '0 = benign_like, 1 = malicious_automation_like'],
        ['rows', validation['rows']],
        ['source groups', validation['group_leakage']['source_group_count']],
        ['scenario families', validation['group_leakage']['scenario_group_count']],
        ['seed', run['seed']]]))
    out.append('\n`malicious_automation_like` means automation-like behaviour observed by this sensor. It is not a '
               'claim that a person attacked anything, that an attack succeeded, or that the source is hostile.\n')
    out.append('### Dataset limitations\n')
    for item in ('synthetic sequences cannot represent real traffic distributions, noise or adversarial adaptation',
                 'test prevalence is a generator artefact and cannot estimate deployment prevalence',
                 'rows from one source are prefix windows of one sequence and are strongly correlated',
                 'four scenario families are test-only, so the test split is deliberately harder than validation',
                 'no labelled capture, PCAP corpus or reviewed production sample was available'):
        out.append(f'- {item}')
    if validation['warnings']:
        out.append('\nValidator warnings:\n')
        for warning in validation['warnings']:
            out.append(f'- {warning}')
    out.append('')


def _contract(out, run, evaluation):
    out.append('## 3. Feature schema and model contract\n')
    out.append(_table(['field', 'value'], [
        ['feature schema version', run['feature_schema_version']],
        ['model feature contract version', run['feature_contract_version']],
        ['runtime tensor', '`features` float32 [1, 36], fixed order from `decision.features.INPUT_ORDER`'],
        ['fitted columns', f"{len(run['model_feature_names'])} of 36"],
        ['excluded columns', ', '.join(f'`{k}`' for k in run['excluded_from_model'])],
        ['preprocessing', run['preprocessing']],
        ['missing values', 'explicit availability mask per column; unknown never becomes an observed zero'],
        ['range contract', 'every transformed column in [0, 1]; violations fail validation, nothing is silently clipped']]))
    out.append('\nExclusion rationale:\n')
    for name, reason in run['excluded_from_model'].items():
        out.append(f'- `{name}`: {reason}')
    out.append('\nNo identity column reaches the model: no address, numeric address, ASN, provider, country, username '
               'or hostname exists in the tensor. No decision-derived column reaches it either: no prior action, block '
               'state, fused risk, math score or earlier model score. Feature schema 1 contains no TTL, IP-ID, '
               'TCP-timestamp or p0f column, so no fingerprint-derived feature can dominate v1 by construction.\n')
    out.append('Zero-weight verification in the exported graph: '
               + ', '.join(f'`{k}` = {v}' for k, v in evaluation['zero_weight_check'].items()) + '.\n')


def _split(out, run, validation, classes):
    out.append('## 4. Split method and leakage checks\n')
    out.append('Whole source sequences are the split unit. A row-level random split would place prefix windows of the '
               'same simulated source in both train and test and inflate every metric. Four scenario families are '
               'additionally held out entirely for test, to measure behaviour never seen while fitting.\n')
    out.append(_table(['split', 'rows', 'sources', 'families', 'benign_like', 'malicious_automation_like',
                       'benign %', 'positive %'],
                      [[name, i['rows'], i['sources'], i['scenario_groups'], i['counts']['0'], i['counts']['1'],
                        f"{i['percent']['0']:.1f}", f"{i['percent']['1']:.1f}"] for name, i in classes.items()]))
    leakage = validation['group_leakage']
    duplicates = validation['duplicates']
    out.append('\n' + _table(['check', 'result'], [
        ['source groups in more than one split', len(leakage['source_groups_in_multiple_splits'])],
        ['identical vectors crossing the train boundary', duplicates['exact_vectors_crossing_train_boundary']],
        ['near-duplicate vectors crossing the train boundary', duplicates['near_vectors_crossing_train_boundary']],
        ['exact duplicate rows in the corpus', duplicates['exact_duplicate_rows']],
        ['test-only scenario families', ', '.join(leakage['test_only_scenario_groups'])],
        ['chronological split', run['split']['applies']]]))
    out.append('\nGroup separation is a failing test, not a warning: `training.split.assert_group_separation` raises '
               '`LeakageError` and `tests/test_p8_training_split.py` asserts it.\n')


def _hyperparameters(out, run):
    out.append('## 5. Hyperparameters and selection\n')
    out.append(_table(['field', 'value'], [
        ['family', 'logistic regression'],
        ['penalty / solver', f"{run['penalty']} / {run['solver']}"],
        ['C grid', ', '.join(str(v) for v in run['grid']['C'])],
        ['class weight grid', ', '.join(run['grid']['class_weight'])],
        ['max_iter', run['max_iter']],
        ['seed', run['seed']],
        ['selected', f"C={run['selected']['C']}, class_weight={run['selected']['class_weight']}, converged in "
                     f"{run['selected']['iterations']} iterations"],
        ['selection rule', run['selection_rule']]]))
    out.append('\n' + _table(['C', 'class weight', 'val PR-AUC', 'val ROC-AUC', 'val FPR @0.50', 'val recall @0.50',
                              'val block precision @0.90'],
                             [[c['C'], c['class_weight'], _fmt(c['validation']['pr_auc']),
                               _fmt(c['validation']['roc_auc']),
                               _fmt(c['validation']['at_0.50']['false_positive_rate']),
                               _fmt(c['validation']['at_0.50']['recall']),
                               _fmt(c['validation']['at_block_reference']['block_precision'])]
                              for c in run['candidates']]))
    out.append('\nClass balance is close to even in this corpus, so `class_weight="balanced"` changed little. No '
               'resampling and no SMOTE was applied; the comparison was made on validation, not assumed.\n')


def _test_metrics(out, evaluation):
    test = evaluation['test']
    at50 = test['at_0.50']
    out.append('## 6. Locked test metrics\n')
    out.append('Computed once, after selection, from scores produced by the production ONNX adapter.\n')
    out.append(_table(['metric', 'value'], [
        ['rows / positives / negatives', f"{test['rows']} / {test['positives']} / {test['negatives']}"],
        ['precision @0.50', _fmt(at50['precision'])], ['recall @0.50', _fmt(at50['recall'])],
        ['F1 @0.50', _fmt(at50['f1'])], ['false positive rate @0.50', _fmt(at50['false_positive_rate'])],
        ['false negative rate @0.50', _fmt(at50['false_negative_rate'])],
        ['specificity @0.50', _fmt(at50['specificity'])], ['accuracy @0.50', _fmt(at50['accuracy'])],
        ['ROC-AUC', _fmt(test['roc_auc'])], ['PR-AUC', _fmt(test['pr_auc'])],
        ['Brier score', _fmt(test['brier_score'])]]))
    out.append('\nAccuracy is reported because it was asked for, not because it is informative: the corpus is near '
               'balanced by construction, which flatters it.\n')
    out.append('### Confusion matrix at 0.50\n')
    out.append(_confusion(at50['confusion_matrix']))
    out.append('\n### Generalisation to unseen scenario families\n')
    out.append(_table(['subset', 'rows', 'PR-AUC', 'ROC-AUC', 'FPR @0.90', 'recall @0.90', 'families'],
                      [[name, i['rows'], _fmt(i['pr_auc']), _fmt(i['roc_auc']),
                        _fmt(i['at_0.90']['false_positive_rate']), _fmt(i['at_0.90']['recall']),
                        ', '.join(i['families'])] for name, i in evaluation['generalisation'].items()]))
    out.append('\nThis is the most important table in the report. Within families the model already saw, separation is '
               'near perfect; on families it never saw, it is close to unusable. Validation cannot detect this, '
               'because validation shares families with train.\n')


def _thresholds(out, evaluation):
    out.append('## 7. Threshold evaluation\n')
    out.append('The model returns a score. It does not select an action. `DecisionFusion` and `PolicyGuard` decide, '
               'and a WATCH threshold may be far lower than a TEMP_BLOCK threshold.\n')
    out.append(_table(['threshold', 'precision', 'recall', 'FPR', 'FNR', 'block precision',
                       'false blocks / 1000 benign', 'positive decisions'],
                      [[f"{r['threshold']:.2f}", _fmt(r['precision']), _fmt(r['recall']),
                        _fmt(r['false_positive_rate']), _fmt(r['false_negative_rate']), _fmt(r['block_precision']),
                        _fmt(r['false_blocks_per_1000_benign'], 1), r['positive_decisions']]
                       for r in evaluation['threshold_table']]))
    c = evaluation['false_positive_concentration']['0.9']
    out.append('\nRaising the threshold barely moves the false positive rate: the false positives are saturated near '
               f"1.0, so they survive every threshold in the table. At 0.90, {c['false_blocks']} of "
               f"{c['benign_rows']} benign rows are flagged and {_fmt(c['dominant_share_of_false_blocks'], 3)} of them "
               f"come from `{c['dominant_scenario']}`; excluding that one family the rate would be "
               f"{_fmt(c['false_positive_rate_excluding_dominant'])}. That counterfactual is descriptive only.\n")
    out.append('## 8. Score distribution\n')
    out.append(_table(['class', 'count', 'min', 'median', 'mean', 'p90', 'p95', 'p99', 'max'],
                      [[name, i['count'], _fmt(i['min']), _fmt(i['median']), _fmt(i['mean']), _fmt(i['p90']),
                        _fmt(i['p95']), _fmt(i['p99']), _fmt(i['max'])]
                       for name, i in evaluation['score_distribution'].items()]))
    calibration = evaluation['calibration']
    out.append('\n## 9. Calibration\n')
    out.append(f"Brier score {_fmt(calibration['brier_score'])}, expected calibration error over 10 bins "
               f"{_fmt(calibration['expected_calibration_error'])}. The output is reported as `model_score` and the "
               'manifest declares `score_semantics = uncalibrated_model_score`. No calibrator was fitted: the corpus '
               'is small and synthetic, so a calibration curve learned from it would describe the generator.\n')
    out.append(_table(['bin', 'count', 'mean score', 'observed positive fraction'],
                      [[f"{r['bin'][0]:.1f}-{r['bin'][1]:.1f}", r['count'], _fmt(r['mean_score']),
                        _fmt(r['observed_positive_fraction'])] for r in calibration['reliability']]))


def _coefficients(out, run, evaluation):
    coefficients = evaluation['coefficients']
    out.append('\n## 10. Coefficients\n')
    out.append(f"Intercept {_fmt(coefficients['intercept'])}.\n")
    out.append(_table(['feature', 'coefficient', 'absolute importance', 'direction'],
                      [[f"`{r['feature']}`", _fmt(r['coefficient'], 3), _fmt(r['absolute_importance'], 3),
                        r['direction']] for r in coefficients['coefficients'][:16]]))
    out.append('\n### Coefficient sanity review\n')
    out.append('- `anomaly_60s`, `ports_900s`, `ports_60s`, `sequential_60s` and `credentials_60s` pushing towards the '
               'positive class is behaviourally plausible: port breadth, sequential ordering, protocol mismatch and '
               'repeated credential prompts are what automated probing looks like to this sensor.')
    out.append('- `families_60s` carries a large **negative** coefficient while its marginal correlation with the '
               'label is positive. A sign flip against the marginal direction means correlated columns are '
               'redistributing weight, not that protocol diversity indicates benign traffic. Individual coefficients '
               'here are not standalone evidence.')
    out.append('- `available_interarrival_cv_60s` carries meaningful positive weight. It is an availability mask, not '
               'a behaviour, and it is nearly constant in this corpus, so that weight is a corpus artefact.')
    out.append('- `deception_60s` is engine-influenced: the sensor decides whether to answer, so it partly measures '
               'our own behaviour. The ablation below shows it is not load bearing.')
    out.append('- Strong separation on seen families does not make the coefficients trustworthy. The unseen-family '
               'result in section 6 is the counter-evidence.\n')
    out.append('## 11. Feature ablation\n')
    out.append(_table(['variant', 'features', 'val PR-AUC', 'val ROC-AUC', 'val FPR @0.50'],
                      [[name, i['features'], _fmt(i['pr_auc']), _fmt(i['roc_auc']),
                        _fmt(i['at_0.50']['false_positive_rate'])] for name, i in run['ablation'].items()]))
    out.append('\nBehaviour columns alone carry almost all of the separation, and removing the engine-influenced '
               'deception counter changes little. Feature schema 1 has no fingerprint-derived column, so the '
               'fingerprint-domination question does not arise for v1; if such a column is ever added, this ablation '
               'is where it must be checked before the column is trusted.\n')


def _errors(out, evaluation):
    errors = evaluation['error_analysis']
    strict = evaluation['error_analysis_at_0.90']
    out.append('## 12. False positive analysis\n')
    out.append(f"At threshold 0.50: {errors['false_positive_count']} false positives; at 0.90: "
               f"{strict['false_positive_count']}.\n")
    out.append(_table(['scenario family', 'false positives @0.50', 'false positives @0.90'],
                      [[f'`{k}`', v, strict['false_positive_scenarios'].get(k, 0)]
                       for k, v in errors['false_positive_scenarios'].items()]))
    out.append('\nStrongest examples, features only and never payload:\n')
    for row in errors['false_positive_examples'][:6]:
        terms = ', '.join(f"`{t['feature']}`={_fmt(t['value'], 2)} ({t['contribution']:+.2f})"
                          for t in row['top_terms'][:4])
        out.append(f"- `{row['scenario_id']}` score {_fmt(row['model_score'], 3)}, {row['observations']} "
                   f"observations over {row['observation_seconds']}s - {terms}")
    out.append('\n`owner_vulnerability_scanner` is the dominant false positive and it is not a modelling defect. An '
               'authorised scan and an unauthorised scan produce the same behaviour; the difference is authorisation, '
               'which is an identity and policy fact. The correct control is the `PolicyGuard` allowlist, not a '
               'behavioural model. `service_discovery`, `deployment_probe` and `admin_diagnostic` fail the same way '
               'at lower intensity.\n')
    out.append('## 13. False negative analysis\n')
    out.append(f"At threshold 0.50: {errors['false_negative_count']} false negatives; at 0.90: "
               f"{strict['false_negative_count']}.\n")
    families = sorted(set(errors['false_negative_scenarios']) | set(strict['false_negative_scenarios']))
    out.append(_table(['scenario family', 'missed @0.50', 'missed @0.90'],
                      [[f'`{name}`', errors['false_negative_scenarios'].get(name, 0),
                        strict['false_negative_scenarios'].get(name, 0)] for name in families]))
    out.append('\nThe misses are exactly the quiet cases: small port sets, long gaps between probes, low-rate '
               'credential attempts, and repeated-probe bots whose rate resembles a monitoring agent. Moving the '
               'threshold to 0.90 makes this substantially worse while barely improving the false positive rate.\n')
    out.append('## 14. Per-scenario behaviour on test\n')
    out.append(_table(['scenario family', 'label', 'rows', 'flagged @0.50', 'median score', 'max score'],
                      [[f'`{name}`', i['label'], i['rows'], f"{i['flagged_fraction']:.2f}",
                        _fmt(i['median_score'], 3), _fmt(i['max_score'], 3)]
                       for name, i in evaluation['by_scenario'].items()]))


def _onnx(out, run, evaluation):
    parity = run['onnx_parity']
    out.append('\n## 15. ONNX export and equivalence\n')
    out.append(_table(['field', 'value'], [
        ['artifact', f"`{Path(run['artifacts']['model']).name}`"],
        ['size', f"{run['artifacts']['model_bytes']} bytes"],
        ['SHA-256', f"`{evaluation['model_sha256']}`"],
        ['input', '`features`, float32, shape [1, 36], fixed order'],
        ['output', '`label` int64 [1] and `probabilities` float32 [1, 2]; production consumes the positive-class score'],
        ['opset', 'ai.onnx 17 / ai.onnx.ml 3, IR 10, zipmap disabled'],
        ['reproducible bytes', 'yes; the converter graph name is pinned to the model version so an '
                               'identical fit exports an identical file on the same locked environment'],
        ['training vs runtime dtype', f"{parity['training_dtype']} vs {parity['runtime_dtype']}"],
        ['parity rows', parity['rows']],
        ['max absolute difference', f"{parity['max_absolute_difference']:.3e}"],
        ['mean absolute difference', f"{parity['mean_absolute_difference']:.3e}"],
        ['tolerance', f"{parity['tolerance']:.1e}"],
        ['parity passed', _fmt(parity['passed'])],
        ['coefficient widening error', f"{run['coefficient_widening_max_error']:.3e}"],
        ['independent float64 recomputation error', f"{evaluation['analytic_reference_max_error']:.3e}"]]))
    out.append('\nEquality is not assumed to be bit exact: fitting runs in float64 and the runtime graph in float32, '
               'so the difference is measured on every held-out row and the export fails if it exceeds tolerance. The '
               'excluded columns are exported with coefficient exactly zero, which keeps the frozen [1, 36] runtime '
               'contract while the fitted model never saw them. The adapter also rejects a wrong feature count, a '
               'wrong schema version, a wrong tensor shape, non-finite input and a hash that does not match the '
               'manifest.\n')


def _benchmark(out, evaluation):
    benchmark = evaluation.get('benchmark')
    if not benchmark:
        return
    out.append('## 16. Inference benchmark\n')
    out.append(_table(['measurement', 'value'], [
        ['model load', f"{benchmark['load_ms']:.1f} ms"],
        ['single inference p50 / p95 / p99',
         ' / '.join(f"{benchmark['latency_ms'][k]:.3f} ms" for k in ('p50', 'p95', 'p99'))],
        ['inferences per second', f"{benchmark['inferences_per_second']:.0f}"],
        ['process RSS', f"{benchmark['process_rss_bytes']} bytes" if benchmark['process_rss_bytes'] else 'n/a']]))
    out.append('\n' + _table(['batch size', 'rows per second', 'per-row ms'],
                             [[size, f"{i['rows_per_second']:.0f}", f"{i['per_row_ms']:.4f}"]
                              for size, i in benchmark['batches'].items()]))
    out.append(f"\n{benchmark['batch_note']}. Inference is per source per decision window, never per packet. No "
               'performance target is asserted from a single measurement run on one machine.\n')


def _shadow(out, evaluation, shadow):
    if not shadow:
        return
    out.append('## 17. Shadow replay through fusion and policy\n')
    out.append('Enforcement disabled, decision mode shadow, no firewall interaction and no packet transmitted.\n')
    rows = []
    for name, info in shadow['candidates'].items():
        summary = info['summary']
        rows.append([name, summary['total_sources_retained'], summary['would_block_sources'],
                     _fmt(summary['block_precision']),
                     ', '.join(info['benign_sources_that_would_block']) or 'none',
                     sum(info['disagreement_counts'].values())])
    out.append(_table(['candidate', 'sources', 'would block sources', 'block precision',
                       'benign families that would block', 'disagreements'], rows))
    out.append('\nThe mathematical baseline alone would block nothing on this corpus. Adding the model score to '
               'fusion moves sources past the block threshold, and they are the authorised scanner family, so shadow '
               'block precision is 0. On this evidence the model must not gain enforcement authority.\n')
    model_side = shadow['candidates'].get(evaluation['model_version'], {})
    out.append('### Disagreements kept for investigation\n')
    for kind, examples in model_side.get('disagreement_examples', {}).items():
        out.append(f'\n**{kind}**\n')
        out.append(_table(['scenario family', 'label', 'math score', 'model score', 'fused risk', 'action'],
                          [[f"`{e['scenario_id']}`", e['label'], _fmt(e['math_score'], 3), _fmt(e['model_score'], 3),
                            _fmt(e['fused_risk'], 3), e['action']] for e in examples[:8]]))
    out.append('\nThe model is consistently more aggressive than the mathematical baseline, mostly on true positives, '
               'which is where its value would be. `PolicyGuard` holds almost all of it at WATCH or OBSERVE through '
               'the data-quality, minimum-sample and math-confirmation gates. Cases in the other direction '
               '(math high, model low) are worth investigating whenever they appear.\n')


def _pcap(out, pcap):
    if not pcap:
        return
    out.append('## 18. Offline PCAP replay\n')
    out.append('Captures are read from disk through the existing offline analysis path and never '
               'retransmitted; enrichment, active probes, firewall and enforcement are refused by that path. '
               'The corpus labels belong to the correlation label space, not the model label space, so they are '
               'reported beside the decisions and never scored against them.\n')
    rows = []
    for sample in pcap['samples']:
        for source, info in sample['decisions_by_source'].items():
            rows.append([sample['id'], sample['packets'],
                         ', '.join(f"{k}={v}" for k, v in sample['observed_correlation_labels'].items()),
                         info['decisions'], _fmt(info['math_score'], 3), _fmt(info['model_score'], 3),
                         _fmt(info['highest_risk'], 3), info['action_at_highest_risk'],
                         _fmt(info['would_enforce']), ', '.join(info['disagreements']) or 'none'])
    out.append(_table(['sample', 'packets', 'correlation label', 'decisions', 'math score', 'model score',
                       'fused risk', 'action', 'would enforce', 'disagreement'], rows))
    out.append('\nThe corpus is two tiny deterministic synthetic captures, so this is an integration result and not '
               'accuracy evidence. What it does show is that the whole chain runs: packets to deterministic parser '
               'to correlation to FeatureVector to ONNX score to fusion to policy, with no enforcement and no '
               'transmitted traffic.\n')


def _gate(out, run, evaluation):
    gate = evaluation.get('quality_gate') or {}
    parity = run['onnx_parity']
    locked = run['locked_test_metrics']['at_block_reference']
    configured = run['quality_gate']
    out.append('## 19. Quality gate\n')
    out.append(f"Status **{configured['status']}**. These thresholds are conservative starting candidates proposed "
               'for review. No measured deployment data supports them yet, and they must not be presented as '
               'established production targets.\n')
    out.append(_table(['check', 'configured', 'measured', 'result'], [
        ['test FPR at reference block threshold', f"<= {configured['max_test_false_positive_rate']}",
         _fmt(locked['false_positive_rate']), _fmt(gate.get('test_false_positive_rate_ok'))],
        ['test block precision at reference block threshold', f">= {configured['min_test_block_precision']}",
         _fmt(locked['block_precision']), _fmt(gate.get('test_block_precision_ok'))],
        ['ONNX parity', f"<= {configured['max_onnx_parity_error']:.1e}",
         f"{parity['max_absolute_difference']:.3e}", _fmt(gate.get('onnx_parity_ok'))],
        ['no group leakage', 'required', 'none detected', _fmt(gate.get('no_group_leakage'))],
        ['**overall**', '', '', f"**{_fmt(gate.get('passed'))}**"]]))
    out.append(f"\nReference block threshold used for the gate: {configured['reference_block_threshold']}. The gate "
               'failing is the expected and correct outcome for a first baseline on synthetic data. The artifact is '
               'still exported, because the pipeline, the frozen contract and the parity checks are the deliverable; '
               'the manifest records `quality_gate_passed=false` and `recommended_mode=shadow`.\n')


def _closing(out, run, evaluation):
    out.append('## 20. Known limitations\n')
    for item in evaluation['limitations']:
        out.append(f'- {item}')
    out.append('- the model cannot distinguish authorised from unauthorised automation, because authorisation is not '
               'a behaviour')
    out.append('- coefficients are not individually interpretable; correlated columns redistribute weight')
    out.append('- the selected C is the weakest regularisation in the grid, chosen on a validation split that shares '
               'scenario families with train; the unseen-family result is the honest counterweight')
    out.append('- a single measurement run on one machine is not a performance guarantee')
    out.append('- no PCAP replay corpus and no sanitised production shadow export existed to evaluate against\n')
    out.append('## 21. Recommendation\n')
    out.append('**SHADOW ONLY.** Do not grant this model enforcement authority and do not enable automatic firewall '
               'blocking from its score.\n\nBefore limited enforcement could even be discussed, all of the following '
               'would have to hold, and none of them holds today:\n')
    for index, item in enumerate((
            'an independent, realistic, labelled evaluation set not generated by this repository',
            'a test split independent at the capture-domain level, not only at the source level',
            'block precision measured on that data at the threshold policy would actually use',
            "hard negatives from the real environment, including its own monitoring and scanning tools",
            "an acceptable false positive rate agreed with the operator, in the operator's own units",
            'ONNX parity and manifest verification on the promoted artifact',
            'shadow replay in that environment supporting the offline result'), 1):
        out.append(f'{index}. {item};')
    out.append('\n## 22. Next experiment\n')
    out.append('Do not replace this baseline yet. The next step is a gradient boosting candidate trained and evaluated '
               'on the **exact same** dataset version, split, feature contract, metrics and threshold table, so the '
               'comparison is fair. Expect it to fit the seen families better; the question worth answering is '
               'whether it does anything for the unseen families, which is where this baseline fails.\n')
    out.append('## 23. Reproduction\n')
    out.append(_table(['component', 'version'], list(run['environment'].items())))
    dataset, model = run['dataset_version'], evaluation['model_version']
    out.append('\n~~~sh\n'
               'uv sync --frozen --extra ml --extra ml-training\n'
               f'uv run --frozen python -m training.dataset --output datasets/{dataset}\n'
               f'uv run --frozen python -m training.validation --dataset datasets/{dataset}\n'
               f'uv run --frozen python -m training.train_logreg --dataset datasets/{dataset} --output-dir models\n'
               f'uv run --frozen python -m training.evaluate_model --dataset datasets/{dataset} --model-dir models \\\n'
               f'    --output models/{model}-evaluation.json --report reports/model-{model}.md \\\n'
               f'    --shadow models/{model}-shadow.json --pcap models/{model}-pcap.json\n'
               f'uv run --frozen python -m training.shadow_replay --dataset datasets/{dataset} --model-dir models \\\n'
               f'    --output models/{model}-shadow.json\n'
               f'uv run --frozen python -m training.pcap_evaluate --corpus tests/fixtures/p2/corpus.json \\\n'
               f'    --model-dir models --output models/{model}-pcap.json\n'
               '~~~\n')


def render(evaluation, training_path, shadow_path=None, pcap_path=None):
    run = json.loads(Path(training_path).read_text(encoding='utf-8'))
    shadow = json.loads(Path(shadow_path).read_text(encoding='utf-8')) if shadow_path else None
    pcap = json.loads(Path(pcap_path).read_text(encoding='utf-8')) if pcap_path else None
    validation = evaluation['dataset_validation']
    out = [f"# Model report: {evaluation['model_version']}\n",
           '> **ENGINEERING BASELINE ONLY - NOT VALIDATED FOR PRODUCTION ENFORCEMENT.**\n>\n'
           '> The corpus is locally generated synthetic behaviour. Every number below describes that corpus and\n'
           '> nothing else. None of it estimates deployment accuracy, prevalence or risk.\n'
           f"> Recommended deployment mode: **{str(evaluation['recommended_mode']).upper()} ONLY**.\n"
           f"> Quality gate passed: **{_fmt(evaluation['quality_gate_passed'])}**.\n",
           '## 1. Purpose\n\nBuild a reproducible training, evaluation and export pipeline, and a first local ONNX '
           'baseline that later candidates can be compared against on identical data, splits, features, metrics and '
           'thresholds. The purpose is a trustworthy experiment, not a high score.\n']
    _dataset(out, run, validation)
    _contract(out, run, evaluation)
    _split(out, run, validation, validation['class_distribution'])
    _hyperparameters(out, run)
    _test_metrics(out, evaluation)
    _thresholds(out, evaluation)
    _coefficients(out, run, evaluation)
    _errors(out, evaluation)
    _onnx(out, run, evaluation)
    _benchmark(out, evaluation)
    _shadow(out, evaluation, shadow)
    _pcap(out, pcap)
    _gate(out, run, evaluation)
    _closing(out, run, evaluation)
    return '\n'.join(out) + '\n'
