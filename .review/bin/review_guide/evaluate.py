"""Frozen trial plans and human-judged comparisons; never promotes a model itself."""

from collections import Counter
from dataclasses import dataclass
import hashlib
import hmac
import json
import math

from .contracts import Json, ValidationError, digest, hex_digest, require, validate_case, validate_eval_manifest, validate_output


@dataclass(frozen=True)
class JudgedTrial:
    record: Json
    judgment: Json


def seal_trial(trial: JudgedTrial, operator_key: bytes) -> Json:
    require(isinstance(trial, JudgedTrial) and bool(operator_key), 'operator judgment required')
    payload = {'record': trial.record, 'judgment': trial.judgment}
    return payload | {'receipt': hmac.new(operator_key, digest(payload).encode(), hashlib.sha256).hexdigest()}


def open_trial(value: Json, operator_key: bytes) -> JudgedTrial:
    require(set(value) == {'record', 'judgment', 'receipt'}, 'signed operator record required')
    expected = seal_trial(JudgedTrial(value['record'], value['judgment']), operator_key)['receipt']
    require(isinstance(value['receipt'], str) and hmac.compare_digest(value['receipt'], expected), 'operator receipt mismatch')
    return JudgedTrial(value['record'], value['judgment'])


def build_eval_manifest(cases: list[Json], configs: list[Json], rubric: Json) -> Json:
    require(rubric.get('version') == 1, 'unsupported rubric')
    trials = rubric.get('critical_trials', 3)
    require(type(trials) is int and trials >= 3, 'critical cases require at least three trials')
    require(len(configs) == 2 and len({digest(c) for c in configs}) == 2, 'two distinct execution configurations required')
    for field in ('tools_digest', 'rules_digest'):
        for config in configs:
            hex_digest(config.get(field), field)
        require(configs[0][field] == configs[1][field], 'comparison conditions differ: ' + field)
    require(bool(cases) and len({c['id'] for c in cases}) == len(cases), 'nonempty unique case collection required')
    for case in cases:
        validate_case(case)
        require(case['status'] == 'confirmed', 'only confirmed cases can be evaluated')
        require(case['split'] == rubric.get('split', 'holdout'), 'tuning and holdout cases must remain separate')
    canonical = sorted(cases, key=lambda c: c['id'])
    manifest = {'schema_version': 1, 'corpus_digest': digest(canonical), 'rubric_digest': digest(rubric),
                'cases': {c['id']: {'input_digest': c['input_digest'], 'critical': c['critical'],
                                   'answer_ids': [a['id'] for a in c['answers']]} for c in canonical},
                'configurations': {digest(c): c for c in configs}, 'configuration_order': [digest(c) for c in configs],
                'expected': [{'case_id': c['id'], 'configuration_digest': digest(config), 'trial_index': trial}
                             for config in configs for c in canonical
                             for trial in range(1, (trials if c['critical'] else 1) + 1)]}
    return validate_eval_manifest(manifest)


def _key(record):
    if (not isinstance(record, dict) or not isinstance(record.get('case_id'), str)
            or not isinstance(record.get('configuration_digest'), str) or type(record.get('trial_index')) is not int):
        return None
    return record['case_id'], record['configuration_digest'], record['trial_index']


def _score(trial: JudgedTrial, case: Json) -> Json:
    answers = set(case['answer_ids'])
    judgment = trial.judgment
    for field in ('actor', 'at', 'reason'):
        require(isinstance(judgment.get(field), str) and bool(judgment[field].strip()), 'incomplete human judgment')
    found, pending, false_positives, unfamiliar = {}, 0, {}, 0
    for stage in ('bugs', 'security', 'verify'):
        result = validate_output({k: v for k, v in trial.record['stages'][stage].items()
                                  if k in {'status','findings','summary','risk','patch','dispositions'}}, stage)
        require(result['status'] in {'verified', 'findings'}, 'incomplete review stage')
        ids = {f['id'] for f in result['findings']}
        require(len(ids) == len(result['findings']), 'duplicate finding identity')
        matches = judgment.get('matches', {}).get(stage, {})
        require(set(matches).issubset(ids) and set(matches.values()).issubset(answers), 'judgment does not match stage evidence')
        found[stage] = set(matches.values())
        false_positives[stage] = 0
        for finding_id in ids - set(matches):
            label = judgment.get('extras', {}).get(stage + ':' + finding_id, 'pending')
            require(label in {'false_positive','unexpected_true_positive','pending'}, 'unknown extra finding judgment')
            if label == 'false_positive': false_positives[stage] += 1
            elif label == 'pending': pending += 1
            else: unfamiliar += 1
    detected = found['bugs'] | found['security']
    final = found['verify']
    missed = len(answers - final)
    return {'expected_answers':len(answers), 'detected':len(detected), 'verified':len(final), 'final':len(final),
            'critical_misses': missed if case['critical'] else 0,
            'ordinary_misses': missed if not case['critical'] else 0,
            'false_positives':false_positives['verify'], 'stage_false_positives':false_positives,
            'pending':pending, 'unexpected_true_positives':unfamiliar}


def compare_runs(manifest: Json, baseline: list, candidate: list, rubric: Json) -> Json:
    manifest = validate_eval_manifest(manifest)
    expected = {_key(t) for t in manifest['expected']}
    reasons, accepted, scores = [], {}, {}
    if digest(rubric) != manifest['rubric_digest']:
        reasons.append('rubric_mismatch')
    if rubric.get('split', 'holdout') != 'holdout':
        reasons.append('tuning_results_cannot_promote')
    for rows, config_id in zip((baseline, candidate), manifest['configuration_order']):
        counts = Counter(_key(t.record) for t in rows if isinstance(t, JudgedTrial))
        for item in rows:
            if not isinstance(item, JudgedTrial):
                reasons.append('unconfirmed_judgment'); continue
            record = item.record
            key = _key(record)
            if key not in expected or record['configuration_digest'] != config_id:
                reasons.append('unexpected_trial'); continue
            if counts[key] != 1:
                reasons.append('duplicate_trial'); continue
            case = manifest['cases'][record['case_id']]
            configuration = manifest['configurations'][config_id]
            if (record.get('corpus_digest') != manifest['corpus_digest']
                    or record.get('rubric_digest') != manifest['rubric_digest']
                    or record.get('input_digest') != case['input_digest']
                    or any(record.get(f) != configuration[f] for f in ('tools_digest','rules_digest'))):
                reasons.append('condition_mismatch'); continue
            if record.get('status') != 'complete':
                reasons.append('incomplete_trial'); continue
            try:
                score = _score(item, case)
            except (ValidationError, KeyError, TypeError, AttributeError):
                reasons.append('invalid_or_incomplete_judgment'); continue
            accepted[key], scores[key] = record, score
    if expected - set(accepted): reasons.append('missing_or_invalid_trials')
    metrics = {}
    additive = ('expected_answers','detected','verified','final','critical_misses','ordinary_misses',
                'false_positives','pending','unexpected_true_positives')
    for config_id in manifest['configuration_order']:
        keys = [k for k in accepted if k[1] == config_id]
        metric = {field: sum(scores[k][field] for k in keys) for field in additive}
        metric['expected_trials'] = sum(k[1] == config_id for k in expected)
        metric['complete_trials'] = len(keys)
        metric['stage_false_positives'] = {stage:sum(scores[k]['stage_false_positives'][stage] for k in keys)
                                            for stage in ('bugs','security','verify')}
        elapsed = [accepted[k].get('elapsed_s') for k in keys]
        metric['elapsed_s'] = (sum(elapsed) if all(type(t) in (int,float) and math.isfinite(t) and t>=0 for t in elapsed) else None)
        usage = [accepted[k].get('usage') for k in keys]
        metric['usage'] = None
        if usage and all(isinstance(u,dict) and all(type(v) is int and v>=0 for v in u.values()) for u in usage):
            metric['usage'] = {field:sum(u.get(field,0) for u in usage) for field in set().union(*usage)}
        metrics[config_id] = metric
    old, new = (metrics[c] for c in manifest['configuration_order'])
    if any(m['pending'] for m in metrics.values()): reasons.append('pending_judgments')
    if new['critical_misses']: reasons.append('critical_miss')
    if any(new[field] < old[field] for field in ('detected','verified','final')):
        reasons.append('review_regression')
    if new['false_positives'] > old['false_positives']: reasons.append('false_positive_regression')
    return {'decision':'hold' if reasons else 'eligible_for_human_review', 'reasons':sorted(set(reasons)),
            'corpus_digest':manifest['corpus_digest'], 'rubric_digest':manifest['rubric_digest'],
            'expected_count':len(expected), 'complete_count':len(accepted), 'completion_rate':len(accepted)/len(expected),
            'metrics':metrics, 'trials': [{'case_id':k[0], 'configuration_digest':k[1], 'trial_index':k[2], **score}
                                         for k, score in scores.items()]}
