"""Evaluation uses input-only workspaces and the same gated role workers, without publication."""

import copy
import hashlib
import json
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .cases import checked_case, materialize_case
from .codex import build_request, run_codex
from .contracts import Json, digest, require, validate_config, validate_eval_manifest

ROLES = ('bugs', 'security', 'verify')


def describe_tools(profile: Path) -> str:
    settings = tomllib.loads(profile.read_text())
    return digest({key: settings.get(key) for key in ('permissions', 'web_search', 'mcp_servers', 'project_doc_max_bytes')})


def prepare_trial(manifest: Json, case: Path, configuration_digest: str, trial_index: int,
                  workspace: Path, started_at: str | None = None) -> Json:
    manifest = validate_eval_manifest(manifest)
    record = checked_case(case)
    key = {'case_id':record['id'], 'configuration_digest':configuration_digest, 'trial_index':trial_index}
    require(key in manifest['expected'], 'trial not declared in frozen manifest')
    require(record['input_digest'] == manifest['cases'][record['id']]['input_digest'], 'case differs from manifest')
    cfg = validate_config(manifest['configurations'][configuration_digest])
    if cfg['mode'] == 'api':
        require(cfg['api_budget']['max_calls'] >= 3, 'trial requires three model calls')
    materialize_case(case, workspace)
    created = datetime.fromisoformat(started_at.replace('Z','+00:00')) if started_at else datetime.now(timezone.utc)
    require(created.tzinfo is not None, 'start time requires timezone')
    run = {'schema_version':1, 'repository':'evaluation/input', 'pr':1, 'base_sha':'0'*40, 'head_sha':'1'*40,
           'policy_sha':'0'*40, 'input_digest':record['input_digest'], 'config_digest':configuration_digest,
           'rules':{'REVIEW.md':hashlib.sha256((workspace/'policy/REVIEW.md').read_bytes()).hexdigest()},
           'prompt_digest':'0'*64, 'mode':cfg['mode'], 'auth_kind':'chatgpt' if cfg['mode']=='self_hosted' else 'api_key',
           'model':cfg['model'], 'codex_version':cfg['codex_version'], 'runner':cfg.get('runner','linux'),
           'round':1, 'role':'bugs', 'deadline_at':(created+timedelta(seconds=cfg['run_timeout_s'])).isoformat(),
           'status':'incomplete','findings':[], 'evidence':[], 'kind':'evaluation',
           'intent':json.loads((workspace/'context.json').read_text())}
    return {'trial':key | {'input_digest':record['input_digest'], 'corpus_digest':manifest['corpus_digest'],
                          'rubric_digest':manifest['rubric_digest'], 'tools_digest':cfg['tools_digest'],
                          'rules_digest':cfg['rules_digest']},
            'run':run, 'config':cfg, 'stages':{}, 'requests':{}}


def trial_request(bundle: Json, role: str, workspace: Path) -> Json:
    require(role in ROLES, 'invalid evaluation role')
    for previous in ROLES[:ROLES.index(role)]:
        require(bundle['stages'].get(previous, {}).get('status') in {'verified','findings'}, 'previous stage did not complete')
    run = copy.deepcopy(bundle['run'])
    run['role'] = role
    # Only prior model findings enter verifier context. Answers, judgments and source links do not.
    run['candidates'] = {stage: result['findings'] for stage, result in bundle['stages'].items()}
    request = build_request(role, run, workspace, bundle['config'])
    require(bundle['config'].get('tools_digest') == describe_tools(Path(request['codex_home'])/'config.toml'),
            'actual tool policy differs from frozen evaluation conditions')
    return request


def trial_record(bundle: Json) -> Json:
    stages = bundle['stages']
    complete = all(stages.get(role, {}).get('status') in {'verified','findings'} for role in ROLES)
    elapsed = [stages.get(role, {}).get('elapsed_s') for role in ROLES]
    usage = [stages.get(role, {}).get('usage') for role in ROLES]
    observed = None
    if all(isinstance(u,dict) for u in usage):
        observed = {key:sum(u.get(key,0) for u in usage) for key in set().union(*usage)}
    return bundle['trial'] | {'status':'complete' if complete else 'incomplete', 'stages':stages,
                             'requests':bundle['requests'], 'usage':observed,
                             'elapsed_s':sum(elapsed) if all(type(e) in (int,float) for e in elapsed) else None}


def run_trial(bundle: Json, workspace: Path, executable: Path) -> Json:
    require(bundle['config']['mode']=='self_hosted', 'API trials must use the official Codex Action')
    for role in ROLES:
        request = trial_request(bundle, role, workspace)
        bundle['requests'][role] = {'prompt_digest':request['prompt_digest'], 'isolation_report_digest':request['gate']['report_digest']}
        result = run_codex(request, executable, request['timeout_s'])
        bundle['stages'][role] = result
        if result['status'] not in {'verified','findings'}: break
    return trial_record(bundle)


def ci_eval_main(operation, repo, cfg, api):
    import os
    import shutil
    from .contracts import relative_path
    from .codex import normalize_action
    from .pipeline import read, write
    if operation=='eval-entry':
        require(os.environ['GITHUB_REF']==cfg['trusted_ref'], 'evaluation must start on protected ref')
        require(cfg.get('entry_isolation',{}).get('status')=='verified', 'entry isolation needs verification')
        source = read(os.environ['GITHUB_EVENT_PATH'])['inputs']
        manifest = read(repo/'.review/evals'/relative_path(source['manifest']))
        case_id = relative_path(source['case_id'])
        require('/' not in case_id and case_id in manifest['cases'], 'case is not in manifest')
        selected = validate_config(manifest['configurations'][source['configuration']])
        require(selected['mode']==cfg['mode'], 'trial cannot switch the configured authentication mode')
        if cfg['mode']=='api':
            require(selected['api_budget']['approved_usd']<=cfg['api_budget']['approved_usd']
                    and selected['api_budget']['max_calls']<=cfg['api_budget']['max_calls'], 'trial exceeds approved budget')
        metadata = api.call('GET', f'/repos/{cfg["repository"]}/actions/runs/{int(os.environ["GITHUB_RUN_ID"])}')
        require(metadata['actor']['type']=='User' and metadata['actor']['login'] in cfg['allowed_actors'], 'evaluation actor not allowed')
        bundle = prepare_trial(manifest,repo/'.review/evals/cases'/case_id,source['configuration'],int(source['trial']),
                               Path('out/workspace'),metadata['created_at'])
        write('out/trial.json',bundle)
        with open(os.environ['GITHUB_OUTPUT'],'a') as handle: handle.write('mode='+selected['mode']+'\n')
        return {'status':'prepared'}
    bundle = read('input/trial.json')
    if operation=='eval-self-hosted':
        from .ssh_worker import run_remote, connection_from_environment
        for role in ROLES:
            run = copy.deepcopy(bundle['run']); run['role'] = role
            run['candidates'] = {stage:r['findings'] for stage,r in bundle['stages'].items()}
            result = run_remote(run,bundle['config'],Path('input/workspace'),connection_from_environment())
            bundle['stages'][role] = result
            bundle['requests'][role] = result.get('request_evidence', {})
            if result['status'] not in {'verified','findings'}: break
        result = trial_record(bundle)
        write('trial-record.json',result); return {'status':result['status']}
    role = os.environ.get('EVAL_ROLE')
    if operation=='eval-request':
        require(role in ROLES, 'invalid evaluation role')
        workspace = Path('/home/runner/review-input')
        home = Path('/home/runner/review-home')
        if role=='bugs':
            require(not workspace.exists() and not home.exists(), 'evaluation runtime paths already exist')
            shutil.copytree('input/workspace',workspace)
            home.mkdir(mode=0o700)
            for name in ('config.toml','isolation.json'):
                shutil.copyfile(repo/'.review/runtime/api'/name,home/name)
        bundle['config']['isolation'].update(codex_home=str(home),report_path=str(home/'isolation.json'))
        request = trial_request(bundle,role,workspace)
        minutes = int(request['timeout_s']//60)
        require(minutes>=1,'shared deadline has less than a minute left')
        bundle['requests'][role] = {'prompt_digest':request['prompt_digest'],'isolation_report_digest':request['gate']['report_digest']}
        Path('request').mkdir(exist_ok=True); Path('request/prompt.md').write_text(request['prompt'])
        write('input/trial.json',bundle)
        with open(os.environ['GITHUB_OUTPUT'],'a') as handle:
            for field,value in {'timeout_minutes':str(minutes), **{f:request[f] for f in ('model','effort','codex_version')}}.items():
                require('\n' not in value and '\r' not in value,'invalid setting')
                handle.write(field+'='+value+'\n')
        return {'status':'prepared'}
    if operation=='eval-normalize':
        require(role in ROLES,'invalid evaluation role')
        path = Path('raw-'+role+'.json')
        bundle['stages'][role] = normalize_action(path.read_text() if path.is_file() else '', os.environ['ACTION_OUTCOME'])
        write('input/trial.json',bundle)
        return {'status':bundle['stages'][role]['status']}
    require(operation=='eval-record','unknown evaluation command')
    result = trial_record(bundle); write('trial-record.json',result); return {'status':result['status']}
