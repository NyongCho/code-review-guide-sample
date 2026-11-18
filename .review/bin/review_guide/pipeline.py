"""Trusted Actions controller. Workers return data; only this controller chooses transitions."""

import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contracts import Json, digest, require, validate_config
from .codex import build_request, run_codex, normalize_action
from .github import GitHub, get_pr, input_digest, verify_entry, verify_current, publish_result, publish_patch, begin_checks, verify_merge_gate
from .lifecycle import initial_state, advance
from .workspace import prepare_workspace
from .workflows import PYTHON_IMAGE, selected_result


def now():
    return datetime.now(timezone.utc).isoformat()


def event(state, kind, **values):
    return {'id': str(uuid.uuid4()), 'kind': kind, 'head_sha': state['head_sha'], 'at': now(), **values}


def stop(state, status, reason):
    return state | {'terminal': True, 'next_role': None, 'phase': 'done', 'status': status, 'reason': reason}


def inspect_state(state: Json, config: Json, tests: Json | None, api: GitHub) -> Json:
    cfg = validate_config(config)
    state = copy.deepcopy(state)
    fresh = verify_current(state, get_pr(state['repository'], state['pr'], api=api))
    if fresh['status'] != 'verified':
        return stop(state, fresh['status'], fresh['reason'])
    if state['terminal']:
        return state
    state = advance(state, event(state, 'tick'), cfg)
    if state['terminal']:
        return state
    if state['tested_head'] != state['head_sha']:
        if not tests or tests.get('head_sha') != state['head_sha']:
            return stop(state, 'incomplete', 'current-head test evidence missing')
        state = advance(state, event(state, 'tests_result', passed=tests.get('status') == 'passed'), cfg)
    if state['terminal']:
        return state
    if cfg.get('entry_isolation', {}).get('status') != 'verified' or cfg['isolation'].get('status') != 'verified':
        return stop(state, 'incomplete', 'entry/runtime isolation needs verification')
    state['role'] = state['next_role']
    return state


def collect_state(state: Json, config: Json, outcomes: Json, result: Json | None, api: GitHub, repo: Path) -> Json:
    if state['terminal']:
        return state
    cfg = validate_config(config)
    fresh = verify_current(state, get_pr(state['repository'], state['pr'], api=api))
    if fresh['status'] != 'verified':
        return stop(state, fresh['status'], fresh['reason'])
    state = advance(state, event(state, 'model_result', role=state['next_role'],
                                result=selected_result(cfg['mode'], outcomes, result)), cfg)
    if state['phase'] == 'publish':
        publication = publish_patch(state, state['edits'], cfg, repo, api)
        state = advance(state, event(state, 'patch_result', result=publication), cfg)
    if state['next_role']:
        state['role'] = state['next_role']
    return state


def test_command(source: Path, command: list[str], name: str) -> list[str]:
    return ['docker', 'run', '--rm', '--name', name, '--network=none', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=1g', '--cpus=2',
            '--user=65534:65534', '--tmpfs=/tmp:rw,noexec,nosuid,size=64m',
            '--mount', f'type=bind,source={source.resolve()},target=/project,readonly',
            '--workdir=/project', '--env=PYTHONDONTWRITEBYTECODE=1', PYTHON_IMAGE, *command]


def run_tests(state, cfg, source):
    if state['terminal'] or state['tested_head'] == state['head_sha']:
        return {'status': 'skipped', 'head_sha': state['head_sha']}
    deadline = datetime.fromisoformat(state['deadline_at'])
    evidence = []
    # Pull outside the untrusted container. No host credentials/env are mounted in it.
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    if remaining <= 0:
        return {'status': 'incomplete', 'head_sha': state['head_sha']}
    subprocess.run(['docker', 'pull', PYTHON_IMAGE], check=True, capture_output=True, timeout=min(remaining, 120))
    for argv in cfg['test_commands']:
        name = 'review-tests-' + uuid.uuid4().hex
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            return {'status': 'incomplete', 'head_sha': state['head_sha']}
        def output_limit():
            import resource
            resource.setrlimit(resource.RLIMIT_FSIZE, (2_000_000, 2_000_000))
        try:
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                proc = subprocess.run(test_command(source, argv, name), stdout=stdout, stderr=stderr,
                                      timeout=min(600, remaining), preexec_fn=output_limit)
                evidence.append({'command': argv, 'exit_code': proc.returncode})
                if proc.returncode:
                    return {'status': 'failed', 'head_sha': state['head_sha'], 'commands': evidence}
        except subprocess.TimeoutExpired:
            return {'status': 'incomplete', 'head_sha': state['head_sha'], 'commands': evidence}
        finally:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    return {'status': 'passed', 'head_sha': state['head_sha'], 'commands': evidence}


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def fetch(repo: Path, state, token):
    import base64
    env = {k: v for k, v in os.environ.items() if k not in {'GH_TOKEN', 'GITHUB_TOKEN', 'OPENAI_API_KEY'}}
    header = 'AUTHORIZATION: basic ' + base64.b64encode(('x-access-token:' + token).encode()).decode()
    env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.https://github.com/.extraheader', GIT_CONFIG_VALUE_0=header)
    for sha in dict.fromkeys([state['base_sha'], state['head_sha']]):
        subprocess.run(['git', '-C', str(repo), '-c', 'core.hooksPath=/dev/null', 'fetch', '--no-tags', '--depth=1', 'origin', sha],
                       check=True, env=env, capture_output=True, timeout=60)


def save_bundle(state, cfg, repo, token, old_workspace=None):
    out = Path('out'); out.mkdir(exist_ok=True)
    workspace = out/'workspace'
    if old_workspace is not None and old_workspace.exists() and read(old_workspace/'input-manifest.json')['head_sha'] == state['head_sha']:
        shutil.copytree(old_workspace, workspace)
    else:
        fetch(repo, state, token)
        prepare_workspace(repo, state['base_sha'], state['head_sha'], workspace, [])
    state['changed_paths'] = read(workspace/'input-manifest.json')['changed_paths']
    write(out/'state.json', state); write(out/'config.json', cfg)
    if state['phase'] == 'fix' or state['terminal'] and state['status'] in {'verified', 'findings'}:
        from .cases import propose_case
        propose_case(state, workspace, out/'candidate')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as handle:
            for key, value in {'role': state.get('next_role') or '', 'phase': state['phase'], 'head': state['head_sha'],
                               'mode': cfg['mode'], 'terminal': str(state['terminal']).lower()}.items():
                handle.write(f'{key}={value}\n')


def ci_main(operation: str, artifact_name=None, destination=None) -> Json:
    """Invoked only from the protected workflow checkout, never from an artifact."""
    repo = Path('trusted').resolve()
    cfg = validate_config(read(repo/'.review/config.json'))
    token = os.environ.get('GH_TOKEN', '')
    api = GitHub(token)
    publisher = None
    if operation in {'entry', 'finish'}:
        require(bool(os.environ.get('REVIEW_CHECK_TOKEN')), 'dedicated check publisher token required')
        publisher = GitHub(os.environ['REVIEW_CHECK_TOKEN'])
        verify_merge_gate(cfg, publisher)
    if operation.startswith("eval-"):
        from .eval_runtime import ci_eval_main
        return ci_eval_main(operation, repo, cfg, api)
    if operation == 'fetch-artifact':
        from .github import download_artifact
        name = f'{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}-{artifact_name}'
        run_id = int(os.environ['GITHUB_RUN_ID'])
        metadata = api.call('GET', f'/repos/{cfg["repository"]}/actions/runs/{run_id}')
        require(metadata.get('id') == run_id and metadata.get('run_attempt') == int(os.environ['GITHUB_RUN_ATTEMPT']),
                'artifact run attempt mismatch')
        # pull_request_target artifacts name the event head, not the protected workflow commit.
        # The downloaded state must still match GITHUB_WORKFLOW_SHA before use below.
        download_artifact(cfg['repository'], {'name': name, 'run_id': run_id,
                          'head_sha': metadata['head_sha']}, destination, api)
        return {'status': 'downloaded'}
    if operation == 'approval':
        require(os.environ.get('GITHUB_REF') == cfg['trusted_ref'], 'approval requires trusted ref')
        binding = json.loads(os.environ['BINDING'])
        require(isinstance(binding, dict) and bool(binding), 'binding object required')
        with open(os.environ['GITHUB_OUTPUT'], 'a') as handle:
            handle.write('digest=' + digest(binding) + '\n')
        return {'status': 'prepared', 'binding_digest': digest(binding)}
    if operation == 'entry':
        source = read(os.environ['GITHUB_EVENT_PATH'])
        pr = get_pr(cfg['repository'], source['number'], api=api)
        verify_entry(pr, cfg, os.environ['GITHUB_REF'])
        require(pr['base']['sha'] == os.environ['GITHUB_WORKFLOW_SHA'], 'base moved since trusted workflow selection')
        commit = api.call('GET', f'/repos/{cfg["repository"]}/commits/{pr["head"]["sha"]}')
        require(commit['sha'] == pr['head']['sha'], 'intent commit mismatch')
        created = datetime.now(timezone.utc)
        state = {'schema_version': 1, 'repository': cfg['repository'], 'pr': pr['number'], 'base_sha': pr['base']['sha'],
                 'head_sha': pr['head']['sha'], 'policy_sha': os.environ['GITHUB_WORKFLOW_SHA'],
                 'input_digest': input_digest(pr), 'config_digest': digest(cfg),
                 'rules': {'REVIEW.md': hashlib.sha256((repo/'REVIEW.md').read_bytes()).hexdigest()},
                 'prompt_digest': '0'*64, 'mode': cfg['mode'], 'auth_kind': 'chatgpt' if cfg['mode']=='self_hosted' else 'api_key',
                 'model': cfg['model'], 'codex_version': cfg['codex_version'], 'runner': cfg.get('runner', 'linux'),
                 'round': 1, 'role': 'bugs', 'created_at': created.isoformat(),
                 'deadline_at': (created + timedelta(seconds=cfg['run_timeout_s'])).isoformat(),
                 'status': 'incomplete', 'findings': [], 'evidence': [],
                 'execution_id': os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'],
                 'intent': {'head_commit_message': commit['commit']['message']}}
        # created_at belongs to the original run; run_started_at advances on each rerun.
        metadata = api.call('GET', f'/repos/{cfg["repository"]}/actions/runs/{int(os.environ["GITHUB_RUN_ID"])}')
        started = datetime.fromisoformat(metadata['run_started_at'].replace('Z', '+00:00'))
        state['created_at'] = started.isoformat()
        state['deadline_at'] = (started + timedelta(seconds=cfg['run_timeout_s'])).isoformat()
        state = initial_state(state, cfg)
        begin_checks(state, cfg, publisher)
        save_bundle(state, cfg, repo, token)
        manifest = read('out/workspace/input-manifest.json')
        state['changed_paths'] = manifest['changed_paths']
        write('out/state.json', state)
        return {'status': 'prepared'}
    if operation == 'finish':
        outcomes = json.loads(os.environ['JOB_OUTCOMES'])
        # Recover only artifacts produced by successful trusted controller jobs in this attempt.
        candidates = ['entry'] + [name for i in range(cfg['max_rounds']*4+3)
                                 for name in (f'inspect_{i}', f'collect_{i}')]
        latest = next(name for name in reversed(candidates) if outcomes.get(name, {}).get('result') == 'success')
        ci_main('fetch-artifact', latest, Path('input'))
    state = read('input/state.json')
    require(state['policy_sha'] == os.environ['GITHUB_WORKFLOW_SHA'] and state['config_digest'] == digest(cfg), 'trusted policy/config mismatch')
    if operation == 'tests':
        result = run_tests(state, cfg, Path('input/workspace/source'))
        write('test-result.json', result)
        return result
    if operation == 'inspect':
        tests = read('test-output/test-result.json') if Path('test-output/test-result.json').is_file() and os.environ.get('TEST_OUTCOME') == 'success' else None
        state = inspect_state(state, cfg, tests, api)
        save_bundle(state, cfg, repo, token, Path('input/workspace'))
        return {'status': state['status']}
    if operation == 'prepare-worker':
        effective = copy.deepcopy(cfg)
        workspace = Path('input/workspace').resolve()
        if cfg['mode'] == 'api':
            workspace = Path('/home/runner/review-input')
            require(not workspace.exists(), 'worker input destination already exists')
            shutil.copytree('input/workspace', workspace)
            home = Path('/home/runner/review-home')
            home.mkdir(mode=0o700)
            source = repo / '.review/runtime/api'
            # These are operator-verified, non-secret files from protected policy, never worker output.
            shutil.copyfile(source/'config.toml', home/'config.toml')
            shutil.copyfile(source/'isolation.json', home/'isolation.json')
            effective['isolation'].update(codex_home=str(home), report_path=str(home/'isolation.json'))
        request = build_request(state['next_role'], state, workspace, effective)
        Path('request').mkdir(exist_ok=True)
        Path('request/prompt.md').write_text(request['prompt'])
        write('request/config.json', effective)
        write('request/context.json', {'workspace': str(workspace), 'timeout_s': request['timeout_s']})
        with open(os.environ['GITHUB_OUTPUT'], 'a') as handle:
            # Round DOWN: Action's minute-granularity timeout must not exceed shared deadline.
            minutes = int(request['timeout_s']//60)
            require(minutes >= 1, 'less than one minute of execution budget remains')
            handle.write(f'timeout_minutes={minutes}\n')
            for field in ('model', 'effort', 'codex_version'):
                require('\n' not in cfg[field] and '\r' not in cfg[field], 'invalid runtime setting')
                handle.write(f'{field}={cfg[field]}\n')
        return {'status': 'prepared'}
    if operation == 'worker':
        context = read('request/context.json'); effective = read('request/config.json')
        request = build_request(state['next_role'], state, Path(context['workspace']), effective)
        result = run_codex(request, Path(os.environ['CODEX_EXECUTABLE']), request['timeout_s'])
        write('model-result.json', result); return {'status': result['status']}
    if operation == 'ssh-worker':
        from .ssh_worker import run_remote, connection_from_environment
        result = run_remote(state, cfg, Path('input/workspace'), connection_from_environment())
        write('model-result.json', result); return {'status': result['status']}
    if operation == 'normalize-worker':
        raw = Path('raw-result.json').read_text() if Path('raw-result.json').is_file() else ''
        result = normalize_action(raw, os.environ['ACTION_OUTCOME'])
        write('model-result.json', result); return {'status': result['status']}
    if operation == 'collect':
        result = read('worker-output/model-result.json') if Path('worker-output/model-result.json').is_file() else None
        if not state['terminal'] and state['next_role'] == 'fix':
            fetch(repo, state, token)
        state = collect_state(state, cfg, {'self_hosted': os.environ['SELF_HOSTED_OUTCOME'], 'api': os.environ['API_OUTCOME']}, result, api, repo)
        save_bundle(state, cfg, repo, token, Path('input/workspace'))
        return {'status': state['status']}
    require(operation == 'finish', 'unknown CI operation')
    if not state['terminal']:
        state = stop(state, 'incomplete', 'workflow stopped before terminal state')
    result = publish_result(state, cfg, api, publisher)
    Path('out').mkdir(exist_ok=True); write('out/run.json', state); write('out/publication.json', result)
    return result
