"""GitHub authority and publication boundary. PR content never executes here."""

import hashlib
import io
import json
import re
import stat
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .contracts import Json, digest, require, relative_path, validate_config
from .lifecycle import required_checks
from .policy import VerifiedApproval, classify_risk


class GitHub:
    def __init__(self, token: str, transport=None):
        self.token, self.transport = token, transport

    def call(self, method: str, path: str, data=None):
        require(path.startswith('/repos/') and not any(c in path for c in ('\r', '\n', '#')), 'invalid API route')
        if self.transport:
            return self.transport(method, path, data)
        request = Request('https://api.github.com' + path,
                          data=json.dumps(data).encode() if data is not None else None,
                          method=method, headers={'Authorization': 'Bearer ' + self.token,
                          'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                          'Content-Type': 'application/json'})
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read(10_000_001)
                require(len(raw) <= 10_000_000, 'GitHub response exceeds limit')
                return json.loads(raw)
        except HTTPError as error:
            raise OSError(f'GitHub {method} failed with HTTP {error.code}') from None

    def collection(self, path: str, key=None):
        items = []
        for page in range(1, 101):
            value = self.call('GET', path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
            batch = value[key] if key else value
            items.extend(batch)
            if len(batch) < 100:
                return items
        raise ValueError('GitHub pagination limit reached')


def route(repo: str) -> str:
    require(bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)), 'invalid repository')
    return '/repos/' + repo


def get_pr(repo: str, number: int, token: str = '', api: GitHub | None = None) -> Json:
    require(type(number) is int and number > 0, 'invalid PR number')
    return (api or GitHub(token)).call('GET', f'{route(repo)}/pulls/{number}')


def input_digest(pr: Json) -> str:
    return digest({'base': pr['base']['sha'], 'head': pr['head']['sha'],
                   'base_repo': pr['base']['repo']['full_name'],
                   'head_repo': pr['head']['repo']['full_name']})


def run_key(run: Json) -> str:
    return digest({key: run[key] for key in ('repository', 'pr', 'base_sha', 'head_sha', 'input_digest',
                                           'policy_sha', 'config_digest', 'round', 'role')})


def verify_entry(pr: Json, config: Json, trusted_ref: str) -> None:
    cfg = validate_config(config)
    require(trusted_ref == cfg['trusted_ref'], 'entry must run on protected trusted ref')
    require(pr['state'] == 'open', 'PR is not open')
    require(cfg['mode'] == 'api' or pr['base']['repo']['private'] is True,
            'subscription model execution requires a private target')
    require(pr['base']['repo']['full_name'] == pr['head']['repo']['full_name'] == cfg['repository'], 'fork or repository mismatch')
    require('refs/heads/' + pr['base']['ref'] == cfg['trusted_ref'], 'unexpected base branch')
    require(pr['user']['type'] == 'User' and pr['user']['login'] in cfg['allowed_actors'], 'author not allowed')


def verify_current(run: Json, pr: Json) -> Json:
    if pr['head']['sha'] != run['head_sha']:
        return {'status': 'incomplete', 'reason': 'stale_head'}
    if pr['state'] != 'open' or pr['base']['sha'] != run['base_sha'] or input_digest(pr) != run['input_digest']:
        return {'status': 'incomplete', 'reason': 'stale_input'}
    return {'status': 'verified'}


def resolve_approval(reference: Json, expected: Json, api: GitHub) -> VerifiedApproval:
    """Only trusted callers supply reference; binding is encoded in the protected job name."""
    root = route(reference['repository'])
    run_id = reference['run_id']
    require(type(run_id) is int and run_id > 0, 'approval run id required')
    run = api.call('GET', f'{root}/actions/runs/{run_id}')
    require(run['event'] == 'workflow_dispatch' and run['conclusion'] == 'success'
            and run['path'] == '.github/workflows/review-approve.yml'
            and run['head_sha'] == reference['policy_sha']
            and run['head_branch'] == reference['trusted_branch'], 'untrusted approval origin')
    for actor in (run['actor'], run['triggering_actor']):
        require(actor['type'] == 'User', 'approval must originate from a human')
        permission = api.call('GET', root + '/collaborators/' + quote(actor['login'], safe='') + '/permission')
        require(permission['permission'] in {'admin', 'maintain', 'write'}, 'approver no longer has write permission')
    jobs = api.collection(f'{root}/actions/runs/{run_id}/jobs', 'jobs')
    require(any(job['name'] == 'approve-' + digest(expected) and job['conclusion'] == 'success' for job in jobs),
            'approval binding does not match request')
    return VerifiedApproval(expected, run['triggering_actor']['login'], f'https://github.com/{reference["repository"]}/actions/runs/{run_id}')


def verify_merge_gate(config: Json, publisher: GitHub) -> None:
    app_id = config.get('check_publisher_app_id')
    require(type(app_id) is int and app_id > 0 and app_id != 15368, 'dedicated check publisher App required')
    branch = validate_config(config)['trusted_ref'].removeprefix('refs/heads/')
    protection = publisher.call('GET', route(config['repository'])+'/branches/'+quote(branch,safe='')+'/protection')
    checks = protection.get('required_status_checks') or {}
    require(checks.get('strict') is True and protection.get('enforce_admins',{}).get('enabled') is True,
            'strict up-to-date branch protection including administrators required')
    required = {'review-guide/ci','review-guide/human'}
    if config.get('review_mode') == 'block':required.add('review-guide/ai')
    bound = {c.get('context') for c in checks.get('checks',[]) if c.get('app_id') == app_id}
    require(required.issubset(bound), 'required checks must be bound to the dedicated publisher App')


def _write_checks(run: Json, config: Json, publisher: GitHub, checks: Json, summary: str,
                  pending=False, existing_only=False) -> None:
    app_id = config.get('check_publisher_app_id')
    require(type(app_id) is int and app_id > 0 and app_id != 15368, 'dedicated check publisher App required')
    root, key = route(run['repository']), run_key(run)
    runs = publisher.collection(f'{root}/commits/{run["head_sha"]}/check-runs', 'check_runs')
    for name in ('ai','ci','human'):
        external = key + ':' + run.get('execution_id','local') + ':' + name
        existing = next((c for c in runs if c.get('external_id') == external and c.get('app',{}).get('id') == app_id),None)
        if existing_only and existing is None:continue
        data = {'name':'review-guide/'+name,'head_sha':run['head_sha'],
                'status':'in_progress' if pending else 'completed', 'external_id':external,
                'output':{'title':'Review pending' if pending else run['status'],'summary':summary}}
        if not pending:
            data['conclusion'] = checks[name]
        written = publisher.call('PATCH' if existing else 'POST',
                  f'{root}/check-runs/{existing["id"]}' if existing else f'{root}/check-runs',data)
        require(written.get('app',{}).get('id') == app_id, 'check was not written by the configured publisher App')


def begin_checks(run: Json, config: Json, publisher: GitHub) -> None:
    _write_checks(run,config,publisher,{},'Trusted review is running for this commit.',pending=True)


def publish_result(run: Json, config: Json, api: GitHub, publisher: GitHub) -> Json:
    current = get_pr(run['repository'], run['pr'], api=api)
    freshness = verify_current(run, current)
    if freshness['status'] != 'verified':
        if current['head']['sha'] == run['head_sha']:
            _write_checks(run,config,publisher,{name:'cancelled' for name in ('ai','ci','human')},
                          'Superseded input: '+freshness['reason'],existing_only=True)
        return freshness
    key, root = run_key(run), route(run['repository'])
    run = dict(run)
    run['trusted_branch'] = validate_config(config)['trusted_ref'].removeprefix('refs/heads/')
    binding = {key: run[key] for key in ('repository', 'base_sha', 'head_sha', 'input_digest', 'policy_sha')}
    human_binding = binding | {'kind': 'human-review'}
    risk = classify_risk(run.get('changed_paths', []), run.get('risk'), config)
    human_ok = not risk['human_required'] or find_approval(run, human_binding, api) is not None
    # Never inherit authority flags from the serialized worker/controller state.
    run['blocking_authorized'] = False
    if config.get('review_mode') == 'block':
        run['blocking_authorized'] = find_approval(run, {'kind': 'blocking-policy', 'policy_sha': run['policy_sha'],
                                                       'config_digest': run['config_digest'], 'rules': run['rules']}, api) is not None
    checks = required_checks(run, config)
    checks['human'] = 'success' if human_ok else 'failure'
    marker = '<!-- review-guide:' + key + ' -->'
    # Finding text is data, never commands or mentions; JSON code fence stops Markdown injection.
    summary = json.dumps({'status': run['status'], 'reason': run.get('reason'), 'head': run['head_sha'],
                          'ci': checks['ci'], 'findings': run['findings'], 'human': checks['human'],
                          'human_binding': human_binding if not human_ok else None}, ensure_ascii=False, indent=2)
    summary = summary.replace('`', '\\u0060').replace('@', '\\u0040')[:50000]
    body = marker + '\nAI review\n\n```json\n' + summary + '\n```'
    comments = api.collection(f'{root}/issues/{run["pr"]}/comments')
    existing = next((c for c in comments if c['body'].startswith(marker)
                     and c.get('user', {}).get('login') == 'github-actions[bot]'), None)
    if existing:
        api.call('PATCH', f'{root}/issues/comments/{existing["id"]}', {'body': body})
    else:
        api.call('POST', f'{root}/issues/{run["pr"]}/comments', {'body': body})
    _write_checks(run,config,publisher,checks,summary)
    return {'status': 'published', 'key': key, 'checks': checks}


def find_approval(run: Json, binding: Json, api: GitHub) -> VerifiedApproval | None:
    from .contracts import ValidationError
    path = route(run['repository']) + '/actions/workflows/review-approve.yml/runs?event=workflow_dispatch&status=success'
    for candidate in api.collection(path, 'workflow_runs'):
        if candidate['head_sha'] != run['policy_sha']:
            continue
        try:
            return resolve_approval({'repository': run['repository'], 'run_id': candidate['id'],
                                     'policy_sha': run['policy_sha'], 'trusted_branch': run['trusted_branch']}, binding, api)
        except ValidationError:
            continue
    return None


def verify_archive(payload: bytes, metadata: Json, expected: Json, dest: Path) -> None:
    require(not metadata.get('expired') and metadata['name'] == expected['name']
            and metadata['workflow_run']['id'] == expected['run_id']
            and metadata['workflow_run']['head_sha'] == expected['head_sha'], 'artifact provenance mismatch')
    require(metadata['digest'] == 'sha256:' + hashlib.sha256(payload).hexdigest(), 'artifact digest mismatch')
    require(not dest.exists(), 'artifact destination must be new')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        total, names = 0, set()
        for member in archive.infolist():
            name = relative_path(member.filename)
            require(name not in names and not member.is_dir(), 'duplicate/directory artifact entry')
            require(not stat.S_ISLNK(member.external_attr >> 16), 'artifact symlink forbidden')
            names.add(name); total += member.file_size
            require(total <= 100_000_000, 'artifact expands beyond limit')
        dest.mkdir(parents=True)
        for member in archive.infolist():
            path = dest / member.filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.read(member))


def publish_patch(run: Json, patch: str, config: Json, repo: Path, api: GitHub) -> Json:
    """Build a tree without executing PR files; non-force ref update cannot replace a divergent head."""
    import base64
    import os
    import subprocess
    import tempfile
    from .policy import check_patch
    if datetime.now(timezone.utc) >= datetime.fromisoformat(run['deadline_at'].replace('Z', '+00:00')):
        return {'status': 'incomplete', 'reason': 'deadline expired'}
    decision = check_patch(patch, run, config, None)
    if decision['status'] != 'verified':
        return decision
    root = route(run['repository'])
    marker = 'review-guide patch ' + digest({'run': run_key(run), 'patch': patch})
    intent = run.get('intent', {}).get('head_commit_message')
    if intent:
        marker += '\n\nOriginal change intent:\n' + intent
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'GIT_CONFIG_NOSYSTEM': '1', 'HOME': '/nonexistent'}
    with tempfile.TemporaryDirectory(prefix='review-patch-') as tmp:
        work = Path(tmp)/'tree'
        subprocess.run(['git', 'init', '--quiet', str(work)],
                       env=env, check=True, capture_output=True)
        def git(*args, input=None):
            return subprocess.run(['git', '-C', str(work), '-c', 'core.hooksPath=/dev/null', *args],
                                  input=input, env=env, capture_output=True, check=True).stdout
        # A shallow runner may have this object only in FETCH_HEAD, outside all branches.
        git('fetch', '--no-tags', '--depth=1', repo.resolve().as_uri(), run['head_sha'])
        git('read-tree', run['head_sha'])
        git('apply', '--cached', '--whitespace=error', '-', input=patch.encode())
        expected_tree = git('write-tree').decode().strip()
        entries = []
        for name in decision['paths']:
            # Deletion has no index entry; binary and mode changes were rejected by policy.
            listing = git('ls-files', '-s', '--', name)
            if not listing:
                entries.append({'path': name, 'mode': '100644', 'type': 'blob', 'sha': None})
                continue
            mode, blob, _ = listing.split(b'\t', 1)[0].split()
            content = git('cat-file', 'blob', blob.decode())
            entries.append({'path': name, 'mode': mode.decode(), 'type': 'blob', 'sha': blob.decode(), 'content_bytes': content})
    current = get_pr(run['repository'], run['pr'], api=api)

    def recovered(pr):
        if pr['head']['sha'] == run['head_sha']:
            return None
        commit = api.call('GET', root + '/git/commits/' + pr['head']['sha'])
        parents = [p['sha'] if isinstance(p, dict) else p for p in commit.get('parents', [])]
        # The message/author are forgeable. Require the exact locally computed patch tree and parent,
        # and unchanged title/body/base via the original input digest.
        tree = commit.get('tree', {})
        tree_sha = tree.get('sha') if isinstance(tree, dict) else tree
        original = dict(pr, head=dict(pr['head'], sha=run['head_sha']))
        if (commit.get('message') == marker and parents == [run['head_sha']] and tree_sha == expected_tree
                and commit.get('author', {}).get('email') == 'review-guide@users.noreply.github.com'
                and verify_current(run, original)['status'] == 'verified'):
            return {'status': 'verified', 'head_sha': pr['head']['sha'], 'input_digest': input_digest(pr)}
        return None

    recovery = recovered(current)
    if recovery:
        return recovery
    fresh = verify_current(run, current)
    if fresh['status'] != 'verified':
        return fresh
    for entry in entries:
        if 'content_bytes' in entry:
            blob = api.call('POST', root + '/git/blobs', {'encoding': 'base64', 'content': base64.b64encode(entry.pop('content_bytes')).decode()})
            require(blob['sha'] == entry['sha'], 'uploaded blob identity mismatch')
    parent = api.call('GET', root + '/git/commits/' + run['head_sha'])
    tree = api.call('POST', root + '/git/trees', {'base_tree': parent['tree']['sha'], 'tree': entries})
    require(tree['sha'] == expected_tree, 'published tree differs from validated patch')
    identity = {'name': 'review-guide', 'email': 'review-guide@users.noreply.github.com', 'date': run['created_at']}
    commit = api.call('POST', root + '/git/commits', {'message': marker, 'tree': tree['sha'],
                      'parents': [run['head_sha']], 'author': identity, 'committer': identity})
    current = get_pr(run['repository'], run['pr'], api=api)
    fresh = verify_current(run, current)
    if fresh['status'] != 'verified':
        return fresh
    if datetime.now(timezone.utc) >= datetime.fromisoformat(run['deadline_at'].replace('Z', '+00:00')):
        return {'status': 'incomplete', 'reason': 'deadline expired'}
    try:
        api.call('PATCH', root + '/git/refs/heads/' + quote(current['head']['ref'], safe='/'),
                 {'sha': commit['sha'], 'force': False})
    except OSError:
        # The write may have reached GitHub. Reconcile it without sending another write.
        pass
    return observe_published_head(run, commit['sha'], api)


def observe_published_head(run: Json, published_sha: str, api: GitHub) -> Json:
    deadline = datetime.fromisoformat(run['deadline_at'].replace('Z', '+00:00'))
    for delay in (0, 1, 2, 4):
        if (deadline - datetime.now(timezone.utc)).total_seconds() <= delay:
            return {'status': 'incomplete', 'reason': 'deadline expired'}
        if delay:
            time.sleep(delay)
        pr = get_pr(run['repository'], run['pr'], api=api)
        head = pr['head']['sha']
        if head not in (run['head_sha'], published_sha):
            return {'status': 'incomplete', 'reason': 'stale_head'}
        # Check the original input binding while allowing only our own head transition.
        original = dict(pr, head=dict(pr['head'], sha=run['head_sha']))
        current = verify_current(run, original)
        if current['status'] != 'verified':
            return current
        if head == published_sha:
            return {'status': 'verified', 'head_sha': head, 'input_digest': input_digest(pr)}
        # The pull request can still show the old ref just after GitHub accepts the push.
    return {'status': 'incomplete', 'reason': 'published head not observed before retry limit'}


def download_artifact(repo: str, expected: Json, dest: Path, api: GitHub) -> None:
    from urllib.request import HTTPRedirectHandler, build_opener
    from urllib.parse import urlparse
    metadata = api.collection(f'{route(repo)}/actions/runs/{expected["run_id"]}/artifacts', 'artifacts')
    matches = [a for a in metadata if a['name'] == expected['name']]
    require(len(matches) == 1, 'artifact missing or ambiguous')
    meta = matches[0]
    # Authenticated request stops at the API redirect. The signed storage URL receives NO token.
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    request = Request(f'https://api.github.com{route(repo)}/actions/artifacts/{int(meta["id"])}/zip',
                      headers={'Authorization': 'Bearer ' + api.token, 'Accept': 'application/vnd.github+json'})
    try:
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            payload = response.read(100_000_001)
    except HTTPError as error:
        require(error.code == 302, 'artifact download rejected')
        location = error.headers['Location']
        parsed = urlparse(location)
        require(parsed.scheme == 'https' and bool(parsed.hostname) and not parsed.username, 'unsafe artifact redirect')
        with urlopen(location, timeout=30) as response:
            payload = response.read(100_000_001)
    require(len(payload) <= 100_000_000, 'artifact compressed size exceeds limit')
    verify_archive(payload, meta, expected, dest)
