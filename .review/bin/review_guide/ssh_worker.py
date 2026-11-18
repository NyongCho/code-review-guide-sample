"""Restricted SSH transport for subscription workers; no GitHub token reaches the server."""

import copy
from datetime import datetime, timezone
import fcntl
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import zipfile

from .codex import _failure, build_request, run_codex
from .contracts import Json, ValidationError, require, relative_path, validate_config, validate_output, validate_run

MAX_ARCHIVE = 100_000_000


def pack_request(run: Json, config: Json, workspace: Path) -> bytes:
    validate_run(run); validate_config(config)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('request.json', json.dumps({'run':run,'config':config}, ensure_ascii=False))
        for path in sorted(workspace.rglob('*')):
            require(not path.is_symlink(), 'worker input symlink forbidden')
            if path.is_file():
                archive.write(path, 'workspace/' + relative_path(path.relative_to(workspace).as_posix()))
                require(stream.tell() <= MAX_ARCHIVE, 'worker request too large')
    return stream.getvalue()


def _unpack(payload: bytes, destination: Path) -> Json:
    require(len(payload) <= MAX_ARCHIVE, 'worker request too large')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names, total = set(), 0
        for item in archive.infolist():
            name = relative_path(item.filename)
            require(name == 'request.json' or name.startswith('workspace/'), 'unexpected worker input')
            require(name not in names and not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16),
                    'duplicate/directory/symlink worker input')
            total += item.file_size
            require(total <= MAX_ARCHIVE and item.file_size <= 5_000_000, 'worker input expands beyond limit')
            names.add(name)
        require('request.json' in names, 'worker request metadata missing')
        metadata = json.loads(archive.read('request.json'))
        for item in archive.infolist():
            path = destination / item.filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.read(item))
    return metadata


def serve_request(payload: bytes, server: Json, execute=run_codex) -> Json:
    try:
        return _serve_request(payload, server, execute)
    except (zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise ValidationError('invalid worker request archive') from exc


def _serve_request(payload: bytes, server: Json, execute) -> Json:
    require(server.get('schema_version') == 1, 'invalid server configuration')
    require(len(payload) <= MAX_ARCHIVE, 'worker request too large')
    root = Path(server['work_root'])
    require(root.is_absolute() and not root.is_symlink(), 'dedicated work root required')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Read the bounded metadata before waiting; queue time consumes the same run deadline.
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        require('request.json' in archive.namelist(), 'worker request metadata missing')
        item = archive.getinfo('request.json')
        require(item.file_size <= 2_000_000, 'oversized request metadata')
        envelope = json.loads(archive.read(item))
    run, cfg = validate_run(envelope['run']), validate_config(envelope['config'])
    require(run['model'] == cfg['model'] and run.get('effort', cfg['effort']) == cfg['effort'], 'request model identity mismatch')
    require(cfg['mode'] == run['mode'] == 'self_hosted' and run['auth_kind'] == 'chatgpt', 'SSH worker only accepts subscription requests')
    require(cfg['repository'] in server['allowed_repositories'], 'repository is not allowed on this worker')
    require(run['repository'] == cfg['repository'] or run.get('kind') == 'evaluation' and run['repository'] == 'evaluation/input',
            'request repository mismatch')
    require(cfg['model'] in server['allowed_models'] and cfg['effort'] in server['allowed_efforts'], 'model/effort is not allowed')
    require(cfg['codex_version'] == server['codex_version'] == run['codex_version'], 'pinned worker version mismatch')
    deadline = datetime.fromisoformat(run['deadline_at'].replace('Z','+00:00'))
    require(deadline > datetime.now(timezone.utc), 'run deadline expired')
    with (root/'worker.lock').open('a') as lock:
        while True:
            require(deadline > datetime.now(timezone.utc), 'run deadline expired while queued')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(0.1)
        active = root/'active-input'
        require(not active.exists() and not active.is_symlink(), 'stale worker input requires operator cleanup')
        active.mkdir(mode=0o700)
        try:
            _unpack(payload, active)
            effective = copy.deepcopy(cfg)
            # Caller-provided authority paths are ignored. These are server-owned configuration.
            effective['isolation'] = {'status':'verified', 'codex_home':server['codex_home'], 'report_path':server['report_path']}
            effective['model_timeout_s'] = min(cfg['model_timeout_s'], server['max_timeout_s'])
            request = build_request(run['role'], run, active/'workspace', effective)
            if run.get('kind') == 'evaluation':
                from .eval_runtime import describe_tools
                require(cfg['tools_digest'] == describe_tools(Path(server['codex_home'])/'config.toml'), 'evaluation tool policy mismatch')
            result = execute(request, Path(server['codex_executable']), request['timeout_s'])
            return result | {'request_evidence': {'prompt_digest':request['prompt_digest'],
                                                 'isolation_report_digest':request['gate']['report_digest'],
                                                 'codex_version':request['codex_version']}}
        finally:
            shutil.rmtree(active)


def run_remote(run: Json, config: Json, workspace: Path, connection: Json, executable='ssh') -> Json:
    cfg = validate_config(config)
    require(cfg['mode'] == 'self_hosted', 'SSH cannot be an API fallback')
    for field in ('host','user'):
        require(isinstance(connection.get(field), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',connection[field]), 'invalid SSH '+field)
    port = connection.get('port', '22') or '22'
    require(str(port).isdigit() and 0 < int(port) < 65536, 'invalid SSH port')
    require(bool(connection.get('private_key')) and bool(connection.get('known_hosts')), 'SSH credential/host identity missing')
    remaining = (datetime.fromisoformat(run['deadline_at'].replace('Z','+00:00'))-datetime.now(timezone.utc)).total_seconds()
    require(remaining > 0, 'run deadline expired')
    payload = pack_request(run, cfg, workspace)
    with tempfile.TemporaryDirectory(prefix='review-ssh-') as tmp:
        root = Path(tmp); key = root/'key'; known = root/'known_hosts'
        key.write_text(connection['private_key'].rstrip()+'\n'); key.chmod(0o600)
        known.write_text(connection['known_hosts'].rstrip()+'\n'); known.chmod(0o600)
        argv = [executable, '-F', '/dev/null', '-T', '-i', str(key), '-p', str(port), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(known),
                '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                connection['user']+'@'+connection['host']]
        env = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}
        # Never stream model output or SSH diagnostics into Actions logs.
        timeout = min(remaining, cfg['model_timeout_s']+120)
        with tempfile.TemporaryFile() as incoming, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            incoming.write(payload); incoming.seek(0)
            try:
                process = subprocess.Popen(argv, stdin=incoming, stdout=stdout, stderr=stderr,
                                           env=env, start_new_session=True)
            except OSError:
                return _failure('failed','SSH worker could not start')
            started = time.monotonic()
            try:
                while True:
                    if os.fstat(stdout.fileno()).st_size+os.fstat(stderr.fileno()).st_size > 2_000_000:
                        return _failure('failed','SSH output exceeds limit')
                    if time.monotonic()-started >= timeout:
                        return _failure('incomplete','SSH worker timed out')
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                if process.returncode:
                    return _failure('failed','SSH worker rejected request or connection failed')
                stdout.seek(0); raw = stdout.read(2_000_001)
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
        try:
            value = json.loads(raw)
            normalized = validate_output({k:v for k,v in value.items() if k in {'status','findings','summary','risk','patch','edits','dispositions'}},run['role'])
            return normalized | {k:value[k] for k in ('usage','elapsed_s','request_evidence') if k in value}
        except (ValueError,TypeError,AttributeError):
            return _failure('failed','invalid SSH worker output')


def connection_from_environment() -> Json:
    return {key:os.environ.get(name,'') for key,name in {'host':'REVIEW_SSH_HOST','user':'REVIEW_SSH_USER',
            'port':'REVIEW_SSH_PORT','known_hosts':'REVIEW_SSH_KNOWN_HOSTS','private_key':'REVIEW_SSH_KEY'}.items()}
