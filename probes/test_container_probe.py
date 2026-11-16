"""Exercise the installed test command with synthetic hostile test code."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.review/bin'))
from review_guide.pipeline import test_command
from review_guide.workflows import PYTHON_IMAGE


CANARY = r'''
import errno, json, os, socket
from pathlib import Path

checks = {}
checks['non_root'] = os.geteuid() == 65534
checks['secret_environment_absent'] = not any(k in os.environ for k in ('GH_TOKEN', 'GITHUB_TOKEN', 'OPENAI_API_KEY'))
for name, path in {
    'outside_file_denied': '__OUTSIDE__',
    'home_read_denied': '__HOME_FILE__',
    'docker_socket_absent': '/var/run/docker.sock',
}.items():
    try:
        Path(path).read_bytes()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        checks[name] = True
    else:
        checks[name] = False
try:
    Path('/project/write-canary').write_text('must be denied')
except OSError as e:
    checks['project_write_denied'] = e.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
else:
    checks['project_write_denied'] = False
try:
    with socket.create_connection(('1.1.1.1', 443), timeout=2):
        pass
except OSError as e:
    checks['network_denied'] = e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES)
else:
    checks['network_denied'] = False
try:
    os.setuid(0)
except PermissionError:
    checks['setuid_denied'] = True
else:
    checks['setuid_denied'] = False
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
checks['no_new_privileges'] = status['NoNewPrivs'].strip() == '1'
checks['capabilities_dropped'] = int(status['CapEff'].strip(), 16) == 0
checks['memory_bounded'] = Path('/sys/fs/cgroup/memory.max').read_text().strip() == '1073741824'
checks['processes_bounded'] = Path('/sys/fs/cgroup/pids.max').read_text().strip() == '128'
print(json.dumps(checks), flush=True)
assert all(checks.values()), checks
'''


def main():
    subprocess.run(['docker', 'pull', PYTHON_IMAGE], check=True, timeout=120)
    with tempfile.TemporaryDirectory(prefix='review-test-probe-') as tmp, \
            tempfile.TemporaryDirectory(prefix='review-host-home-', dir=Path.home()) as home_tmp:
        parent = Path(tmp)
        source = parent / 'project'
        source.mkdir(mode=0o755)
        outside = parent / 'host-only-canary'
        outside.write_text('synthetic-host-content')
        home_file = Path(home_tmp) / 'canary'
        home_file.write_text('synthetic-home-content')
        (source / 'canary.py').write_text(CANARY.replace('__OUTSIDE__', str(outside)).replace('__HOME_FILE__', str(home_file)))
        name = 'review-probe-' + uuid.uuid4().hex
        command = test_command(source, ['python3', 'canary.py'], name)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                env=os.environ | {'GH_TOKEN': 'synthetic-gh-canary', 'OPENAI_API_KEY': 'synthetic-api-canary'})
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            result.check_returncode()
            checks = json.loads(result.stdout)
            assert checks and all(value is True for value in checks.values()), checks
            evidence = ROOT / 'probe-evidence'
            evidence.mkdir(exist_ok=True)
            (evidence / 'test-container.json').write_text(json.dumps({
                'status': 'verified', 'image': PYTHON_IMAGE,
                'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'checks': checks,
            }, indent=2) + '\n')
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)


if __name__ == '__main__':
    main()
