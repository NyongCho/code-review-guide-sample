"""Prepare a single fixed-prompt API smoke call under the verified profile."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.argv[1] == 'check':
        assert json.loads((ROOT/'smoke-result.json').read_text()) == {'ok': True}
        print('Fixed-prompt API response verified; inspect CLI token usage before further calls.')
        return
    config = json.loads((ROOT/'.review/config.json').read_text())
    assert config['mode'] == 'api' and config['model'] == 'gpt-6-luna' and config['effort'] == 'low'
    profile = ROOT/'.review/runtime/api/config.toml'
    report = json.loads((ROOT/'.review/runtime/api/isolation.json').read_text())
    assert report['status'] == 'verified' and report['mode'] == 'api'
    assert report['codex_version'] == config['codex_version'] == '0.169.0'
    assert report['policy_digest'] == hashlib.sha256(profile.read_bytes()).hexdigest()
    assert report['checks'] and all(report['checks'].values())
    settings = tomllib.loads(profile.read_text())
    native = [Path(name) for name in settings['permissions']['review']['filesystem'] if name.endswith('/bin/codex')]
    assert len(native) == 1
    assert hashlib.sha256(native[0].read_bytes()).hexdigest() == report['native_sha256']
    assert subprocess.check_output([str(native[0]), '--version'], text=True).strip() == 'codex-cli 0.169.0'
    home = Path('/home/runner/review-home')
    workspace = Path('/home/runner/review-input')
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    shutil.copyfile(profile, home/'config.toml')
    (workspace/'smoke.schema.json').write_text(json.dumps({
        'type':'object', 'properties':{'ok':{'type':'boolean'}},
        'required':['ok'], 'additionalProperties':False,
    })+'\n')
    print('Pinned native binary and exact profile match the verified isolation evidence.')


if __name__ == '__main__':
    main()
