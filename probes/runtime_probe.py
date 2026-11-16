"""Credential-free canaries for the pinned API Action on an ephemeral runner."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

HOME = Path('/home/runner/review-home')
INPUT = Path('/home/runner/review-input')
EXPECTED_NATIVE = 'b452ca20f838a8855a88a41050ee4a694033fff4ea3ecdad5633e6e0e8d13f2b'
STATE = Path('/home/runner/probe-state.json')

if sys.argv[1] == 'prepare':
    root = Path(subprocess.check_output(['npm','root','-g'], text=True).strip())
    matches = [p for p in root.rglob('codex') if p.is_file() and p.read_bytes()[:4] == b'\x7fELF']
    assert len(matches) == 1, [str(p) for p in matches]
    native = matches[0]
    assert hashlib.sha256(native.read_bytes()).hexdigest() == EXPECTED_NATIVE
    HOME.mkdir(mode=0o700); INPUT.mkdir(mode=0o700)
    (INPUT/'allowed.txt').write_text('synthetic input')
    (INPUT/'inert').mkdir()
    (INPUT/'inert/AGENTS.override.md').write_text('INERT_INSTRUCTION_CANARY_8271')
    (INPUT/'AGENTS.md').write_text('ACTIVE_INSTRUCTION_CANARY_8271')
    (Path('/home/runner')/'outside-canary').write_text('synthetic, not a secret')
    policy = 'default_permissions="review"\nweb_search="disabled"\nproject_doc_max_bytes=0\n'
    policy += '\n[permissions.review.filesystem]\n":minimal"="read"\n'
    policy += json.dumps(str(INPUT))+'="read"\n'+json.dumps(str(native))+'="read"\n'
    policy += '\n[permissions.review.network]\nenabled=false\n'
    (HOME/'config.toml').write_text(policy)
    STATE.write_text(json.dumps({'native':str(native),'original_policy':policy}))
else:
    state=json.loads(STATE.read_text()); native=state['native']
    env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','CODEX_HOME':str(HOME),'HOME':str(HOME)}
    assert subprocess.check_output([native,'--version'],env=env,text=True).strip()=='codex-cli 0.169.0'
    original=tomllib.loads(state['original_policy']); actual=tomllib.loads((HOME/'config.toml').read_text())
    for key in ('permissions','default_permissions','web_search','project_doc_max_bytes'):
        assert actual[key] == original[key], key
    secret_process=subprocess.Popen(['/bin/sleep','30'],env={'SYNTHETIC_SECRET':'outside-model-canary'})
    probe=r'''
import errno,json,os,socket
from pathlib import Path
result={}
assert Path('allowed.txt').read_text()=='synthetic input'
for name,path in [('outside','/home/runner/outside-canary'),('home','/home/runner/review-home/config.toml'),('docker','/var/run/docker.sock')]:
    try:Path(path).read_bytes()
    except (PermissionError,FileNotFoundError,IsADirectoryError):result[name+'_read_denied']=True
    else:raise AssertionError(name+' readable')
try:Path('write-forbidden').write_text('x')
except OSError as exc:
    assert exc.errno in (errno.EPERM,errno.EACCES,errno.EROFS),exc
    result['write_denied']=True
else:raise AssertionError('write succeeded')
s=None
try:
    s=socket.socket();s.settimeout(3);s.connect(('1.1.1.1',443))
except PermissionError:result['network_denied']=True
else:raise AssertionError('network not denied by permission')
finally:
    if s is not None:s.close()
try:os.setuid(0)
except OSError as exc:
    assert exc.errno in (errno.EPERM,errno.EINVAL),exc
    assert os.getuid()!=0
    result['setuid_denied']=True
else:raise AssertionError('setuid succeeded')
status=Path('/proc/self/status').read_text()
values={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status.splitlines() if ':' in line}
assert values['NoNewPrivs']=='1' and int(values['CapEff'],16)==0,values
result['privilege_escalation_denied']=True
assert not any(k in os.environ for k in ['OPENAI_API_KEY','CODEX_API_KEY','GH_TOKEN','GITHUB_TOKEN','PROXY_API_KEY'])
result['secret_environment_absent']=True
for name in ('environ','mem'):
    try:
        with open('/proc/OUTSIDE_PROCESS_PID/'+name,'rb') as handle:handle.read(1)
    except (PermissionError,FileNotFoundError,ProcessLookupError):result['process_'+name+'_denied']=True
    else:raise AssertionError('outside process '+name+' is readable')
print(json.dumps(result))
'''
    probe=probe.replace('OUTSIDE_PROCESS_PID',str(secret_process.pid))
    result=subprocess.run([native,'sandbox','-P','review','-C',str(INPUT),'--','/usr/bin/python3','-c',probe],env=env,capture_output=True,text=True,timeout=20)
    secret_process.terminate();secret_process.wait()
    if result.returncode:
        print(result.stderr[-5000:]);raise SystemExit(result.returncode)
    checks=json.loads(result.stdout)
    prompt=subprocess.run([native,'debug','prompt-input','Render a synthetic probe'],cwd=INPUT,env=env,capture_output=True,text=True,timeout=20)
    assert prompt.returncode==0,prompt.stderr
    json.loads(prompt.stdout)
    assert 'INSTRUCTION_CANARY_8271' not in prompt.stdout
    checks['instructions_inert']=True
    checks['secret_read_denied']=checks['outside_read_denied'] and checks['home_read_denied'] and checks['process_environ_denied'] and checks['process_mem_denied']
    report={'status':'verified','mode':'api','codex_version':'0.169.0','runner':'linux',
      'policy_digest':hashlib.sha256(state['original_policy'].encode()).hexdigest(),
      'post_action_policy_digest':hashlib.sha256((HOME/'config.toml').read_bytes()).hexdigest(),
      'checks':checks,'native_sha256':EXPECTED_NATIVE}
    Path('probe-evidence').mkdir(exist_ok=True)
    Path('probe-evidence/isolation.json').write_text(json.dumps(report,indent=2)+'\n')
    Path('probe-evidence/config.toml').write_text(state['original_policy'])
    Path('probe-evidence/instructions.txt').write_text('Active and inert project instruction canaries absent from rendered prompt.\n')
    print(json.dumps(report,indent=2))
