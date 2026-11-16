"""Operator-facing case and evaluation commands; no worker has the operator key."""

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import secrets
import stat
import sys

from .cases import OperatorDecision, checked_case, confirm_case, materialize_case, propose_case
from .contracts import digest, require
from .evaluate import JudgedTrial, build_eval_manifest, compare_runs, open_trial, seal_trial
from .eval_runtime import prepare_trial, run_trial, describe_tools


def register(sub):
    case = sub.add_parser('case', help='propose or explicitly confirm evaluation cases').add_subparsers(dest='operation', required=True)
    propose = case.add_parser('propose')
    for name in ('run','snapshot','output'): propose.add_argument('--'+name,type=Path,required=True)
    confirm = case.add_parser('confirm')
    for name in ('candidate','answers','output'): confirm.add_argument('--'+name,type=Path,required=True)
    confirm.add_argument('--reason',required=True)
    confirm.add_argument('--critical',action='store_true')
    confirm.add_argument('--split',choices=['holdout','tuning'],default='holdout')
    materialize = case.add_parser('materialize')
    for name in ('case','output'): materialize.add_argument('--'+name,type=Path,required=True)
    evaluation = sub.add_parser('eval',help='freeze, execute, judge and compare trials').add_subparsers(dest='operation',required=True)
    conditions = evaluation.add_parser('conditions')
    conditions.add_argument('--profile',type=Path,required=True)
    conditions.add_argument('--output',type=Path,required=True)
    prepare = evaluation.add_parser('prepare')
    prepare.add_argument('--cases',type=Path,nargs='+',required=True)
    prepare.add_argument('--configurations',type=Path,nargs=2,required=True)
    for name in ('rubric','output'): prepare.add_argument('--'+name,type=Path,required=True)
    run = evaluation.add_parser('run')
    for name in ('manifest','case','workspace','executable','output'): run.add_argument('--'+name,type=Path,required=True)
    run.add_argument('--configuration',required=True)
    run.add_argument('--trial',type=int,required=True)
    judge = evaluation.add_parser('judge')
    for name in ('record','judgment','output'): judge.add_argument('--'+name,type=Path,required=True)
    compare = evaluation.add_parser('compare')
    for name in ('manifest','rubric','output'): compare.add_argument('--'+name,type=Path,required=True)
    for name in ('baseline','candidate'): compare.add_argument('--'+name,type=Path,nargs='+',required=True)
    for parser in (judge,compare):
        parser.add_argument('--operator-key',type=Path,default=Path.home()/'.config/review-guide/operator.key')


def load(path):
    return json.loads(path.read_text())


def save(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def confirm_operator(identity, description):
    require(sys.stdin.isatty() and os.environ.get('GITHUB_ACTIONS')!='true' and not os.environ.get('REVIEW_WORKER'),
            'interactive confirmation in a separate operator environment is required')
    print(description, file=sys.stderr)
    require(input(f'Type the complete digest to confirm {identity}: ').strip()==identity, 'confirmation cancelled')


def operator_key(path: Path, create=False):
    require(not path.is_symlink(), 'operator key cannot be a symlink')
    if create and not path.exists():
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd,'wb') as handle: handle.write(secrets.token_bytes(32))
    require(stat.S_IMODE(path.stat().st_mode)==0o600 and path.stat().st_uid==os.getuid(), 'operator key requires owned mode 0600')
    key = path.read_bytes()
    require(len(key)==32, 'invalid operator key')
    return key


def execute(args):
    if args.command=='case':
        if args.operation=='propose': return propose_case(load(args.run), args.snapshot, args.output)
        if args.operation=='materialize': return materialize_case(args.case,args.output)
        candidate = checked_case(args.candidate)
        answers = load(args.answers)
        confirm_operator(candidate['input_digest'], json.dumps({'case':candidate['id'],'answers':answers,'reason':args.reason},ensure_ascii=False,indent=2))
        decision = OperatorDecision(getpass.getuser(),datetime.now(timezone.utc).isoformat(),candidate['input_digest'],
                                    args.reason, answers, args.critical,args.split)
        return confirm_case(args.candidate,decision,args.output)
    if args.operation=='conditions':
        result = {'tools_digest':describe_tools(args.profile)}
    elif args.operation=='prepare':
        cases = [checked_case(path) for path in args.cases]
        configs = [load(path) for path in args.configurations]
        rules_digest = digest({case['id']:{k:v for k,v in case['input_files'].items() if k.startswith('policy/')} for case in cases})
        for config in configs:
            require(config.get('rules_digest',rules_digest)==rules_digest,'configured rules do not match case inputs')
            config['rules_digest']=rules_digest
        result = build_eval_manifest(cases,configs,load(args.rubric))
    elif args.operation=='run':
        bundle = prepare_trial(load(args.manifest),args.case,args.configuration,args.trial,args.workspace)
        result = run_trial(bundle,args.workspace,args.executable)
    elif args.operation=='judge':
        record, judgment = load(args.record),load(args.judgment)
        confirm_operator(digest(record), json.dumps({'record':record,'judgment':judgment},ensure_ascii=False,indent=2))
        judgment.update(actor=getpass.getuser(),at=datetime.now(timezone.utc).isoformat())
        result = seal_trial(JudgedTrial(record,judgment),operator_key(args.operator_key,create=True))
    else:
        key = operator_key(args.operator_key)
        result = compare_runs(load(args.manifest),[open_trial(load(p),key) for p in args.baseline],
                              [open_trial(load(p),key) for p in args.candidate],load(args.rubric))
    save(args.output,result)
    return result
