"""Project-owned case candidates and explicit operator confirmation.

The operator environment must be outside worker filesystem/credential access. A JSON
field claiming approval never grants authority; interactive CLI confirmation is local.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from .contracts import Json, digest, require, relative_path, validate_case, validate_run, validate_output
from .github import run_key


@dataclass(frozen=True)
class OperatorDecision:
    actor: str
    at: str
    input_digest: str
    reason: str
    answers: list
    critical: bool
    split: str


def inventory(root: Path) -> dict[str, str]:
    require(root.is_dir() and not root.is_symlink(), 'input directory missing or symlinked')
    result, total = {}, 0
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'input symlink forbidden')
        if path.is_file():
            name = relative_path(path.relative_to(root).as_posix())
            require('.git' not in Path(name).parts, 'Git history is not an evaluation input')
            size = path.stat().st_size; total += size
            require(size <= 5_000_000 and total <= 50_000_000, 'case input exceeds supported size')
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    require(bool(result), 'case input is empty')
    return result


def checked_case(path: Path) -> Json:
    case = validate_case(json.loads((path/'case.json').read_text()))
    files = inventory(path/'input')
    require(case.get('input_files') == files and case['input_digest'] == digest(files), 'case input identity mismatch')
    return case


def _save_case(case: Json, input_root: Path, dest: Path) -> Json:
    if dest.exists():
        require(checked_case(dest) == case, 'existing case has different content')
        return case
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix='.case-') as temp:
        draft = Path(temp)/'draft'; draft.mkdir()
        shutil.copytree(input_root, draft/'input')
        (draft/'case.json').write_text(json.dumps(case, ensure_ascii=False, indent=2) + '\n')
        draft.rename(dest)
    return case


def propose_case(run: Json, snapshot: Path, dest: Path) -> Json:
    run = validate_run(run)
    manifest = json.loads((snapshot/'input-manifest.json').read_text())
    require(manifest['base_sha'] == run['base_sha'] and manifest['head_sha'] == run['head_sha'], 'snapshot source mismatch')
    expected = dict(manifest['files']) | {'policy/' + name: value for name, value in manifest['rules'].items()}
    expected['change.diff'] = manifest['diff_digest']
    actual = inventory(snapshot)
    actual.pop('input-manifest.json', None)
    require(actual == expected, 'snapshot hashes or file inventory mismatch')
    with tempfile.TemporaryDirectory(prefix='review-case-') as tmp:
        clean = Path(tmp)/'input'; clean.mkdir()
        # Generated operational metadata is not evaluation source. Keep PR instruction changes
        # as inert data and the diff; protected rules/prompts/schema remain available.
        operational = {value for name, value in manifest['inert_files'].items()
                       if name.startswith(('.review/bin/', '.review/runtime/'))
                       or name in {'.review/config.json', '.review/manifest.json'}}
        for name in actual:
            if name in operational or name == 'policy/.review/config.json':
                continue
            target = clean/name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(snapshot/name, target)
        intent = run.get('intent', {})
        # Origin links live in the control record, never in the generated evaluation context.
        context = {key: re.sub(r'https?://\S+', '[external reference omitted]', str(intent.get(key, '')))
                   for key in ('title', 'body')}
        (clean/'context.json').write_text(json.dumps(context, ensure_ascii=False, indent=2) + '\n')
        clean_files = inventory(clean)
        clean_manifest = {'files': {k:v for k,v in actual.items() if k in clean_files},
                          'inert_files': {k:v for k,v in manifest['inert_files'].items() if v not in operational}}
        (clean/'input-manifest.json').write_text(json.dumps(clean_manifest, indent=2) + '\n')
        files = inventory(clean)
        case = {'schema_version': 1, 'id': 'case-' + digest({'run':run_key(run),'input':digest(files)})[:24],
                'status': 'candidate', 'critical': False, 'split': 'tuning', 'input_digest': digest(files),
                'input_files': files, 'source': {key: run[key] for key in ('repository','pr','base_sha','head_sha','input_digest')},
                'observations': {'findings': run['findings'], 'history': run.get('history', []), 'run_key': run_key(run)}}
        return _save_case(validate_case(case), clean, dest)


def confirm_case(candidate: Path, decision: OperatorDecision, dest: Path) -> Json:
    require(isinstance(decision, OperatorDecision), 'worker approval JSON is not operator authority')
    require(os.environ.get('GITHUB_ACTIONS') != 'true' and not os.environ.get('REVIEW_WORKER'),
            'confirmation must run in the separate operator environment')
    case = checked_case(candidate)
    require(case['status'] == 'candidate' and decision.input_digest == case['input_digest'], 'confirmation does not match candidate')
    # Expected semantic findings use the same condition/location/impact vocabulary as reviews.
    validate_output({'status': 'findings' if decision.answers else 'verified', 'findings': decision.answers,
                     'summary': decision.reason, 'risk':'unknown', 'patch':'', 'dispositions':[]}, 'verify')
    case.update(status='confirmed', critical=decision.critical or any(a['severity'] in {'P0','P1'} for a in decision.answers),
                split=decision.split, answers=decision.answers,
                decision={'actor':decision.actor, 'at':decision.at, 'reason':decision.reason,
                          'authority':'local-operator', 'input_digest':decision.input_digest})
    return _save_case(validate_case(case), candidate/'input', dest)


def materialize_case(case: Path, dest: Path) -> Json:
    record = checked_case(case)
    require(record['status'] == 'confirmed', 'evaluation requires a human-confirmed case')
    require(not dest.exists(), 'evaluation workspace must be new')
    shutil.copytree(case/'input', dest)
    require(inventory(dest) == record['input_files'], 'materialized input mismatch')
    return {'case_id': record['id'], 'input_digest': record['input_digest'], 'status': 'prepared'}
