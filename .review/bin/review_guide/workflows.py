"""Finite GitHub DAG shared by both explicitly selected model runtimes."""

import json
from .contracts import Json, validate_config
from .codex import _failure

CHECKOUT = 'actions/checkout@f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a'
UPLOAD = 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9'
DOWNLOAD = 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333'
APP_TOKEN = 'actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349'
CODEX_ACTION = 'openai/codex-action@13e9c17417b29e9a276f73ec6ed7fb574137d3c3'
PYTHON_IMAGE = 'python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b'
CLI = 'python3 trusted/.review/bin/reviewctl.py ci '
PREFIX = '${{ github.run_id }}-${{ github.run_attempt }}-'


def ssh_environment():
    return {'REVIEW_SSH_KEY':'${{ secrets.REVIEW_SSH_KEY }}',
            **{key:'${{ vars.'+key+' }}' for key in ('REVIEW_SSH_HOST','REVIEW_SSH_USER','REVIEW_SSH_PORT','REVIEW_SSH_KNOWN_HOSTS')}}


def selected_result(mode: str, outcomes: Json, result: Json | None) -> Json:
    if outcomes.get(mode) != 'success':
        return _failure('incomplete', 'selected model job did not succeed')
    return result if result else _failure('incomplete', 'selected model output missing')


def checkout():
    return {'uses': CHECKOUT, 'with': {'ref': '${{ github.workflow_sha }}', 'path': 'trusted',
                                     'persist-credentials': False}}


def download(name, path):
    return command('fetch-artifact --name ' + name + ' --destination ' + path,
                   {'GH_TOKEN': '${{ github.token }}'})


def upload(name, path, days):
    return {'uses': UPLOAD, 'with': {'name': PREFIX + name, 'path': path,
            'retention-days': days, 'if-no-files-found': 'error', 'include-hidden-files': True}}


def command(operation, env=None, **extra):
    return {'run': CLI + operation, **({'env': env} if env else {}), **extra}


def outputs():
    return {k: '${{ steps.control.outputs.' + k + ' }}' for k in ('role', 'phase', 'head', 'mode', 'terminal')}


def render_workflows(config: Json) -> dict[str, str]:
    cfg = validate_config(config)
    days = cfg['retention_days']
    read = {'contents': 'read', 'actions': 'read'}
    write = read | {'contents': 'write', 'pull-requests': 'write'}
    token = {'GH_TOKEN': '${{ github.token }}'}
    publisher = token | {'REVIEW_CHECK_TOKEN':'${{ steps.publisher-token.outputs.token }}'}
    mint = {'id':'publisher-token','uses':APP_TOKEN,'with':{
        'app-id':'${{ vars.REVIEW_APP_ID }}','private-key':'${{ secrets.REVIEW_APP_PRIVATE_KEY }}',
        'permission-checks':'write','permission-contents':'read','permission-administration':'read'}}
    jobs = {'entry': {'runs-on': 'ubuntu-24.04', 'timeout-minutes': 5, 'permissions': read,
                     'environment':'review-publisher', 'outputs': outputs(), 'steps': [checkout(), mint, command('entry', publisher, id='control'),
                                                     upload('entry', 'out', days)]}}
    previous, state_name = 'entry', 'entry'
    # Each repair gets bugs/security/verify/fix, and the final repair ALWAYS gets three fresh reviews.
    for i in range(cfg['max_rounds'] * 4 + 3):
        tests, inspect, collect = f'tests_{i}', f'inspect_{i}', f'collect_{i}'
        jobs[tests] = {'needs': [previous], 'if': "${{ !cancelled() && needs." + previous + ".result == 'success' && needs." + previous + ".outputs.terminal != 'true' }}",
                      'runs-on': 'ubuntu-24.04', 'timeout-minutes': 15, 'permissions': read,
                      'steps': [checkout(), download(state_name, 'input'), command('tests'),
                                upload(tests, 'test-result.json', days)]}
        jobs[inspect] = {'needs': [previous, tests], 'if': "${{ always() && !cancelled() && needs." + previous + ".result == 'success' && needs." + previous + ".outputs.terminal != 'true' }}",
                        'runs-on': 'ubuntu-24.04', 'timeout-minutes': 5, 'permissions': read, 'outputs': outputs(),
                        'steps': [checkout(), download(state_name, 'input'),
                                  download(tests, 'test-output') | {'if': '${{ needs.' + tests + ".result == 'success' }}"},
                                  command('inspect', token | {'TEST_OUTCOME': '${{ needs.' + tests + '.result }}'}, id='control'),
                                  upload(inspect, 'out', days)]}
        for mode in ('self_hosted', 'api'):
            name = f'{mode}_{i}'
            condition = '${{ !cancelled() && needs.' + inspect + ".outputs.mode == '" + mode + "' && needs." + inspect + ".outputs.role != '' }}"
            steps = [checkout(), download(inspect, 'input'), command('prepare-worker')]
            if mode == 'self_hosted':
                steps[2] = command('ssh-worker', ssh_environment())
            else:
                steps.extend([{'name': 'Call Codex', 'id': 'codex', 'uses': CODEX_ACTION,
                               'timeout-minutes': '${{ fromJSON(steps.prepare.outputs.timeout_minutes) }}',
                               'continue-on-error': True,
                               'with': {'openai-api-key': '${{ secrets.OPENAI_API_KEY }}',
                                        'prompt-file': 'request/prompt.md', 'output-file': 'raw-result.json',
                                        'output-schema-file': '/home/runner/review-input/policy/.review/schemas/model-output.schema.json',
                                        'working-directory': '/home/runner/review-input',
                                        'codex-home': '/home/runner/review-home', 'permission-profile': 'review',
                                        'safety-strategy': 'drop-sudo', 'codex-version': '${{ steps.prepare.outputs.codex_version }}',
                                        'model': '${{ steps.prepare.outputs.model }}', 'effort': '${{ steps.prepare.outputs.effort }}',
                                        'codex-args': '["--ephemeral", "--skip-git-repo-check"]'}},
                              command('normalize-worker', {'ACTION_OUTCOME': '${{ steps.codex.outcome }}'}, **{'if': '${{ always() && !cancelled() }}'})])
            steps[2]['id'] = 'prepare'
            steps.append(upload(name, 'model-result.json', days))
            jobs[name] = {'needs': [inspect], 'if': condition, 'runs-on': 'ubuntu-24.04',
                          'environment': 'review-runtime', 'timeout-minutes': max(2, (cfg['model_timeout_s'] + 59)//60 + 2),
                          'permissions': read, 'steps': steps}
        steps = [checkout(), download(inspect, 'input')]
        for mode in ('self_hosted', 'api'):
            name = f'{mode}_{i}'
            steps.append(download(name, 'worker-output') | {'if': '${{ needs.' + name + ".result == 'success' }}"})
        steps.extend([command('collect', token | {'SELF_HOSTED_OUTCOME': '${{ needs.self_hosted_' + str(i) + '.result }}',
                                                 'API_OUTCOME': '${{ needs.api_' + str(i) + '.result }}'}, id='control'),
                      upload(collect, 'out', days)])
        jobs[collect] = {'needs': [inspect, f'self_hosted_{i}', f'api_{i}'],
                         'if': '${{ always() && !cancelled() && needs.' + inspect + ".result == 'success' }}",
                         'runs-on': 'ubuntu-24.04', 'timeout-minutes': 10, 'permissions': write,
                         'outputs': outputs(), 'steps': steps}
        previous, state_name = collect, collect
    jobs['finish'] = {'needs': list(jobs), 'if': "${{ always() && needs.entry.result == 'success' }}",
                      'runs-on': 'ubuntu-24.04', 'timeout-minutes': 5, 'permissions': write,
                      'environment':'review-publisher', 'steps': [checkout(), mint, command('finish', publisher | {'JOB_OUTCOMES': '${{ toJSON(needs) }}'}),
                                upload('record', 'out', days)]}
    workflow = {'name': 'Project AI review', 'on': {'pull_request_target': {'types': ['opened', 'synchronize', 'reopened', 'edited', 'ready_for_review']}},
                'permissions': {}, 'concurrency': {'group': 'review-${{ github.event.pull_request.number }}', 'cancel-in-progress': True},
                'jobs': jobs}
    approve = {'name': 'Approve scoped review decision', 'on': {'workflow_dispatch': {'inputs': {
                    'binding': {'description': 'Canonical binding JSON, reviewed by the operator', 'required': True, 'type': 'string'}}}},
               'permissions': {'contents': 'read'}, 'jobs': {'approve': {'name': 'approve-${{ steps.binding.outputs.digest }}',
                    'runs-on': 'ubuntu-24.04', 'environment': 'review-approval', 'steps': [checkout(),
                    command('approval', {'BINDING': '${{ inputs.binding }}'}, id='binding')]}}}
    # GitHub cannot use step outputs in a job name. Resolve a binding job first on the trusted ref.
    approve['jobs'] = {'binding': {'runs-on': 'ubuntu-24.04', 'outputs': {'digest': '${{ steps.binding.outputs.digest }}'},
                                  'steps': [checkout(), command('approval', {'BINDING': '${{ inputs.binding }}'}, id='binding')]},
                       'approve': {'needs': ['binding'], 'name': 'approve-${{ needs.binding.outputs.digest }}',
                                   'runs-on': 'ubuntu-24.04', 'environment': 'review-approval',
                                   'steps': [{'run': 'true'}]}}
    return {'.github/workflows/review-entry.yml': json.dumps(workflow, indent=2) + '\n',
            '.github/workflows/review-approve.yml': json.dumps(approve, indent=2) + '\n',
            '.github/workflows/review-evaluate.yml': json.dumps(evaluation_workflow(cfg, jobs['api_0']['steps'][3]), indent=2) + '\n'}


def evaluation_workflow(cfg: Json, model_step: Json) -> Json:
    import copy
    read = {'contents':'read','actions':'read'}
    jobs = {'entry': {'runs-on':'ubuntu-24.04','timeout-minutes':5,'permissions':read,
                      'outputs':{'mode':'${{ steps.control.outputs.mode }}'},
                      'steps':[checkout(), command('eval-entry', {'GH_TOKEN':'${{ github.token }}'}, id='control'),
                               upload('eval-input','out',cfg['retention_days'])]}}
    for mode in ('self_hosted','api'):
        steps = [checkout(), download('eval-input','input')]
        if mode=='self_hosted':
            steps.append(command('eval-self-hosted', ssh_environment()))
        else:
            for role in ('bugs','security','verify'):
                steps.append(command('eval-request', {'EVAL_ROLE':role}, id='prepare_'+role))
                action = copy.deepcopy(model_step)
                action['id'] = 'codex_'+role
                action['timeout-minutes'] = action['timeout-minutes'].replace('steps.prepare.', 'steps.prepare_'+role+'.')
                action['with'] = {key: value.replace('steps.prepare.', 'steps.prepare_'+role+'.') if isinstance(value,str) else value
                                  for key,value in action['with'].items()}
                action['with']['output-file'] = 'raw-'+role+'.json'
                steps.append(action)
                steps.append(command('eval-normalize', {'EVAL_ROLE':role,'ACTION_OUTCOME':'${{ steps.codex_'+role+'.outcome }}'},
                                     **{'if':'${{ always() && !cancelled() }}'}))
            steps.append(command('eval-record', **{'if':'${{ always() && !cancelled() }}'}))
        steps.append(upload('eval-record-'+mode,'trial-record.json',cfg['retention_days']) | {'if':'${{ always() && !cancelled() }}'})
        jobs[mode] = {'needs':['entry'], 'if':"${{ needs.entry.outputs.mode == '"+mode+"' }}",
                      'runs-on':'ubuntu-24.04',
                      'environment':'review-runtime', 'timeout-minutes':max(5,(cfg['run_timeout_s']+59)//60),
                      'permissions':read,'steps':steps}
    return {'name':'Evaluate one frozen trial','permissions':{},
            'on':{'workflow_dispatch':{'inputs':{name:{'required':True,'type':'string','description':description}
                  for name,description in {'manifest':'Manifest path relative to .review/evals',
                                           'case_id':'Confirmed case folder name', 'configuration':'Frozen configuration digest',
                                           'trial':'Trial index from the expected manifest'}.items()}}}, 'jobs':jobs}
