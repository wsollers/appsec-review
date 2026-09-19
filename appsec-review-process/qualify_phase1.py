"""Reproducible A01-A16 qualification. Evidence is retained; no target builds/scans/LLMs."""
from __future__ import annotations
import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid

from execution_state import ROOT, atomic_json, atomic_bytes, data_path, digest, execute, file_hash, now, read_json

REPO = ROOT.parent
COMPOSE = ['docker','compose','-f','orchestrator/dagster/compose.yaml']


def code_identity():
    paths = list(ROOT.glob('*.py')) + [ROOT/'job-graph.json',ROOT/'process-manifest.json',ROOT/'phase-1-implementation-prompt.md',
        ROOT/'00-intake-recovery/config.md',ROOT/'00-intake-recovery/prompt.md',ROOT/'tooling/buildenv-catalog.json']
    paths += list((ROOT/'registry').rglob('*.json')) + list((REPO/'schemas').glob('*.json')) + list((ROOT/'tests').glob('*.py'))
    paths += [REPO/'orchestrator/dagster'/name for name in ('definitions.py','compose.yaml','Dockerfile','requirements.txt','requirements.lock.txt','dagster.yaml','workspace.yaml')]
    paths += [REPO/'pipeline/engagement_job.ps1',REPO/'pipeline/engagement_job.sh',REPO/'docs/phase-1-job-graph.mmd']
    return {'base_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
            'working_tree_files':{str(p.relative_to(REPO)):file_hash(p) for p in sorted(set(paths))}}


def containers(project):
    ids=subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project],text=True).split()
    if not ids: return []
    records=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
    # Never export Config.Env, which contains service credentials.
    return [{'Id':r['Id'],'Name':r['Name'],'State':r['State'],'Mounts':r['Mounts'],'Image':r['Image'],
             'ports':r['NetworkSettings']['Ports']} for r in records]


def legacy_identity(records):
    # Docker returns mount arrays in map iteration order; compare identities, not order.
    return sorted([{'Id':r['Id'],'Name':r['Name'],'State':r['State'],
                    'Mounts':sorted(r['Mounts'],key=lambda m:(m['Destination'],m['Source']))} for r in records],key=lambda r:r['Id'])


def contracts():
    from job_graph import composition,load_graph,mermaid
    from schema_validate import validate_document
    from validate_design_parity import validate_manifest
    kinds={'personas':('persona','persona_id'),'roles':('role','role_id'),'domains':('domain','domain_id'),
           'tooling-profiles':('tooling-profile','tooling_profile_id'),'output-contracts':('output-contract','contract_id'),
           'job-templates':('job-template','job_template_id')}
    count=0
    for folder,(schema,field) in kinds.items():
        for path in (ROOT/'registry'/folder).glob('*.json'):
            record=read_json(path); errors=validate_document(record,schema+'.schema.json')
            if errors or record[field] != path.stem: raise ValueError(str(path)+': '+str(errors))
            if folder=='job-templates': composition(record)
            count+=1
    graph=load_graph()
    if mermaid(graph) != (REPO/'docs/phase-1-job-graph.mmd').read_text(): raise ValueError('diagram drift')
    parity_manifest=read_json(ROOT/'design-parity-manifest.json')
    parity=validate_manifest(parity_manifest)
    if parity['errors']: raise ValueError('design parity validation failed: '+'; '.join(parity['errors']))
    print(json.dumps({'registry_records':count,'graph_jobs':len(graph['jobs']),
                      'parity_capabilities':parity['capability_count'],
                      'schemas_and_semantics':'PASS','design_parity_inventory':'PASS'}))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id');parser.add_argument('--check-contracts',action='store_true')
    args=parser.parse_args(argv)
    if args.check_contracts: contracts();return 0
    if not args.run_id: parser.error('--run-id is required')
    if not (ROOT/'runs'/args.run_id/'run-status.json').exists(): parser.error('create qualification run with run_process.py --start first')
    batch='q-'+uuid.uuid4().hex[:8]; root=data_path(args.run_id,'acceptance',batch);root.mkdir(parents=True)
    before=code_identity();atomic_json(root/'tested-identity.json',before)
    steps={}
    def command(name,argv,timeout=300,env=None):
        logs=root/name
        print(f'{name}: running',flush=True)
        result=execute(argv,REPO,logs,timeout,env=env)
        result['artifacts']=[{'path':str(p.relative_to(data_path(args.run_id))),'sha256':file_hash(p)}
                             for p in sorted(logs.iterdir()) if p.is_file()]
        steps[name]=result
        print(f'{name}: exit {result["exit_code"]}'+(' '+result['error'] if result.get('error') else ''),flush=True)
        return result
    def ok(name): return name in steps and steps[name]['exit_code']==0 and not steps[name].get('error')
    try:
        old_before=containers('lra-ingestion-harness');new_before=containers('appsec-review')
        atomic_json(root/'legacy-before.json',old_before);atomic_json(root/'services-before.json',new_before)
        contracts_result=command('contracts',[sys.executable,'-B',str(ROOT/'qualify_phase1.py'),'--check-contracts'])
        with ThreadPoolExecutor(max_workers=2) as pool:
            win=pool.submit(command,'tests-host',[sys.executable,'-B',str(ROOT/'tests/test_phase1.py')],360,
                            dict(os.environ,PHASE1_TEST_DATA=str(root/'f'),PYTHONDONTWRITEBYTECODE='1'))
            linux=pool.submit(command,'tests-linux',COMPOSE+['exec','-T','-e',f'PHASE1_TEST_DATA=/runs/{args.run_id}/data/acceptance/{batch}/l',
                                  'code-server','python','-B','/opt/process/tests/test_phase1.py'],600)
            win.result();linux.result()
        command('dagster',COMPOSE+['exec','-T','code-server','python','-B','/opt/process/qualify_dagster.py',
                                  '--qualification-run',args.run_id,'--evidence-id',batch+'-dagster'],900)
        command('restart',COMPOSE+['restart'],180)
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            services=containers('appsec-review')
            if len(services)==4 and all(r['State'].get('Health',{}).get('Status')=='healthy' for r in services): break
            time.sleep(2)
        atomic_json(root/'services-after.json',services)
        healthy=len(services)==4 and all(r['State'].get('Health',{}).get('Status')=='healthy' for r in services)
        with urllib.request.urlopen('http://127.0.0.1:3000/server_info',timeout=10) as response:
            atomic_bytes(root/'webserver.json',response.read());web_ok=response.status==200
        query='query { pipelineOrError(params:{repositoryName:"__repository__", repositoryLocationName:"appsec_review", pipelineName:"phase1_intake"}) { __typename ... on Pipeline { name solids { name inputs { definition { name } dependsOn { solid { name } } } } } } }'
        request=urllib.request.Request('http://127.0.0.1:3000/graphql',data=json.dumps({'query':query}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=10) as response:
            ui=json.loads(response.read())
        atomic_json(root/'ui-graph.json',{'query':query,'result':ui})
        graph=ui['data']['pipelineOrError']
        edges={(upstream['solid']['name'],node['name']) for node in graph['solids'] for port in node['inputs'] for upstream in port['dependsOn']}
        web_ok=web_ok and edges=={('intake_config','intake_pre_validation'),('intake_pre_validation','intake_work'),('intake_work','intake_post_validation')}
        command('restart-check',COMPOSE+['exec','-T','code-server','python','-B','/opt/process/qualify_dagster.py',
                                        '--qualification-run',args.run_id,'--evidence-id',batch+'-dagster','--resume-check'],120)
        command('runtime',COMPOSE+['exec','-T','code-server','python','-B','-c',
            "import json,subprocess;from definitions import defs;print(json.dumps({'jobs':[{ 'name':j.name,'ops':list(j.graph.node_dict)} for j in defs.get_repository_def().get_all_jobs()],'dependencies':subprocess.check_output(['pip','freeze','--all'],text=True),'git':subprocess.check_output(['git','--version'],text=True)}))"],60)
        old_after=containers('lra-ingestion-harness');atomic_json(root/'legacy-after.json',old_after)
        old_ok=legacy_identity(old_before)==legacy_identity(old_after) and all(not x['State']['Running'] for x in old_after)
        original=data_path(args.run_id,'acceptance','lra-ingestion-harness-before.json')
        if original.exists(): old_ok=old_ok and legacy_identity(read_json(original))==legacy_identity(old_after)
        # Host Freeciv run also exercises the compatibility CLI and Windows link handling.
        created=command('create-host-run',[sys.executable,'-B',str(ROOT/'run_process.py'),'--start'])
        rid=json.loads((root/'create-host-run/stdout.log').read_text())['run_id']
        command('stage-host-run',[sys.executable,'-B',str(ROOT/'stage_artifacts.py'),'--run-id',rid,'--project','freeciv21',
            '--target',str(REPO/'targets/freeciv21'),'--business-goal','Bounded qualification; no builds or scanners','--platform','Linux','--platform','Windows'])
        # Explicit adapter parity diagnostics; the operator CLI submits to Linux Dagster.
        command('intake-host',[sys.executable,'-B',str(ROOT/'phase1.py'),'intake','--run-id',rid],300)
        command('reuse-host',[sys.executable,'-B',str(ROOT/'phase1.py'),'intake','--run-id',rid],300)
        command('status-host',[sys.executable,'-B',str(ROOT/'review_cli.py'),'status','--run-id',rid],180)
        command('handoff-host',[sys.executable,'-B',str(ROOT/'create_handoff.py'),'--run-id',rid,'--process','02-evidence-pregather','--budget','probe'],180)
        command('validate-host',[sys.executable,'-B',str(ROOT/'validate_lane_output.py'),'--run-id',rid,'--process','00-intake-recovery'],180)
        command('graph',[sys.executable,'-B',str(ROOT/'phase1.py'),'graph','--check'])
        reuse=json.loads((root/'reuse-host/stdout.log').read_text()) if ok('reuse-host') else {}
        from phase1 import accepted,job_root
        pointer=accepted(rid,fresh=False) if ok('intake-host') else None
        if pointer:
            result=read_json(job_root(rid)/'attempts'/pointer['attempt_id']/'outputs/intake.json')
            freeciv_ok=result['native']['applicable'] and result['native']['build_status']=='NOT_EXECUTED' and result['source_revision'] != 'unversioned' and not result['scope']['primary_selection_excludes_other_scope']
            atomic_json(root/'freeciv-host.json',{'run_id':rid,'pointer':pointer,'native':result['native'],'scope':result['scope'],'families':list(result['families'])})
        else: freeciv_ok=False
    except BaseException as exc:
        atomic_json(root/'qualification-error.json',{'error':f'{type(exc).__name__}: {exc}'})
        print(f'Qualification error: {exc}',file=sys.stderr,flush=True)
        healthy=web_ok=old_ok=freeciv_ok=False;reuse={}
    after=code_identity();stable=before==after
    atomic_json(root/'steps.json',steps)
    methods=[n.name for n in ast.walk(ast.parse((ROOT/'tests/test_phase1.py').read_text())) if isinstance(n,ast.FunctionDef) and n.name.startswith('test_A')]
    tests_ok=ok('tests-host') and ok('tests-linux')
    prompt_hash=file_hash(ROOT/'phase-1-implementation-prompt.md')
    initial_vetting=data_path(args.run_id,'acceptance','prompt-vetting.json')
    initial=read_json(initial_vetting) if initial_vetting.exists() else {}
    vetted=initial.get('prompt_sha256')==prompt_hash and initial.get('requirement_blockers')==[]
    mappings={
      'A01':(['qualify_phase1.py','phase-1-implementation-prompt.md'],['contracts']),
      'A02':(['orchestrator/dagster/compose.yaml','orchestrator/dagster/definitions.py','qualify_dagster.py'],['dagster','restart','restart-check','runtime']),
      'A03':(['job_graph.py','registry/'],['contracts','tests-host','tests-linux']),
      'A04':(['intake.py'],['tests-host','tests-linux','intake-host']),
      'A05':(['phase1.py:validate_supplied'],['tests-host','tests-linux']),
      'A06':(['execution_state.py:identifier/beneath','phase1.py'],['tests-host','tests-linux']),
      'A07':(['phase1.py:Session/accepted'],['tests-host','tests-linux','reuse-host','dagster']),
      'A08':(['job_graph.py:definition_hash','intake.py:source_identity','phase1.py:invalidate'],['tests-host','tests-linux']),
      'A09':(['execution_state.py:Lock/atomic_bytes','phase1.py:Session'],['tests-host','tests-linux']),
      'A10':(['job_graph.py','phase1.py:Session'],['tests-host','tests-linux','dagster']),
      'A11':(['execution_state.py:execute','process_gate.py'],['tests-host','tests-linux']),
      'A12':(['execution_state.py:ProcessTree/execute','phase1.py:Session.fail'],['tests-host','tests-linux']),
      'A13':(['stage_artifacts.py','create_handoff.py','review_cli.py','validate_lane_output.py','pipeline/engagement_job.*'],['tests-host','tests-linux','handoff-host','status-host','validate-host']),
      'A14':(['intake.py','qualify_dagster.py'],['intake-host','reuse-host','dagster']),
      'A15':(['job-graph.json','docs/phase-1-job-graph.mmd','job_graph.py','review_cli.py'],['graph','status-host','dagster','tests-host','tests-linux']),
      'A16':(['qualify_phase1.py'],list(steps))}
    conditions={'A01':ok('contracts') and stable and vetted,'A02':all(ok(n) for n in ('dagster','restart','restart-check','runtime')) and healthy and web_ok and old_ok,
                **{f'A{i:02}':tests_ok for i in range(3,14)},
                'A14':freeciv_ok and reuse.get('reused') is True and ok('dagster'),
                'A15':tests_ok and ok('graph') and ok('status-host') and ok('dagster'),'A16':stable and bool(steps)}
    conditions['A03'] &= ok('contracts')
    conditions['A13'] &= all(ok(n) for n in ('handoff-host','status-host','validate-host'))
    gate_rows=[]
    for gate,(files,names) in mappings.items():
        gate_rows.append({'id':gate,'status':'PASS' if conditions[gate] else 'FAIL','implementation':files,
            'tests':[m for m in methods if m.startswith('test_'+gate)],
            'commands':[{'step':name,**steps[name]} for name in names if name in steps],
            'resume_command':f'python -B appsec-review-process/qualify_phase1.py --run-id {args.run_id}'})
    for row in gate_rows:
        extra={'A02':['legacy-before.json','legacy-after.json','services-before.json','services-after.json','webserver.json','ui-graph.json'],
               'A14':['freeciv-host.json'],'A16':['tested-identity.json','steps.json']}.get(row['id'],[])
        row['additional_evidence']=[{'path':str((root/name).relative_to(data_path(args.run_id))),'sha256':file_hash(root/name)} for name in extra if (root/name).exists()]
    blockers=[r['id'] for r in gate_rows if r['status']!='PASS']
    section=''; requirements=[]
    section_gates={'Task 0':['A01'],'Task 1':['A02'],'Task 2':['A04','A05','A13','A14'],
                   'Task 3':['A06','A07','A08','A09','A13'],'Task 4':['A03','A10','A15'],'Task 5':['A11','A12','A15']}
    for number,line in enumerate((ROOT/'phase-1-implementation-prompt.md').read_text().splitlines(),1):
        if line.startswith('## '): section=line[3:]
        if not line.strip(): continue
        gates=next((ids for prefix,ids in section_gates.items() if section.startswith(prefix)),['A01','A16'])
        if line.startswith('| A'):
            gates=[line.split('|')[1].strip()]
        requirements.append({'line':number,'section':section,'requirement':line,'gates':gates,
            'implementation':sorted({p for gate in gates for p in mappings[gate][0]}),
            'tests':sorted({m for gate in gates for m in methods if m.startswith('test_'+gate)}),
            'evidence':'acceptance.json: '+', '.join(gates),
            'disposition':'PASS' if all(conditions[gate] for gate in gates) else 'UNRESOLVED; see gate commands and diagnostics'})
    vet={'reviewer':'Codex /root; self-review, not independent','date':now(),'prompt_sha256':prompt_hash,
         'tested_identity_sha256':file_hash(root/'tested-identity.json'),'requirement_matrix':gate_rows,
         'requirements':requirements,'initial_review':str(initial_vetting),'initial_review_hash_matches':vetted,
         'remaining_requirement_blockers':blockers,
         'resolved_findings':['Legacy/shared scratch requires explicit import into a new run','Non-native intake is not gated on compile databases',
         'Missing pregather output differs from corrupt supplied evidence','OS locks bind a run to one executor platform',
         'Validator composition is explicit and nonrecursive','Planned downstream jobs are not dispatched or claimed implemented',
         'Freeciv Windows Linux-link caveats are recorded without following links','Command redaction, lost-worker cleanup and logging failures have behavioral tests'],
         'coverage':'Tasks 0-5 and acceptance A01-A16; see per-gate implementation/tests/commands above and the initial line-by-line prompt-vetting.json.'}
    atomic_json(root/'prompt-vetting.json',vet)
    report={'run_id':args.run_id,'qualification_id':batch,'date':now(),'status':'ACCEPTED' if not blockers else 'NOT ACCEPTED',
            'gates':gate_rows,'tested_identity':before,'stable_during_tests':stable,'prompt_sha256':prompt_hash,
            'review_type':'self-review','limitations':['Intake and handoff only; downstream partition/discovery/scanners remain planned.',
             'No Freeciv21 build, native compile evidence, full security review or LLM was executed.',
             'Execution-platform-bound OS locking; no distributed or cross-OS lock guarantee.',
             'Quiescent source boundary checks; transient edit/revert between checks is not detectable.',
             'One attempt per invocation; infrastructure recovery is explicit, not an automatic target retry.',
             'Raw logs stay local; service metadata/compute logs use dedicated persistent Dagster volumes.'],
            'blockers':blockers,'resume_command':f'python -B appsec-review-process/qualify_phase1.py --run-id {args.run_id}'}
    atomic_json(root/'acceptance.json',report)
    lines=['# Phase 1 acceptance', '', '**'+report['status']+'**', '',f'Run: `{args.run_id}`; qualification: `{batch}`',
           f'Tested base revision: `{before["base_revision"]}` plus exact working-file hashes in tested-identity.json.',
           f'Prompt SHA-256: `{prompt_hash}`','', '| Gate | Status | Evidence |','|---|---|---|']
    lines += [f'| {r["id"]} | {r["status"]} | acceptance.json: commands, exit codes, artifacts and SHA-256 hashes |' for r in gate_rows]
    lines += ['', 'Limitations:', *['- '+s for s in report['limitations']], '', 'Resume: `'+report['resume_command']+'`']
    atomic_bytes(root/'acceptance.md',('\n'.join(lines)+'\n').encode())
    atomic_json(data_path(args.run_id,'acceptance','latest.json'),{'report':str((root/'acceptance.json').relative_to(data_path(args.run_id))),
                'sha256':file_hash(root/'acceptance.json'),'status':report['status']})
    print(json.dumps({'status':report['status'],'report':str(root/'acceptance.md'),'blockers':blockers}),flush=True)
    return 0 if not blockers else 1


if __name__ == '__main__':
    raise SystemExit(main())
