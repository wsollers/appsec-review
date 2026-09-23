#!/usr/bin/env python3
"""Generate the job and artifact catalog for the process docs.

Reads the machine-readable sources and writes docs/processes/job-catalog.md (and job-catalog.json,
the same data for other renderers such as the Google Doc build):

  appsec-review-process/job-graph.json               lifecycle nodes, lanes, dependencies, contracts
  appsec-review-process/design-parity-manifest.json  readiness, execution mode, worker, pool, Dagster jobs
  appsec-review-process/process-manifest.json        lane order
  appsec-review-process/registry/job-templates/      declared inputs and outputs, persona composition
  appsec-review-process/registry/output-contracts/   required output files, claim class
  appsec-review-process/<lane>/config.md             "Required Inputs" / "Required Outputs" of stage lanes
  docs/processes/catalog/steps.json                  operator steps, human tasks, standalone Dagster jobs, ops
  docs/processes/catalog/artifacts.json              artifact vocabulary for those steps
  docs/processes/catalog/models.json                 which entries each process model contains
  docs/processes/bpmn/pre-submission.bpmn            cross-check: every BPMN task is covered by a step

Usage:
  python3 docs/processes/job_catalog.py           # regenerate
  python3 docs/processes/job_catalog.py --check   # exit 1 if the outputs are stale or a reference is broken

Standard library only, so it runs with any Python 3.10+ on the host.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROC = ROOT / 'appsec-review-process'
CAT = ROOT / 'docs' / 'processes' / 'catalog'
OUT_MD = ROOT / 'docs' / 'processes' / 'job-catalog.md'
OUT_JSON = ROOT / 'docs' / 'processes' / 'job-catalog.json'
BPMN = ROOT / 'docs' / 'processes' / 'bpmn' / 'pre-submission.bpmn'

KIND_LABEL = {'script': 'operator script', 'human': 'human task', 'dagster-job': 'Dagster job',
              'dagster-op': 'Dagster op', 'dagster-service': 'Dagster service', 'lifecycle': 'lifecycle job'}


def load(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


def config_sections(lane: str) -> dict[str, list[str]]:
    """Bullets under '## Required Inputs' / '## Required Outputs' of a lane's config.md (wrapped lines joined)."""
    path = PROC / lane / 'config.md'
    if not path.exists():
        return {}
    text = path.read_text(encoding='utf-8')
    found = {}
    for heading in ('Required Inputs', 'Required Outputs'):
        m = re.search(r'^## ' + heading + r'\s*\n(.*?)(?=^## |\Z)', text, re.M | re.S)
        if not m:
            continue
        items: list[str] = []
        for line in m.group(1).splitlines():
            if line.startswith('- '):
                items.append(line[2:].strip())
            elif items and line.startswith('  ') and line.strip():
                items[-1] += ' ' + line.strip()
        found[heading] = items
    return found


def build() -> dict:
    graph = load(PROC / 'job-graph.json')['jobs']
    parity = {j['id']: j for j in load(PROC / 'design-parity-manifest.json')['jobs']}
    order = load(PROC / 'process-manifest.json')['process_order']
    templates = {p.stem: load(p) for p in sorted((PROC / 'registry' / 'job-templates').glob('*.json'))}
    contracts = {load(p)['contract_id']: load(p) for p in sorted((PROC / 'registry' / 'output-contracts').glob('*.json'))}
    steps = load(CAT / 'steps.json')['steps']
    artifacts = load(CAT / 'artifacts.json')['artifacts']
    models = load(CAT / 'models.json')['models']
    problems: list[str] = []

    # ---- lifecycle jobs ------------------------------------------------------------------------
    jobs = []
    for jid, node in graph.items():
        p = parity.get(jid, {})
        tpl = templates.get(node.get('template') or '')
        contract = contracts.get(node['contract'])
        stage = config_sections(node['lane']) if jid == node['lane'] else {}
        declared_in, declared_out, in_src, out_src = [], [], None, None
        if tpl:
            declared_in = [('required', x) for x in tpl['inputs'].get('required', [])] + \
                          [('optional', x) for x in tpl['inputs'].get('optional', [])]
            in_src = f"registry/job-templates/{node['template']}.json"
        elif stage.get('Required Inputs'):
            declared_in = [('required', x) for x in stage['Required Inputs']]
            in_src = f"{node['lane']}/config.md"
        if contract:
            declared_out = list(contract.get('required_files', []))
            out_src = f"registry/output-contracts/{node['contract']}.json"
        elif tpl:
            declared_out = list(tpl['outputs'].get('files', []))
            out_src = f"registry/job-templates/{node['template']}.json"
        elif stage.get('Required Outputs'):
            declared_out = stage['Required Outputs']
            out_src = f"{node['lane']}/config.md"
        dag = p.get('dagster', {})
        jobs.append({
            'id': jid, 'lane': node['lane'],
            'name': (tpl or {}).get('display_name') or (contract or {}).get('display_name') or jid,
            'contract': node['contract'], 'implemented': node['implemented'],
            'readiness': p.get('readiness', 'unknown'),
            'execution_mode': p.get('execution', {}).get('mode', 'unknown'),
            'worker': p.get('execution', {}).get('worker'),
            'resource_pool': p.get('resource_pool'),
            'dagster_jobs': sorted(set(dag.get('standalone_jobs', []))),
            'lifecycle_binding': (dag.get('lifecycle_binding') or {}).get('kind'),
            'composition': (tpl or {}).get('composition'),
            'depends_on': [{'job': d['job'], 'kind': d['kind'], 'contract': d['contract']} for d in node['dependencies']],
            'declared_inputs': [{'need': k, 'input': v} for k, v in declared_in], 'inputs_source': in_src,
            'output_dir': f"runs/<run_id>/data/jobs/{node['namespace']}/",
            'output_files': declared_out, 'outputs_source': out_src,
            'claim_class': ((contract or {}).get('claim_class') or {}).get('claim_class_id')
                           if isinstance((contract or {}).get('claim_class'), dict) else (contract or {}).get('claim_class'),
            'gaps': p.get('gaps', []), 'next_prerequisite': p.get('next_prerequisite'),
            # Graph roots read the staged intake contract (inputs/artifact-manifest.json).
            'consumes': [f"job:{d['job']}" for d in node['dependencies']] or ['artifact-manifest'],
            'produces': [f'job:{jid}'],
        })
    job_by_id = {j['id']: j for j in jobs}
    lane_rank = {lane: i for i, lane in enumerate(order)}
    lanes = sorted({j['lane'] for j in jobs}, key=lambda l: lane_rank.get(l, 999))

    # ---- steps ----------------------------------------------------------------------------------
    step_by_id = {s['id']: s for s in steps}

    def known(ref: str, where: str):
        if ref.startswith('job:'):
            if ref[4:] not in job_by_id:
                problems.append(f'{where}: unknown lifecycle job {ref}')
        elif ref not in artifacts:
            problems.append(f'{where}: unknown artifact {ref}')

    for s in steps:
        for ref in s['consumes'] + s['produces']:
            known(ref, f"step {s['id']}")
        for lj in s.get('lifecycle', []):
            if lj != '*' and lj not in job_by_id:
                problems.append(f"step {s['id']}: unknown lifecycle job {lj}")

    # BPMN cross-check: every task-like element is covered by exactly the steps that name it.
    if BPMN.exists():
        text = BPMN.read_text(encoding='utf-8')
        tasks = dict(re.findall(r'<bpmn:(?:\w*[tT]ask|intermediateCatchEvent)\b[^>]*?\bid="([^"]+)"[^>]*?\bname="([^"]*)"', text))
        covered = {b for s in steps for b in s.get('bpmn', [])}
        for b in sorted(covered - set(tasks)):
            problems.append(f'steps.json names BPMN element {b}, which pre-submission.bpmn does not contain')
        for b in sorted(set(tasks) - covered):
            problems.append(f'BPMN task {b} ("{tasks[b]}") is not covered by any step in steps.json')

    # ---- entries (uniform view of steps and lifecycle jobs) ---------------------------------------
    def entry(ref: str) -> dict:
        if ref.startswith('step:'):
            s = step_by_id.get(ref[5:])
            if not s:
                problems.append(f'models.json: unknown step {ref}')
                return {}
            return {'ref': ref, 'id': s['id'], 'name': s['name'], 'kind': s['kind'],
                    'consumes': s['consumes'], 'produces': s['produces'], 'declared_inputs': []}
        if ref.startswith('job:'):
            j = job_by_id.get(ref[4:])
            if not j:
                problems.append(f'models.json: unknown lifecycle job {ref}')
                return {}
            return {'ref': ref, 'id': j['id'], 'name': j['name'], 'kind': 'lifecycle',
                    'consumes': j['consumes'], 'produces': j['produces'],
                    'declared_inputs': [d['input'] for d in j['declared_inputs'] if d['need'] == 'required']}
        problems.append(f'models.json: bad member {ref}')
        return {}

    def rollup(entries: list[dict]) -> dict:
        consumed = [r for e in entries for r in e['consumes']]
        produced = [r for e in entries for r in e['produces']]
        uniq = lambda xs: list(dict.fromkeys(xs))
        consumed, produced = uniq(consumed), uniq(produced)
        declared = uniq([d for e in entries for d in e['declared_inputs']])
        return {'enters': [r for r in consumed if r not in produced],
                'leaves': [r for r in produced if r not in consumed],
                'passes': [r for r in produced if r in consumed],
                'declared_inputs': declared}

    out_models = []
    for m in models:
        explicit = set()
        if m['groups'] != 'lanes':
            for g in m['groups']:
                explicit.update(x for x in g['members'] if not x.startswith('lane:'))
            raw_groups = m['groups']
        else:
            raw_groups = [{'name': lane, 'members': [f'lane:{lane}']} for lane in lanes]
        groups = []
        for g in raw_groups:
            refs = []
            for mem in g['members']:
                if mem.startswith('lane:'):
                    lane = mem[5:]
                    if lane not in lanes:
                        problems.append(f"models.json {m['id']}: unknown lane {lane}")
                    refs += [f"job:{j['id']}" for j in jobs if j['lane'] == lane and f"job:{j['id']}" not in explicit]
                else:
                    refs.append(mem)
            entries = [e for e in (entry(r) for r in refs) if e]
            groups.append({'name': g['name'], 'entries': entries, 'rollup': rollup(entries)})
        all_entries = list({e['ref']: e for g in groups for e in g['entries']}.values())
        out_models.append({'id': m['id'], 'name': m['name'], 'source': m['source'], 'about': m['about'],
                           'groups': groups, 'rollup': rollup(all_entries)})

    # ---- artifact glossary with producers and consumers ------------------------------------------
    glossary = {}
    for aid, a in artifacts.items():
        glossary[aid] = {'id': aid, **a, 'produced_by': [], 'consumed_by': []}
    for j in jobs:
        glossary[f"job:{j['id']}"] = {'id': f"job:{j['id']}", 'kind': 'job output',
                                      'path': j['output_dir'], 'about': f"Accepted {j['contract']} output of {j['id']}.",
                                      'produced_by': [], 'consumed_by': []}
    for s in steps:
        for r in s['produces']:
            glossary.get(r, {}).setdefault('produced_by', []).append(f"step:{s['id']}")
        for r in s['consumes']:
            glossary.get(r, {}).setdefault('consumed_by', []).append(f"step:{s['id']}")
    for j in jobs:
        glossary[f"job:{j['id']}"]['produced_by'].append(f"job:{j['id']}")
        for r in j['consumes']:
            glossary[r].setdefault('consumed_by', []).append(f"job:{j['id']}")
    for aid, a in artifacts.items():
        if not glossary[aid]['produced_by'] and not glossary[aid]['consumed_by']:
            problems.append(f'artifacts.json: {aid} is neither produced nor consumed by any entry')

    return {'schema': 'appsec-review/job-catalog/1',
            'generated_by': 'docs/processes/job_catalog.py',
            'counts': {'lifecycle_jobs': len(jobs), 'steps': len(steps), 'artifacts': len(artifacts),
                       'models': len(out_models)},
            'models': out_models, 'steps': steps, 'lifecycle_jobs': jobs, 'lanes': lanes,
            'artifacts': glossary, 'problems': problems}


# ---- markdown ---------------------------------------------------------------------------------------

def anchor(ref: str) -> str:
    return re.sub(r'[^a-z0-9-]+', '-', ref.lower()).strip('-')


def link(ref: str) -> str:
    return f'[`{ref[4:] if ref.startswith("job:") else ref}`](#{anchor("a-" + ref)})'


def entry_link(e: dict) -> str:
    return f"[{e['name']}](#{anchor(e['ref'])})"


def cell(items, fn=link, empty='--') -> str:
    return '<br>'.join(fn(x) for x in items) if items else empty


def esc(text: str) -> str:
    return str(text).replace('|', '\\|').replace('\n', ' ')


def render(cat: dict) -> str:
    L = []
    w = L.append
    w('# Job and artifact catalog')
    w('')
    w('<!-- GENERATED by docs/processes/job_catalog.py -- do not edit by hand. Edit the sources it names, then rerun it. -->')
    w('')
    w('What each process model runs and what flows between its steps, rolled up per model, with an')
    w('appendix entry per job. Generated from the job graph, design-parity manifest, registry templates and')
    w('output contracts, lane `config.md` files, and the hand-maintained `docs/processes/catalog/*.json`')
    w('(operator steps, human tasks, standalone Dagster jobs, artifact vocabulary, model membership).')
    w('Regenerate after any process change: `python3 docs/processes/job_catalog.py`;')
    w('`--check` fails when this file is stale or a reference is broken.')
    w('')
    c = cat['counts']
    w(f"Covers {c['models']} process models, {c['steps']} steps (operator scripts, human tasks, standalone "
      f"Dagster jobs and ops), {c['lifecycle_jobs']} lifecycle jobs and {len(cat['artifacts'])} artifacts.")
    w('')
    w('How to read the rollups: **Enters** is what the model or group consumes but does not produce itself')
    w('(its inputs); **Leaves** is what it produces that nothing inside consumes (its results); **Passes**')
    w('is handed from one step to another inside it. Artifact names link to the glossary (Appendix C), which')
    w('gives each path and every producer and consumer. `job:<id>` is the accepted output of a lifecycle job.')
    w('')
    if cat['problems']:
        w('> **Catalog problems** (fix the sources, then regenerate):')
        for p in cat['problems']:
            w(f'> - {esc(p)}')
        w('')
    w('## Contents')
    w('')
    for m in cat['models']:
        w(f"- [{m['name']}](#{anchor('model-' + m['id'])})")
    w('- [Appendix A: steps and standalone Dagster jobs](#appendix-a-steps-and-standalone-dagster-jobs)')
    w('- [Appendix B: lifecycle jobs](#appendix-b-lifecycle-jobs)')
    w('- [Appendix C: artifact glossary](#appendix-c-artifact-glossary)')
    w('')

    for m in cat['models']:
        w(f'<a id="{anchor("model-" + m["id"])}"></a>')
        w('')
        w(f"## {m['name']}")
        w('')
        w(f"{m['about']} Source: `{m['source']}`.")
        w('')
        r = m['rollup']
        w('| Rolled up for the model | Artifacts |')
        w('|---|---|')
        w(f"| Enters | {cell(r['enters'])} |")
        w(f"| Leaves | {cell(r['leaves'])} |")
        w(f"| Passes between steps | {cell(r['passes'])} |")
        w('')
        lifecycle_only = all(e['kind'] == 'lifecycle' for g in m['groups'] for e in g['entries'])
        if lifecycle_only:
            w('Per lane (each job\'s full inputs and outputs are in Appendix B):')
            w('')
            w('| Lane | Jobs | Enters | Leaves |')
            w('|---|---|---|---|')
            for g in m['groups']:
                w(f"| `{g['name']}` | {cell(g['entries'], entry_link)} | {cell(g['rollup']['enters'])} | {cell(g['rollup']['leaves'])} |")
            w('')
            continue
        for g in m['groups']:
            w(f"### {m['name'].split(' (')[0]}: {g['name']}")
            w('')
            w('| Step | Type | Consumes | Produces |')
            w('|---|---|---|---|')
            for e in g['entries']:
                w(f"| {entry_link(e)} | {KIND_LABEL.get(e['kind'], e['kind'])} | {cell(e['consumes'])} | {cell(e['produces'])} |")
            gr = g['rollup']
            w(f"| **Group rollup** | | **Enters:** {cell(gr['enters'])} | **Leaves:** {cell(gr['leaves'])} |")
            w('')

    w('## Appendix A: steps and standalone Dagster jobs')
    w('')
    w('Everything that is not a lifecycle-graph node: operator scripts, human tasks, standalone Dagster jobs')
    w('and the ops of `engagement_workflow`. Source: `docs/processes/catalog/steps.json`.')
    w('')
    for s in cat['steps']:
        w(f'<a id="{anchor("step:" + s["id"])}"></a>')
        w('')
        w(f"### {s['name']}")
        w('')
        w('| | |')
        w('|---|---|')
        w(f"| Type | {KIND_LABEL.get(s['kind'], s['kind'])} |")
        w(f"| Runs | `{esc(s['runs'])}` |")
        if s.get('lifecycle'):
            w(f"| Lifecycle job(s) | {'all (Appendix B)' if s['lifecycle'] == ['*'] else cell(['job:' + x for x in s['lifecycle']], lambda r: f'[`{r[4:]}`](#{anchor(r)})')} |")
        if s.get('bpmn'):
            w(f"| BPMN elements | {', '.join('`' + b + '`' for b in s['bpmn'])} |")
        w(f"| Consumes | {cell(s['consumes'])} |")
        w(f"| Produces | {cell(s['produces'])} |")
        w(f"| Notes | {esc(s.get('notes', ''))} |")
        w('')

    w('## Appendix B: lifecycle jobs')
    w('')
    w('One entry per `job-graph.json` node, grouped by lane in `process-manifest.json` order. Declared inputs')
    w('and outputs come from the job template, else the output contract, else the lane `config.md`;')
    w('the source is named in each entry. Output paths are under `appsec-review-process/`.')
    w('')
    w('| Lane | Job | Contract | Readiness | Depends on |')
    w('|---|---|---|---|---|')
    for lane in cat['lanes']:
        for j in [j for j in cat['lifecycle_jobs'] if j['lane'] == lane]:
            deps = ', '.join(f"`{d['job']}`" + (' (optional)' if d['kind'] != 'required' else '') for d in j['depends_on']) or '--'
            w(f"| `{lane}` | [`{j['id']}`](#{anchor('job:' + j['id'])}) | `{j['contract']}` | {j['readiness']} | {deps} |")
    w('')
    for lane in cat['lanes']:
        w(f'### Lane `{lane}`')
        w('')
        for j in [j for j in cat['lifecycle_jobs'] if j['lane'] == lane]:
            w(f'<a id="{anchor("job:" + j["id"])}"></a>')
            w('')
            w(f"#### `{j['id']}` -- {esc(j['name'])}")
            w('')
            w('| | |')
            w('|---|---|')
            w(f"| Contract | `{j['contract']}`" + (f" (claim class `{j['claim_class']}`)" if j['claim_class'] else '') + ' |')
            w(f"| Status | readiness `{j['readiness']}`; execution `{j['execution_mode']}`; job-graph `implemented: {str(j['implemented']).lower()}` |")
            if j['worker']:
                w(f"| Worker | `{j['worker']}` |")
            w(f"| Resource pool | `{j['resource_pool']}` |")
            if j['dagster_jobs'] or j['lifecycle_binding']:
                w(f"| Dagster | standalone: {', '.join('`' + x + '`' for x in j['dagster_jobs']) or '--'}; lifecycle binding: `{j['lifecycle_binding'] or 'none'}` |")
            if j['composition']:
                comp = j['composition']
                w(f"| Composition | persona `{comp.get('persona_id')}`, role `{comp.get('role_id')}`, tooling `{comp.get('tooling_profile_id')}` |")
            deps = '<br>'.join(f"[`{d['job']}`](#{anchor('job:' + d['job'])}) ({d['kind']}, contract `{d['contract']}`)" for d in j['depends_on']) or f"{link('artifact-manifest')} (graph root)"
            w(f'| Consumes (graph) | {deps} |')
            if j['declared_inputs']:
                w(f"| Declared inputs ({j['inputs_source']}) | " + '<br>'.join(f"{esc(d['input'])}" + (' *(optional)*' if d['need'] == 'optional' else '') for d in j['declared_inputs']) + ' |')
            w(f"| Produces | `{j['output_dir']}` |")
            if j['output_files']:
                w(f"| Output files ({j['outputs_source']}) | " + '<br>'.join(esc(f) for f in j['output_files']) + ' |')
            else:
                w(f"| Output files | not yet defined (no output contract, template or lane config) |")
            consumers = cat['artifacts'][f"job:{j['id']}"]['consumed_by']
            w(f"| Consumed by | {cell(consumers, lambda r: f'[`{r.split(chr(58), 1)[1]}`](#{anchor(r)})')} |")
            if j['gaps']:
                w(f"| Gaps | {', '.join('`' + g + '`' for g in j['gaps'])} |")
            if j['next_prerequisite']:
                w(f"| Next prerequisite | {esc(j['next_prerequisite'])} |")
            w('')

    w('## Appendix C: artifact glossary')
    w('')
    w('Artifact vocabulary from `docs/processes/catalog/artifacts.json`, plus one `job:<id>` entry per lifecycle')
    w('job. Producers and consumers are computed from the catalog.')
    w('')
    w('| Artifact | Kind | Path | Produced by | Consumed by |')
    w('|---|---|---|---|---|')
    ref_link = lambda r: f'[`{r.split(chr(58), 1)[1]}`](#{anchor(r)})'
    for aid, a in cat['artifacts'].items():
        name = aid[4:] if aid.startswith('job:') else aid
        w(f'| <a id="{anchor("a-" + aid)}"></a>`{name}` | {a["kind"]} | {esc(a["path"])} | {cell(a["produced_by"], ref_link)} | {cell(a["consumed_by"], ref_link)} |')
    w('')
    return '\n'.join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--check', action='store_true', help='fail if outputs are stale or references are broken')
    args = ap.parse_args()
    cat = build()
    md = render(cat)
    js = json.dumps(cat, indent=1, ensure_ascii=False) + '\n'
    if args.check:
        stale = [p.name for p, t in ((OUT_MD, md), (OUT_JSON, js)) if not p.exists() or p.read_text(encoding='utf-8') != t]
        for p in cat['problems']:
            print('problem:', p)
        for s in stale:
            print('stale:', s, '(run docs/processes/job_catalog.py)')
        return 1 if stale or cat['problems'] else 0
    OUT_MD.write_text(md, encoding='utf-8', newline='\n')
    OUT_JSON.write_text(js, encoding='utf-8', newline='\n')
    print(f"wrote {OUT_MD.relative_to(ROOT)} and {OUT_JSON.relative_to(ROOT)}: {cat['counts']}")
    for p in cat['problems']:
        print('problem:', p)
    return 1 if cat['problems'] else 0


if __name__ == '__main__':
    sys.exit(main())
