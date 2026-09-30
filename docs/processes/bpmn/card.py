#!/usr/bin/env python3
"""Generate one BPMN card per job mapped into the engagement flow.

A card shows one job: the job before it (preceded_by), the job itself with its inputs on the left and
outputs on the right, and, when it has sub-jobs, each sub-job inside it with its own inputs above and
outputs below. Every data object is labelled with the artifact and where it comes from (the step that
produces it, or "external"). Reads docs/processes/job-catalog.json ("flow"), which job_catalog.py
generates from docs/processes/catalog/steps.json; edit steps.json, never the cards.

Usage:
  python3 docs/processes/bpmn/card.py           # write docs/processes/bpmn/cards/<step-id>.bpmn
  python3 docs/processes/bpmn/card.py --check   # exit 1 if a card is stale, missing or orphaned

Render the cards to SVG/PNG with render-in-docker.sh (images/docs-render; see README.md). Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parent / 'job-catalog.json'
CARDS = HERE / 'cards'

TASK_TYPE = {'script': 'scriptTask', 'human': 'userTask', 'dagster-job': 'serviceTask',
             'dagster-op': 'serviceTask', 'dagster-service': 'serviceTask'}

DO_W, DO_H = 36, 50          # data object icon
LABEL_W, LABEL_H = 170, 42   # data object label: artifact, then its origin
SLOT = 180                   # horizontal room per data object in a sub-job column
PITCH = 115                  # vertical room per data object beside the job
TASK_H = 80


def nc(text: str) -> str:
    """An XML NCName fragment for ids."""
    return re.sub(r'[^A-Za-z0-9_.-]', '_', text)


def attr(text: str) -> str:
    return quoteattr(text, {'\n': '&#10;'})


def short(ref: str) -> str:
    return ref.split(':', 1)[1] if ref.startswith('step:') else ref


def origin(src: str) -> str:
    return 'external input' if src == 'external' else f'from {short(src)}'


class Card:
    def __init__(self, job: dict):
        self.job = job
        self.sem: list[str] = []      # semantic XML, process level
        self.di: list[str] = []       # diagram shapes and edges
        self.n = 0

    def uid(self, prefix: str, name: str) -> str:
        self.n += 1
        return f'{prefix}_{self.n}_{nc(name)}'[:80]

    # ---- DI helpers ---------------------------------------------------------------------------
    def shape(self, el: str, x, y, w, h, label=None, expanded=None):
        ex = f' isExpanded="{str(expanded).lower()}"' if expanded is not None else ''
        s = f'      <bpmndi:BPMNShape id="{el}_di" bpmnElement="{el}"{ex}>\n' \
            f'        <dc:Bounds x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" />\n'
        if label:
            lx, ly, lw, lh = label
            s += f'        <bpmndi:BPMNLabel>\n          <dc:Bounds x="{lx:.0f}" y="{ly:.0f}" width="{lw:.0f}" height="{lh:.0f}" />\n' \
                 f'        </bpmndi:BPMNLabel>\n'
        self.di.append(s + '      </bpmndi:BPMNShape>')

    def edge(self, el: str, points):
        wps = ''.join(f'        <di:waypoint x="{x:.0f}" y="{y:.0f}" />\n' for x, y in points)
        self.di.append(f'      <bpmndi:BPMNEdge id="{el}_di" bpmnElement="{el}">\n{wps}      </bpmndi:BPMNEdge>')

    def data_object(self, into: list[str], artifact: str, src: str | None, x, y, label_above: bool) -> str:
        """src None: an output of the activity it hangs off, labelled with the artifact alone."""
        """Data object icon at (x, y); returns its reference id."""
        do, ref = self.uid('DataObject', artifact), self.uid('DataRef', artifact)
        into.append(f'    <bpmn:dataObject id="{do}" />')
        into.append(f'    <bpmn:dataObjectReference id="{ref}" name={attr(artifact if src is None else artifact + chr(10) + origin(src))} dataObjectRef="{do}" />')
        lx = x + DO_W / 2 - LABEL_W / 2
        ly = y - 58 if label_above else y + DO_H + 2          # bpmn-js wraps external labels at ~90px: room for 4 lines
        self.shape(ref, x, y, DO_W, DO_H, (lx, ly, LABEL_W, LABEL_H))
        return ref

    # ---- activities ---------------------------------------------------------------------------
    def activity(self, kind: str, aid: str, name: str, body: list[str], children: list[str] | None = None) -> str:
        tag = 'subProcess' if children is not None else TASK_TYPE.get(kind, 'task')
        inner = ''.join(f'  {line}\n' for line in body + (children or []))
        return f'    <bpmn:{tag} id="{aid}" name={attr(name)}>\n{inner}    </bpmn:{tag}>'

    def io(self, aid: str, ins: list[str], outs: list[str]) -> list[str]:
        """incoming/outgoing are added by the caller; property + data associations here."""
        body = []
        if ins:
            body.append(f'  <bpmn:property id="{aid}_in" name="__targetRef_placeholder" />')
        for r in ins:
            body.append(f'  <bpmn:dataInputAssociation id="In_{r}"><bpmn:sourceRef>{r}</bpmn:sourceRef>'
                        f'<bpmn:targetRef>{aid}_in</bpmn:targetRef></bpmn:dataInputAssociation>')
        for r in outs:
            body.append(f'  <bpmn:dataOutputAssociation id="Out_{r}"><bpmn:targetRef>{r}</bpmn:targetRef></bpmn:dataOutputAssociation>')
        return body

    # ---- layout -------------------------------------------------------------------------------
    def build(self) -> str:
        job = self.job
        subs = job['sub_jobs']
        jid = self.uid('Job', short(job['ref']))

        # Sub-job columns inside the job (expanded sub-process).
        cols = [max(200, SLOT * max(len(s['inputs']), len(s['outputs']), 1)) for s in subs]
        pad, gap = 30, 30
        if subs:
            job_w = pad * 2 + sum(cols) + gap * (len(cols) - 1)
            natural_h = 440
        else:
            job_w, natural_h = 200, TASK_H
        n_side = max(len(job['inputs']), len(job['outputs']), 1)
        job_h = max(natural_h, 30 + n_side * PITCH)

        left_x = 60                       # parent input icons
        job_x = left_x + DO_W + 120
        job_y = 220
        right_x = job_x + job_w + 120     # parent output icons

        # Preceded by (or start of the flow) above the job.
        flow_id = self.uid('Flow', 'preceded_by')
        cx = job_x + job_w / 2
        if job['preceded_by']:
            pid = self.uid('Prev', short(job['preceded_by']))
            name = f"Preceded by:\n{job['preceded_by_name']} ({short(job['preceded_by'])})"
            self.sem.append(f'    <bpmn:task id="{pid}" name={attr(name)}>\n'
                            f'      <bpmn:outgoing>{flow_id}</bpmn:outgoing>\n    </bpmn:task>')
            self.shape(pid, cx - 120, 40, 240, TASK_H)
            prev_bottom = 40 + TASK_H
        else:
            pid = self.uid('Start', 'flow')
            self.sem.append(f'    <bpmn:startEvent id="{pid}" name="Start of the engagement flow (nothing precedes this job)">\n'
                            f'      <bpmn:outgoing>{flow_id}</bpmn:outgoing>\n    </bpmn:startEvent>')
            self.shape(pid, cx - 18, 80, 36, 36, (cx + 30, 84, 220, 28))
            prev_bottom = 116
        self.sem.append(f'    <bpmn:sequenceFlow id="{flow_id}" sourceRef="{pid}" targetRef="{jid}" />')
        self.edge(flow_id, [(cx, prev_bottom), (cx, job_y)])

        # Headings.
        for text, x in (('Inputs', left_x - 20), ('Outputs', right_x - 20)):
            tid = self.uid('Heading', text)
            self.sem.append(f'    <bpmn:textAnnotation id="{tid}"><bpmn:text>{text}</bpmn:text></bpmn:textAnnotation>')
            self.shape(tid, x, job_y - 50, 100, 30)

        # Job inputs (left) and outputs (right), one row each, lines straight into the job's side.
        ins, outs = [], []
        for i, inp in enumerate(job['inputs']):
            y = job_y + 20 + i * PITCH
            r = self.data_object(self.sem, inp['ref'], inp['from'], left_x, y, label_above=False)
            ins.append(r)
            self.edge(f'In_{r}', [(left_x + DO_W, y + DO_H / 2), (job_x, y + DO_H / 2)])
        for i, ref in enumerate(job['outputs']):
            y = job_y + 20 + i * PITCH
            r = self.data_object(self.sem, ref, None, right_x, y, label_above=False)
            outs.append(r)
            self.edge(f'Out_{r}', [(job_x + job_w, y + DO_H / 2), (right_x, y + DO_H / 2)])

        body = [f'  <bpmn:incoming>{flow_id}</bpmn:incoming>'] + self.io(jid, ins, outs)
        label = job['name'] if short(job['ref']) in job['name'] else f"{job['name']} ({short(job['ref'])})"
        if not subs:
            self.sem.append(self.activity(job['kind'], jid, label, body))
            self.shape(jid, job_x, job_y, job_w, job_h)
        else:
            children: list[str] = []
            self.shape(jid, job_x, job_y, job_w, job_h, expanded=True)
            x = job_x + pad
            in_y = job_y + 100                      # input icons; labels above them
            task_y = in_y + DO_H + 45
            out_y = task_y + TASK_H + 45            # output icons; labels below them
            for sub, w in zip(subs, cols):
                sid = self.uid('SubJob', short(sub['ref']))
                s_in, s_out = [], []
                for k, inp in enumerate(sub['inputs']):
                    sx = x + (w - SLOT * len(sub['inputs'])) / 2 + k * SLOT + (SLOT - DO_W) / 2
                    r = self.data_object(children, inp['ref'], inp['from'], sx, in_y, label_above=True)
                    s_in.append(r)
                    self.edge(f'In_{r}', [(sx + DO_W / 2, in_y + DO_H), (sx + DO_W / 2, task_y)])
                for k, ref in enumerate(sub['outputs']):
                    sx = x + (w - SLOT * len(sub['outputs'])) / 2 + k * SLOT + (SLOT - DO_W) / 2
                    r = self.data_object(children, ref, None, sx, out_y, label_above=False)
                    s_out.append(r)
                    self.edge(f'Out_{r}', [(sx + DO_W / 2, task_y + TASK_H), (sx + DO_W / 2, out_y)])
                children.append(self.activity(sub['kind'], sid, sub['name'] if short(sub['ref']) in sub['name'] else f"{sub['name']}\n({short(sub['ref'])})", self.io(sid, s_in, s_out)))
                self.shape(sid, x + 10, task_y, w - 20, TASK_H)
                x += w + gap
            self.sem.append(self.activity(job['kind'], jid, label, body, children))

        pid_ = nc(short(job['ref']))
        return '\n'.join([
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!-- GENERATED by docs/processes/bpmn/card.py from docs/processes/catalog/steps.json; do not edit by hand. -->',
            '<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL" '
            'xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI" xmlns:dc="http://www.omg.org/spec/DD/20100524/DC" '
            'xmlns:di="http://www.omg.org/spec/DD/20100524/DI" id="Card_' + pid_ + '" '
            'targetNamespace="https://github.com/wsollers/appsec-review/job-cards">',
            f'  <bpmn:process id="Process_{pid_}" name={attr("Job card: " + job["name"])} isExecutable="false">',
            *self.sem,
            '  </bpmn:process>',
            f'  <bpmndi:BPMNDiagram id="Diagram_{pid_}" name={attr(job["name"])}>',
            f'    <bpmndi:BPMNPlane id="Plane_{pid_}" bpmnElement="Process_{pid_}">',
            *self.di,
            '    </bpmndi:BPMNPlane>',
            '  </bpmndi:BPMNDiagram>',
            '</bpmn:definitions>',
            ''])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--check', action='store_true', help='fail if a card is stale, missing or orphaned')
    args = ap.parse_args()
    flow = json.loads(CATALOG.read_text(encoding='utf-8'))['flow']
    cards = {CARDS / f'{sid}.bpmn': Card(job).build() for sid, job in flow.items()}
    if args.check:
        bad = [f'stale or missing: {p.name}' for p, t in cards.items()
               if not p.exists() or p.read_text(encoding='utf-8') != t]
        bad += [f'orphaned: {p.name} (no step maps it)' for p in sorted(CARDS.glob('*.bpmn')) if p not in cards]
        for b in bad:
            print(b, '(run docs/processes/bpmn/card.py)')
        return 1 if bad else 0
    CARDS.mkdir(exist_ok=True)
    for p, t in cards.items():
        p.write_text(t, encoding='utf-8', newline='\n')
    print(f'wrote {len(cards)} cards to {CARDS.relative_to(HERE.parents[2])}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
