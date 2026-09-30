# BPMN process models

`pre-submission.bpmn` is the source (BPMN 2.0 with diagram layout). Open and edit it in
[bpmn.io](https://demo.bpmn.io) or Camunda Modeler; the five collapsed subprocesses in the overview
drill down into their own diagrams.

`render/` holds SVG and PNG renders of every diagram in the file, produced with bpmn-js (the bpmn.io
renderer). After editing the model, re-render:

```bash
cd docs/processes/bpmn
npm install --no-save bpmn-js@17 puppeteer
node render.cjs pre-submission.bpmn render-new   # then rename into render/ as needed
```

`render.cjs` needs `PUPPETEER_PATH` (path to the `puppeteer` module) and, if puppeteer's bundled
browser is not used, `CHROME` (a Chromium executable).

`render/print/` holds each diagram cut into overlapping, page-width segments
(`<diagram>-partNofM.png`) for documents with portrait pages, such as the Google Doc
["AppSecReview - Process.doc"](https://docs.google.com/document/d/1OwuRBMoLLoPOL79JlSDUvhUdzgdG_hNDbidD9PHlteI/edit). Regenerate them from the full PNGs whenever the renders change.

What each BPMN task consumes and produces is in [../job-catalog.md](../job-catalog.md) (model
"Pre-submission process"). `catalog/steps.json` maps each step to the BPMN element ids it covers, and
`python3 docs/processes/job_catalog.py --check` fails if a BPMN task is added without a step, so update
`steps.json` with the model.

## Job cards

`cards/<step-id>.bpmn` is one generated card per job mapped into the engagement flow: the job before it
(`preceded_by`), the job with its inputs on the left and outputs on the right, and, when it has
`sub_jobs`, each sub-job inside it with its own inputs above and outputs below. Every input is
labelled with the step that produces it, or "external input". The cards are generated, never edited:
the source is `preceded_by` and `sub_jobs` in `../catalog/steps.json`.

```bash
python3 docs/processes/job_catalog.py        # resolves the flow into job-catalog.json ("flow")
python3 docs/processes/bpmn/card.py          # writes cards/*.bpmn; --check fails when one is stale
cd docs/processes/bpmn && for f in cards/*.bpmn; do node render.cjs "$f" cards/render; done
```

`job_catalog.py --check` fails when a mapped job consumes an artifact that a catalog entry produces
but nothing before it in the `preceded_by` chain does, when a sub-job consumes something neither its
siblings nor the jobs before its parent produce, or when a parent declares an output none of its
sub-jobs produce. Sub-jobs take no `preceded_by`; their parent orders them.
