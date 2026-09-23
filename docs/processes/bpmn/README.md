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
["AppSecReview - Process.doc"](https://docs.google.com/document/d/1DZlI8yF94P5cYO_fDxb8-hsY6eH7tZtmQd4Oscvd9hM/edit). Regenerate them from the full PNGs whenever the renders change.

