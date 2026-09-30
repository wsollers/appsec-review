# docs-render

Renders the BPMN process models in `docs/processes/bpmn/` (`pre-submission.bpmn` and the generated job
cards) to SVG and PNG with bpmn-js in headless Chromium, so the host needs only Docker: no Node
packages, no browser.

- Base: `node:22-bookworm`, pinned by the same digest as `audit-buildenv-typescript`.
- Browser: Debian's `chromium`, driven by `puppeteer-core` (which never downloads a browser);
  `fonts-liberation` supplies a metric-compatible Arial, the font bpmn-js lays labels out in.
- `bpmn-js` and `puppeteer-core` are installed with `npm ci` from `package-lock.json` (sha512 integrity
  per package). Only `package.json` and the lock are copied in; `render.cjs` is mounted read-only at run
  time, never copied.

## Use

```bash
bash docs/processes/bpmn/render-in-docker.sh                                  # all job cards -> cards/render/
bash docs/processes/bpmn/render-in-docker.sh pre-submission.bpmn render-new   # any model -> <outdir>
SKIP_BUILD=1 bash docs/processes/bpmn/render-in-docker.sh                     # reuse docs-render:local
```

Each render runs with `--network none`, a read-only root, `--cap-drop ALL`, `no-new-privileges` and the
caller's uid.

## Updating bpmn-js or puppeteer-core

Change the exact version in `package.json`, run `npm install --package-lock-only --ignore-scripts` in this
folder, commit both files, and re-render the cards to check the output.
