# Mermaid renders

PNG renders of the Mermaid charts in the process docs, for places that cannot render Mermaid
(the Google Doc ["AppSecReview - Process.doc"](https://docs.google.com/document/d/1OwuRBMoLLoPOL79JlSDUvhUdzgdG_hNDbidD9PHlteI/edit)). Re-render whenever a chart changes:

```bash
npx -p @mermaid-js/mermaid-cli mmdc -i chart.mmd -o render/<name>.png -b white -s 2
```

| File | Source |
|---|---|
| `flow-bringup-status.png` | the chart in `flow-bringup.md` |
| `engagement-start-flow.png` | the chart in `engagement-start.md` |
| `dagster-workflow.png` | `docs/dagster/dagster-workflow.mmd` |
| `dagster-launching-path.png` | the chart in `docs/dagster/dagster-launching.md` |
