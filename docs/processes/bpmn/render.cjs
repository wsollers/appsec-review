// Render every BPMNDiagram in a .bpmn file to SVG + PNG with bpmn-js (the bpmn.io / Camunda renderer).
// usage: node render.cjs <file.bpmn> <outdir>
const fs = require('fs'), path = require('path');
const puppeteer = require(process.env.PUPPETEER_PATH);
(async () => {
  const [file, outdir] = process.argv.slice(2);
  fs.mkdirSync(outdir, { recursive: true });
  const browser = await puppeteer.launch({ executablePath: process.env.CHROME, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setViewport({ width: 2400, height: 1400, deviceScaleFactor: 2 });
  await page.setContent('<html><body style="margin:0;background:#fff"><div id="c" style="width:2400px;height:1400px"></div></body></html>');
  await page.addScriptTag({ path: require.resolve('bpmn-js/dist/bpmn-viewer.development.js') });
  const xml = fs.readFileSync(file, 'utf8');
  const result = await page.evaluate(async (xml) => {
    const viewer = new BpmnJS({ container: '#c' });
    const imp = await viewer.importXML(xml);
    const defs = viewer.getDefinitions();
    const out = [];
    for (const d of defs.diagrams) {
      await viewer.open(d);
      const { svg } = await viewer.saveSVG();
      out.push({ id: d.id, name: d.name, svg });
    }
    return { warnings: imp.warnings.map(w => w.message), out };
  }, xml);
  console.log('import warnings:', result.warnings.length); result.warnings.slice(0, 10).forEach(w => console.log(' -', w));
  for (const { id, name, svg } of result.out) {
    const base = path.join(outdir, id.replace(/^Diagram_/, ''));
    fs.writeFileSync(base + '.svg', svg);
    await page.setContent(`<html><body style="margin:0;background:#fff">${svg}</body></html>`);
    const el = await page.$('svg');
    await el.screenshot({ path: base + '.png' });
    console.log('rendered', id, '-', name);
  }
  await browser.close();
})();
