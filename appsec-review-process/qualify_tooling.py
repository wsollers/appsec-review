"""Probe installed language images and MCP services, writing only beneath owner run data."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import uuid

from execution_state import ROOT, atomic_json, data_path, execute

SERVERS = {
 'cpp': ['clangd'], 'java': ['jdtls','-data','/scratch/jdtls-workspace'],
 'go': ['gopls','serve'], 'typescript': ['typescript-language-server','--stdio'],
 'php': ['phpactor','language-server'], 'dotnet': ['csharp-ls'],
 'python': ['pylsp'], 'rust': ['rust-analyzer'],
}


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--run-id',required=True)
    args = p.parse_args()
    owner = data_path(args.run_id, 'tooling', 'qualification-' + uuid.uuid4().hex[:8]); owner.mkdir(parents=True)
    def check(language):
        root = owner / language; root.mkdir()
        for name in ('home','tmp','cache'): (root/name).mkdir()
        image = 'audit-buildenv-' + language + ':local'
        inspection = execute(['docker','image','inspect','--format','{{.Id}}',image], ROOT.parent, root/'image',30)
        image_id = (root/'image/stdout.log').read_text().strip()
        if inspection['exit_code'] != 0: return {'language': language, 'status': 'MISSING_IMAGE'}
        # Pin the inspected immutable image ID for each probe invocation.
        target = ROOT.parent / ('targets/freeciv21' if language == 'cpp' else 'images/test/' + language)
        common = ['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
                  '--security-opt','no-new-privileges','--pids-limit','256','--memory','2g','--cpus','2',
                  '--mount',f'type=bind,src={target},dst=/workspace,readonly',
                  '--mount',f'type=bind,src={ROOT},dst=/opt/process,readonly',
                  '--mount',f'type=bind,src={root},dst=/scratch',
                  '-e','HOME=/scratch/home','-e','TMPDIR=/scratch/tmp','-e','XDG_CACHE_HOME=/scratch/cache',
                  '-e','PYTHONDONTWRITEBYTECODE=1','-e','MEMORY_FILE_PATH=/scratch/memory.json',
                  '-e','JAVA_TOOL_OPTIONS=-Duser.home=/scratch/home',
                  '--workdir','/workspace','--entrypoint','python3',image_id,
                  '/opt/process/tooling/probe_stdio.py']
        checks = []
        probes = [('lsp','lsp',SERVERS[language]),
                  ('filesystem','mcp',['mcp-server-filesystem','/workspace']),
                  ('memory','mcp',['mcp-server-memory'])]
        for name, mode, command in probes:
            argv = common + ['--out','/scratch/'+name,'--mode',mode]
            if language == 'typescript' and name == 'lsp':
                argv += ['--initialization-json',json.dumps({'tsserver':{'path':'/usr/local/lib/node_modules/vscode-langservers-extracted/node_modules/typescript/lib/tsserver.js'}})]
            if name == 'filesystem':
                argv += ['--call-json',json.dumps({'name':'list_allowed_directories','arguments':{}})]
            if name == 'memory':
                argv += ['--call-json',json.dumps({'name':'read_graph','arguments':{}})]
            result = execute(argv + ['--'] + command, ROOT.parent, root/(name+'-launch'),90)
            checks.append({'name':name,'status':'PASS' if result['exit_code']==0 and not result.get('error') else 'FAILED',
                           'receipt':str(root/name/'receipt.json')})
        return {'language':language,'image':image,'image_id':image_id,'checks':checks,
                'status':'PASS' if all(c['status']=='PASS' for c in checks) else 'FAILED'}
    with ThreadPoolExecutor(max_workers=3) as pool: results=list(pool.map(check,SERVERS))
    report={'status':'PASS' if all(r['status']=='PASS' for r in results) else 'GAPS',
            'results':results,'scope':'protocol initialization/discovery and MCP read calls; no semantic build qualification'}
    atomic_json(owner/'report.json',report); print(json.dumps({'report':str(owner/'report.json'),**report},indent=2))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__': raise SystemExit(main())
