#!/opt/binary-analysis-venv/bin/python3
"""Small CFG/call-edge summary for pregather binary intelligence."""
import json
import sys

import angr


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: angr-summary <binary>", file=sys.stderr)
        return 2

    target = sys.argv[1]
    project = angr.Project(target, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)

    functions = []
    edges = []
    for addr, func in sorted(cfg.kb.functions.items()):
        name = func.name or hex(addr)
        functions.append(
            {
                "address": hex(addr),
                "name": name,
                "block_count": len(list(func.blocks)),
                "returning": bool(func.returning),
            }
        )
        for callee_addr in sorted(func.get_call_sites()):
            target_addr = func.get_call_target(callee_addr)
            if target_addr is not None:
                edges.append(
                    {
                        "caller": name,
                        "call_site": hex(callee_addr),
                        "target": hex(target_addr),
                    }
                )

    print(
        json.dumps(
            {
                "target": target,
                "architecture": project.arch.name,
                "entry": hex(project.entry),
                "function_count": len(functions),
                "call_edge_count": len(edges),
                "functions": functions[:5000],
                "call_edges": edges[:10000],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
