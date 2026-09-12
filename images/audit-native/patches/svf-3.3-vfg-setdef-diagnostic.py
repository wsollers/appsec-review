#!/usr/bin/env python3
"""Patch SVF-3.3 svf/include/Graphs/VFG.h: VFG::setDef's "a ValVar can only have unique
definition" assertion becomes a diagnostic that keeps the FIRST definition and prints
both, so (a) the run continues and (b) the offending construct is named.

Applied at image build. Reason (2026-09-12): the assertion fires on the linked
Notepad++ notepadPlus module (MSVC target) in both full and pointer-only SVFG builds;
root cause not yet identified. Every occurrence is printed with the [SVF-PATCH] prefix;
count them in the run log. Remove this patch once the cause is fixed here or upstream.
"""
import sys
p = sys.argv[1]
s = open(p).read()
old = '''            assert((it->second == node->getId()) && "a ValVar can only have unique definition ");'''
new = '''            if (it->second != node->getId())
            {
                SVFUtil::errs() << "[SVF-PATCH] duplicate definition for ValVar " << valVar->getId()
                                << " (" << valVar->toString() << ")\\n    existing: " << getGNode(it->second)->toString()
                                << "\\n    ignored : " << node->toString() << "\\n";
            }'''
assert s.count(old) == 1, "setDef assertion not found exactly once — SVF version changed?"
open(p, "w").write(s.replace(old, new))
print("patched", p)
