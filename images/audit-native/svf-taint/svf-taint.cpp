//===- svf-taint.cpp — whole-program taint over SVF's sparse value-flow graph ----===//
//
// Mythos L3 client for SVF-3.3. Answers the question CSA can't carry across TUs:
//
//   does a value derived from untrusted input bytes reach
//     (a) an index into a fixed-size (global / constant) array,
//     (b) a size argument of a memory-copying call,
//     (c) pointer arithmetic on a heap object,
//   anywhere in the linked program?
//
// It does NOT prove overflow. It emits candidates with the full provenance the
// verifier and refutation lanes need: source call + location, sink statement +
// location, the base object and its declared size where known. Refuting a
// candidate means showing the bound check SVF's flow-insensitive view didn't see.
//
// Sources are configured, not hard-coded: -sources=ReadFile:1,recv:1,MapViewOfFile:-1
// (name : 0-based out-argument index, -1 = return value). A matching call taints
// the memory objects its pointer argument may point to (Andersen pts); every load
// from a tainted object yields a tainted value; tainted values propagate forward
// along the SVFG (copies, casts, phis, integer arithmetic, call/ret); a store of a
// tainted value taints the target objects — iterated to a fixpoint.
//
// Build: see CMakeLists.txt + build.sh (inside audit-native; needs SVF_DIR, LLVM_DIR,
// Z3_DIR). Status 2026-09-12: written against SVF-3.3 headers, NOT yet compiled.
//
// Usage: svf-taint -sources=ReadFile:1,recv:1 -out=/scratch/svf-taint.json module.bc
//===----------------------------------------------------------------------------===//

#include "Graphs/SVFG.h"
#include "MSSA/SVFGBuilder.h"
#include "SVF-LLVM/LLVMModule.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/Options.h"
#include "Util/CommandLine.h"
#include "WPA/Andersen.h"
#include "llvm/Support/ManagedStatic.h"

#include <cstdio>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace SVF;
using namespace std;

static Option<string> SourcesOpt("sources",
    "comma list of name:argidx taint sources (argidx -1 = return value)",
    "ReadFile:1,ReadFileEx:1,recv:1,recvfrom:1,WSARecv:1,InternetReadFile:1,WinHttpReadData:1,MapViewOfFile:-1,fread:0,read:1");
static Option<string> SinkCallsOpt("sink-calls",
    "comma list of name:sizeargidx size-taking calls treated as sinks",
    "memcpy:2,memmove:2,memset:2,CopyMemory:2,MoveMemory:2,RtlCopyMemory:2,wmemcpy:2,strncpy:2,wcsncpy:2,memcpy_s:1,memcpy_s:3,alloca:0,malloc:0,operator new:0");
static Option<string> OutOpt("out", "JSON output path", "svf-taint.json");
static Option<bool> Verbose("taint-verbose", "print progress", false);
static Option<u32_t> MaxSourceObjs("max-source-objs",
    "a source whose buffer points to more than this many objects is recorded as SOURCE_UNRESOLVED and not "
    "seeded (Andersen collapses all std::allocator storage into one object: 2,231 objects from one ReadFile "
    "on Notepad++ drowned every precise source, 2026-09-12)", 64);
static Option<bool> PtrOnly("ptr-only",
    "build the pointer-only SVFG instead of the full one. Loses integer-arithmetic propagation "
    "(index = byte*2 breaks the chain) but avoids VFG::setDef 'unique definition' assertions seen "
    "on MSVC-target IR with funclet EH (Notepad++ /EHa, 2026-09-12). Degraded mode; record it.", false);

namespace {

struct Src { string name; int arg; };
struct SinkCall { string name; int arg; };

static vector<pair<string,int>> parseList(const string& s) {
    vector<pair<string,int>> v; stringstream ss(s); string item;
    while (getline(ss, item, ',')) {
        auto c = item.rfind(':'); if (c == string::npos) continue;
        v.push_back({item.substr(0, c), stoi(item.substr(c + 1))});
    }
    return v;
}

static string esc(const string& s) {
    // JSON string escaping incl. all control characters (LLVM instruction text carries tabs;
    // an unescaped one made the first real output unparseable, 2026-09-12).
    string o;
    for (unsigned char ch : s) {
        switch (ch) {
        case '"': o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n"; break;
        case '\t': o += "\\t"; break;
        case '\r': o += "\\r"; break;
        default:
            if (ch < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", ch); o += b; }
            else o += (char)ch;
        }
    }
    return o;
}

static bool nameMatches(const string& callee, const string& want) {
    // extern "C" names must match exactly (substring matched ReadFile against unrelated symbols).
    // For MSVC-mangled C++ names, accept "?<want>@" (method/function name at mangling start).
    if (callee == want) return true;
    if (want.find('?') == string::npos && callee.rfind("?" + want + "@", 0) == 0) return true;
    return false;
}

struct Finding {
    string kind, sinkLoc, sinkFun, sinkDesc, baseObj, baseKind;
    u32_t baseBytes = 0, baseElems = 0;
    string srcName, srcLoc, srcFun;
    int srcArg = 0;
};

struct Taint {
    SVFIR* pag; Andersen* ander; SVFG* svfg;
    vector<pair<string,int>> sources, sinkCalls;
    // tainted state
    // Field-sensitive: these are SVF's precise object ids (GepObjVar per field), NOT base
    // objects. Collapsing to bases tainted whole classes once their buffer field was
    // tainted — every load of Buffer::_size etc. lit up (first Notepad++ run, 2026-09-12).
    Set<NodeID> taintedObjs;                     // memory (sub)objects holding untrusted bytes
    Map<NodeID, u32_t> taintedVals;              // ValVar id -> source index that tainted it
    struct SourceRec { string name; int arg; string loc; string fun; string callee; u32_t objs = 0; string status = "seeded"; };
    vector<SourceRec> srcRecs;
    vector<Finding> findings;

    Taint(SVFIR* p, Andersen* a, SVFG* g) : pag(p), ander(a), svfg(g) {}

    string funName(const FunObjVar* f) { return f ? f->getName() : "?"; }

    // ---- seeding from configured source calls ----
    void seed() {
        for (const CallICFGNode* cs : pag->getCallSiteSet()) {
            const FunObjVar* callee = cs->getCalledFunction();
            if (!callee) continue;
            const string cname = callee->getName();
            for (auto& [name, arg] : sources) {
                if (!nameMatches(cname, name)) continue;
                u32_t sidx = srcRecs.size();
                srcRecs.push_back({name, arg, cs->getSourceLoc(), funName(cs->getFun()), cname});
                SourceRec& rec = srcRecs.back();
                if (arg >= 0) {
                    const auto& parms = cs->getActualParms();
                    if ((u32_t)arg >= parms.size()) { rec.status = "no_such_arg"; continue; }
                    NodeID ptr = parms[arg]->getId();
                    const PointsTo& pts = ander->getPts(ptr);
                    rec.objs = pts.count();
                    if (rec.objs == 0) { rec.status = "empty_pts"; }
                    else if (rec.objs > MaxSourceObjs()) { rec.status = "SOURCE_UNRESOLVED"; }
                    else for (NodeID o : pts) if (!pag->isBlkObjOrConstantObj(o)) taintedObjs.insert(o);
                    if (Verbose()) SVFUtil::outs() << "source " << cname << " arg " << arg << " -> " << rec.objs << " objects, " << rec.status << " @ " << cs->getSourceLoc() << "\n";
                } else {
                    const RetICFGNode* ret = cs->getRetICFGNode();
                    if (ret && pag->callsiteHasRet(ret)) {
                        const SVFVar* rv = pag->getCallSiteRet(ret);
                        const PointsTo& pts = ander->getPts(rv->getId());
                        rec.objs = pts.count();
                        if (rec.objs > MaxSourceObjs()) { rec.status = "SOURCE_UNRESOLVED"; }
                        else {
                            markVal(rv->getId(), sidx);
                            // a returned pointer (MapViewOfFile) also taints what it points to
                            for (NodeID o : pts) if (!pag->isBlkObjOrConstantObj(o)) taintedObjs.insert(o);
                        }
                    }
                }
            }
        }
    }

    void markVal(NodeID v, u32_t sidx) { if (!taintedVals.count(v)) taintedVals[v] = sidx; }

    // ---- forward propagation along the SVFG from one value ----
    void propagateFrom(const ValVar* v, u32_t sidx, Set<const VFGNode*>& visited) {
        if (!svfg->hasDefSVFGNode(v)) return;
        FIFOWorkList<const VFGNode*> wl; wl.push(svfg->getDefSVFGNode(v));
        while (!wl.empty()) {
            const VFGNode* n = wl.pop();
            if (!visited.insert(n).second) continue;
            if (const SVFVar* def = n->getValue()) markVal(def->getId(), sidx);
            for (auto it = n->OutEdgeBegin(); it != n->OutEdgeEnd(); ++it) wl.push((*it)->getDstNode());
        }
    }

    // ---- fixpoint: loads from tainted objects -> tainted values; stores of tainted values -> tainted objects ----
    void run() {
        seed();
        Set<const VFGNode*> visited;
        bool changed = true; int iter = 0;
        while (changed && iter++ < 50) {
            changed = false;
            size_t nv = taintedVals.size(), no = taintedObjs.size();
            for (SVFStmt* st : pag->getSVFStmtSet(SVFStmt::Load)) {
                auto* ld = SVFUtil::cast<LoadStmt>(st);
                if (taintedVals.count(ld->getLHSVarID())) continue;
                u32_t sidx = 0; bool hit = false;
                for (NodeID o : ander->getPts(ld->getRHSVarID()))
                    if (taintedObjs.count(o)) { hit = true; break; }
                if (!hit) continue;
                // attribute to whichever source tainted the pointer, else the first source
                auto pit = taintedVals.find(ld->getRHSVarID());
                sidx = pit != taintedVals.end() ? pit->second : 0;
                markVal(ld->getLHSVarID(), sidx);
                if (auto* vv = SVFUtil::dyn_cast<ValVar>(ld->getLHSVar())) propagateFrom(vv, sidx, visited);
            }
            for (SVFStmt* st : pag->getSVFStmtSet(SVFStmt::Store)) {
                auto* s = SVFUtil::cast<StoreStmt>(st);
                if (!taintedVals.count(s->getRHSVarID())) continue;
                for (NodeID o : ander->getPts(s->getLHSVarID())) if (!pag->isBlkObjOrConstantObj(o)) taintedObjs.insert(o);
            }
            changed = taintedVals.size() != nv || taintedObjs.size() != no;
            if (Verbose()) SVFUtil::outs() << "iter " << iter << ": " << taintedVals.size() << " tainted values, " << taintedObjs.size() << " tainted objects\n";
        }
        sinks();
    }

    void describeBase(NodeID ptr, Finding& f) {
        for (NodeID o : ander->getPts(ptr)) {
            const BaseObjVar* b = pag->getBaseObject(o);
            if (!b) continue;
            if (SVFUtil::isa<GlobalObjVar>(b)) f.baseKind = "global";
            else if (b->isHeap()) f.baseKind = "heap";
            else if (b->isStack()) f.baseKind = "stack";
            else f.baseKind = "other";
            f.baseObj = b->getName().empty() ? b->getSourceLoc() : b->getName();
            f.baseBytes = b->getByteSizeOfObj(); f.baseElems = b->getNumOfElements();
            if (f.baseKind == "global") return;   // prefer the global/const-array interpretation
        }
    }

    void emit(Finding f, u32_t sidx) {
        if (sidx < srcRecs.size()) { f.srcName = srcRecs[sidx].name; f.srcArg = srcRecs[sidx].arg; f.srcLoc = srcRecs[sidx].loc; f.srcFun = srcRecs[sidx].fun; }
        findings.push_back(std::move(f));
    }

    // ---- sinks ----
    void sinks() {
        // (a) GEP with a tainted (non-constant) index operand
        for (SVFStmt* st : pag->getSVFStmtSet(SVFStmt::Gep)) {
            auto* gep = SVFUtil::cast<GepStmt>(st);
            if (gep->isConstantOffset()) continue;
            for (auto& [idxVar, ty] : gep->getAccessPath().getIdxOperandPairVec()) {
                if (!idxVar) continue;
                auto it = taintedVals.find(idxVar->getId());
                if (it == taintedVals.end()) continue;
                Finding f; f.kind = "TAINTED_INDEX"; f.sinkLoc = gep->getICFGNode()->getSourceLoc();
                f.sinkFun = funName(gep->getICFGNode()->getFun()); f.sinkDesc = gep->toString();
                describeBase(gep->getRHSVarID(), f);
                if (f.baseKind == "heap") f.kind = "TAINTED_HEAP_OFFSET";
                emit(f, it->second); break;
            }
        }
        // (b) size argument of a copying/allocating call
        for (const CallICFGNode* cs : pag->getCallSiteSet()) {
            const FunObjVar* callee = cs->getCalledFunction();
            if (!callee) continue;
            for (auto& [name, arg] : sinkCalls) {
                if (!nameMatches(callee->getName(), name)) continue;
                const auto& parms = cs->getActualParms();
                if ((u32_t)arg >= parms.size()) continue;
                auto it = taintedVals.find(parms[arg]->getId());
                if (it == taintedVals.end()) continue;
                Finding f; f.kind = "TAINTED_SIZE_ARG"; f.sinkLoc = cs->getSourceLoc(); f.sinkFun = funName(cs->getFun());
                f.sinkDesc = callee->getName() + " arg " + to_string(arg);
                if (arg != 0 && parms.size() > 0) describeBase(parms[0]->getId(), f);  // destination buffer
                emit(f, it->second);
            }
        }
    }

    void writeJson(const string& path, const string& module) {
        ofstream o(path);
        o << "{\n \"generator\": \"svf-taint\", \"module\": \"" << esc(module) << "\", \"svfg\": \"" << (PtrOnly() ? "ptr-only" : "full") << "\",\n";
        o << " \"sources_seen\": " << srcRecs.size() << ", \"tainted_values\": " << taintedVals.size()
          << ", \"tainted_objects\": " << taintedObjs.size() << ", \"findings_total\": " << findings.size() << ",\n \"sources\": [\n";
        for (size_t i = 0; i < srcRecs.size(); ++i)
            o << "  {\"name\": \"" << esc(srcRecs[i].name) << "\", \"callee\": \"" << esc(srcRecs[i].callee) << "\", \"arg\": " << srcRecs[i].arg
              << ", \"objects\": " << srcRecs[i].objs << ", \"status\": \"" << srcRecs[i].status
              << "\", \"loc\": \"" << esc(srcRecs[i].loc) << "\", \"function\": \"" << esc(srcRecs[i].fun) << "\"}" << (i + 1 < srcRecs.size() ? ",\n" : "\n");
        o << " ],\n \"findings\": [\n";
        for (size_t i = 0; i < findings.size(); ++i) {
            const Finding& f = findings[i];
            o << "  {\"kind\": \"" << f.kind << "\", \"sink_loc\": \"" << esc(f.sinkLoc) << "\", \"sink_function\": \"" << esc(f.sinkFun)
              << "\", \"sink\": \"" << esc(f.sinkDesc) << "\", \"base_object\": \"" << esc(f.baseObj) << "\", \"base_kind\": \"" << f.baseKind
              << "\", \"base_bytes\": " << f.baseBytes << ", \"base_elements\": " << f.baseElems
              << ", \"source\": \"" << esc(f.srcName) << "\", \"source_arg\": " << f.srcArg << ", \"source_loc\": \"" << esc(f.srcLoc)
              << "\", \"source_function\": \"" << esc(f.srcFun) << "\"}" << (i + 1 < findings.size() ? ",\n" : "\n");
        }
        o << " ]\n}\n";
    }
};

} // namespace

int main(int argc, char** argv) {
    vector<string> modules = OptionBase::parseOptions(argc, argv, "SVF whole-program taint (Mythos L3)", "[options] <module.bc>");
    if (modules.empty()) { SVFUtil::errs() << "no input module\n"; return 2; }
    LLVMModuleSet::buildSVFModule(modules);
    SVFIRBuilder builder;
    SVFIR* pag = builder.build();
    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);
    SVFGBuilder svfBuilder;
    SVFG* svfg = PtrOnly() ? svfBuilder.buildPTROnlySVFG(ander) : svfBuilder.buildFullSVFG(ander);
    if (PtrOnly()) SVFUtil::outs() << "svf-taint: pointer-only SVFG (degraded: no integer propagation)\n";

    Taint t(pag, ander, svfg);
    t.sources = parseList(SourcesOpt());
    t.sinkCalls = parseList(SinkCallsOpt());
    t.run();
    t.writeJson(OutOpt(), modules[0]);
    SVFUtil::outs() << "svf-taint: " << t.srcRecs.size() << " source calls, " << t.taintedVals.size() << " tainted values, "
                    << t.taintedObjs.size() << " tainted objects, " << t.findings.size() << " candidates -> " << OutOpt() << "\n";

    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();
    LLVMModuleSet::releaseLLVMModuleSet();
    llvm::llvm_shutdown();
    return 0;
}
