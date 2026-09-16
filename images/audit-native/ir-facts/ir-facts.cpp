//===- ir-facts.cpp — dump the facts a verifier needs from LLVM bitcode -----------===//
//
// Mythos L7 substrate. Reads a (linked) module compiled with -g and writes JSON:
//
//   globals    : every global with an array type — element count, element bytes,
//                constant-ness, source location (from DIGlobalVariable)
//   ctor_stores: in MSVC constructors (??0...), constant integers stored through `this`
//                — field index, value, struct type, source line
//   geps       : every GEP with a non-constant index — base kind (global name /
//                alloca / argument / other), base element count if known, index width,
//                whether the index is a zero-extended 8-bit value (type-bounded),
//                enclosing function, source line
//   size_calls : memcpy/memmove/memset intrinsics, operator new[] / malloc, and
//                std::basic_string(ptr, n) constructors — size operand constant or not,
//                whether it depends on a function argument, source line
//   allocas    : stack arrays with element counts
//
// The point is that these are the numbers a finding's claim rests on. A verifier
// compares the claim against them instead of re-reading the source.
//
//   ir-facts module.bc -o ir-facts.json
//
// Status 2026-09-13: written against LLVM 21 API, not yet compiled.
//===------------------------------------------------------------------------------===//

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <map>
#include <set>
#include <string>

using namespace llvm;

static cl::opt<std::string> Input(cl::Positional, cl::desc("<module.bc>"), cl::Required);
static cl::opt<std::string> Output("o", cl::desc("output JSON"), cl::init("ir-facts.json"));

namespace {

std::string demangleName(StringRef n) {
  std::string d = demangle(n.str());
  return d.empty() ? n.str() : d;
}

json::Object loc(const DebugLoc &dl) {
  json::Object o;
  if (dl) {
    o["file"] = dl->getFilename().str();
    o["dir"] = dl->getDirectory().str();
    o["line"] = (int64_t)dl.getLine();
    o["col"] = (int64_t)dl.getCol();
  }
  return o;
}

json::Object gloc(const GlobalVariable &gv) {
  json::Object o;
  SmallVector<DIGlobalVariableExpression *, 1> dbg;
  gv.getDebugInfo(dbg);
  if (!dbg.empty()) {
    auto *v = dbg[0]->getVariable();
    o["file"] = v->getFilename().str();
    o["dir"] = v->getDirectory().str();
    o["line"] = (int64_t)v->getLine();
  }
  return o;
}

/** Does value v depend (through a bounded number of instruction hops) on a function argument? */
bool dependsOnArg(const Value *v, std::set<const Value *> &seen, int depth, std::string &via) {
  if (!v || depth > 12 || !seen.insert(v).second) return false;
  if (auto *a = dyn_cast<Argument>(v)) { via = "arg" + std::to_string(a->getArgNo()); return true; }
  if (auto *ld = dyn_cast<LoadInst>(v)) {
    // a load: follow the pointer (this->field, or a local that an argument was stored into)
    if (dependsOnArg(ld->getPointerOperand(), seen, depth + 1, via)) return true;
    // stores into that local within the same function
    for (const User *u : ld->getPointerOperand()->users())
      if (auto *st = dyn_cast<StoreInst>(u))
        if (st->getPointerOperand() == ld->getPointerOperand() && dependsOnArg(st->getValueOperand(), seen, depth + 1, via)) return true;
    return false;
  }
  if (auto *i = dyn_cast<Instruction>(v))
    for (const Use &op : i->operands())
      if (dependsOnArg(op.get(), seen, depth + 1, via)) return true;
  return false;
}

/** Innermost struct + field addressed by a GEP: walks the index chain (derived-class GEPs
    address a base subobject then the field in ONE instruction: `vector, this, 0, 0, 0`).
    Returns false if the GEP does not end in a constant struct field index. */
bool structField(const GetElementPtrInst *g, std::string &sname, int64_t &field) {
  bool found = false;
  for (gep_type_iterator it = gep_type_begin(g), e = gep_type_end(g); it != e; ++it) {
    if (StructType *st = it.getStructTypeOrNull()) {
      if (auto *ci = dyn_cast<ConstantInt>(it.getOperand())) { sname = st->hasName() ? st->getName().str() : "?"; field = ci->getSExtValue(); found = true; }
      else return false;
    }
  }
  return found;
}

/** Class name of the method being analysed (set per function). Used as the struct identity for
    accesses through `this`: with opaque pointers, a field-0 access is a bare `load ptr, %this`
    with NO getelementptr, so there is no struct type in the IR to read (EASTL vector::mpBegin,
    2026-09-16). The demangled name is the same for every method of the class, so operator[]'s
    mpBegin and size()'s mpEnd key on the same identity. */
static std::string gThisClass;
static const Argument *gThisArg = nullptr;

std::string classOfMethod(const Function &F) {
  std::string d = demangleName(F.getName());
  size_t paren = d.find('(');                  // strip parameter list
  if (paren == std::string::npos) return "";
  std::string q = d.substr(0, paren);
  size_t sp = q.rfind(' ');                    // strip return type ("void ", "int ")
  if (sp != std::string::npos && q.find('<', sp) == std::string::npos) q = q.substr(sp + 1);
  // last "::" at template depth 0 separates class from member
  int depth = 0; size_t cut = std::string::npos;
  for (size_t i = 0; i < q.size(); ++i) {
    if (q[i] == '<') depth++; else if (q[i] == '>') depth--;
    else if (depth == 0 && q[i] == ':' && i + 1 < q.size() && q[i + 1] == ':') cut = i;
  }
  return cut == std::string::npos ? "" : q.substr(0, cut);
}

/** Resolve a pointer to `this` through -O0 spill slots. */
bool isThis(const Value *p) {
  p = p->stripPointerCasts();
  for (int i = 0; i < 4; ++i) {
    if (p == gThisArg) return true;
    if (auto *ld = dyn_cast<LoadInst>(p)) {
      const Value *slot = ld->getPointerOperand()->stripPointerCasts(); const Value *stored = nullptr;
      for (const User *u : slot->users()) if (auto *st = dyn_cast<StoreInst>(u)) if (st->getPointerOperand() == slot) { stored = st->getValueOperand()->stripPointerCasts(); break; }
      if (!stored) return false;
      p = stored; continue;
    }
    return false;
  }
  return false;
}

/** (struct, field) addressed by pointer `addr` (the pointer operand of a load/store):
    a GEP -> innermost struct + field (through inheritance chains); if the GEP's base is `this`,
    the class name is used as identity. A bare `this` -> (class, 0). */
bool fieldOfAddress(const Value *addr, std::string &sname, int64_t &field) {
  const Value *a = addr->stripPointerCasts();
  if (auto *g = dyn_cast<GetElementPtrInst>(a)) {
    if (!structField(g, sname, field)) return false;
    if (!gThisClass.empty() && isThis(g->getPointerOperand())) sname = gThisClass;
    return true;
  }
  if (!gThisClass.empty() && isThis(a)) { sname = gThisClass; field = 0; return true; }
  return false;
}

/** Field loads a value depends on: walks operands (bounded), collecting (struct, field-index)
    for every `load (gep %struct, 0, N)` reached. Used to relate an index to a bound field. */
static std::map<const Function *, std::set<std::pair<std::string,int64_t>>> gGetterDeps;   // fn -> fields its return derives from

void fieldDeps(const Value *v, std::set<std::pair<std::string,int64_t>> &out, std::set<const Value *> &seen, int depth) {
  if (!v || depth > 10 || !seen.insert(v).second) return;
  // At -O0 nothing is inlined: `i < v.size()` compares against a CALL, not a field load.
  // Getter summary: size()/end()/capacity() return values derived from fields (EASTL, 2026-09-15:
  // VectorBase 0/123 bounded before this).
  if (auto *cb = dyn_cast<CallBase>(v)) {
    if (const Function *cf = cb->getCalledFunction()) { auto it = gGetterDeps.find(cf); if (it != gGetterDeps.end()) out.insert(it->second.begin(), it->second.end()); }
    for (const Use &op : cb->args()) fieldDeps(op.get(), out, seen, depth + 1);
    return;
  }
  if (auto *ld = dyn_cast<LoadInst>(v)) {
    const Value *p = ld->getPointerOperand()->stripPointerCasts();
    { std::string sn; int64_t fi; if (fieldOfAddress(p, sn, fi)) out.insert({sn, fi}); }
    fieldDeps(p, out, seen, depth + 1);
    // through a spill slot: the value stored there
    for (const User *u : p->users()) if (auto *st = dyn_cast<StoreInst>(u)) if (st->getPointerOperand() == p) fieldDeps(st->getValueOperand(), out, seen, depth + 1);
    return;
  }
  if (auto *i = dyn_cast<Instruction>(v)) for (const Use &op : i->operands()) fieldDeps(op.get(), out, seen, depth + 1);
}

/** If ptr is a load of a struct field (possibly through a spill slot), return (struct, field). */
bool loadedFromField(const Value *ptr, std::string &sname, int64_t &field) {
  const Value *p = ptr->stripPointerCasts();
  for (int i = 0; i < 4; ++i) {
    if (auto *ld = dyn_cast<LoadInst>(p)) {
      const Value *src = ld->getPointerOperand()->stripPointerCasts();
      if (fieldOfAddress(src, sname, field)) return true;
      // spill slot: follow the store into it
      const Value *stored = nullptr;
      for (const User *u : src->users()) if (auto *st = dyn_cast<StoreInst>(u)) if (st->getPointerOperand() == src) { stored = st->getValueOperand()->stripPointerCasts(); break; }
      if (!stored) return false;
      p = stored; continue;
    }
    return false;
  }
  return false;
}

/** If idx is an integer parameter (through zext/sext/trunc or a -O0 spill slot), return its
    number, else -1. Deliberately NOT "depends on an argument": a loop counter bounded by a
    member depends on `this`, and treating `this` as the index parameter sent the call-site
    check after the wrong value (EASTL FindSwitch, 2026-09-15). */
int indexParam(const Value *v) {
  for (int i = 0; i < 6 && v; ++i) {
    if (auto *a = dyn_cast<Argument>(v)) return a->getType()->isIntegerTy() ? (int)a->getArgNo() : -1;
    if (auto *c = dyn_cast<CastInst>(v)) { v = c->getOperand(0); continue; }
    if (auto *ld = dyn_cast<LoadInst>(v)) {
      const Value *slot = ld->getPointerOperand()->stripPointerCasts(); const Value *stored = nullptr;
      for (const User *u : slot->users()) if (auto *st = dyn_cast<StoreInst>(u)) if (st->getPointerOperand() == slot) { stored = st->getValueOperand(); break; }
      v = stored; continue;
    }
    return -1;
  }
  return -1;
}

std::string constOrExpr(const Value *v, bool &isConst, int64_t &cval) {
  isConst = false;
  if (auto *c = dyn_cast<ConstantInt>(v)) { isConst = true; cval = c->getSExtValue(); return std::to_string(cval); }
  std::string s; raw_string_ostream os(s); v->print(os, true); return os.str();
}

/** Describe the base of a pointer: global (name, elems), alloca (elems), argument, or other. */
json::Object describeBase(const Value *ptr, const DataLayout &DL) {
  json::Object o;
  const Value *base = ptr->stripPointerCasts();
  // walk simple GEP/load chains to the underlying object
  for (int i = 0; i < 6; ++i) {
    if (auto *gep = dyn_cast<GetElementPtrInst>(base)) { base = gep->getPointerOperand()->stripPointerCasts(); continue; }
    if (auto *ld = dyn_cast<LoadInst>(base)) {
      // -O0 spills pointers to allocas: `%this.addr`, `%buf.addr`. The loaded pointer's
      // object is whatever was stored into that slot, not the slot itself.
      o["via_load"] = true;
      const Value *slot = ld->getPointerOperand()->stripPointerCasts();
      const Value *stored = nullptr;
      for (const User *u : slot->users())
        if (auto *st = dyn_cast<StoreInst>(u)) if (st->getPointerOperand() == slot) { stored = st->getValueOperand()->stripPointerCasts(); break; }
      if (stored) { base = stored; continue; }
      base = slot; continue;
    }
    break;
  }
  if (auto *gv = dyn_cast<GlobalVariable>(base)) {
    o["kind"] = "global"; o["name"] = gv->getName().str(); o["demangled"] = demangleName(gv->getName());
    if (auto *at = dyn_cast<ArrayType>(gv->getValueType())) {
      o["elements"] = (int64_t)at->getNumElements();
      o["element_bytes"] = (int64_t)DL.getTypeAllocSize(at->getElementType());
    }
    o["is_constant"] = gv->isConstant();
  } else if (auto *al = dyn_cast<AllocaInst>(base)) {
    o["kind"] = "alloca";
    if (auto *at = dyn_cast<ArrayType>(al->getAllocatedType())) {
      o["elements"] = (int64_t)at->getNumElements();
      o["element_bytes"] = (int64_t)DL.getTypeAllocSize(at->getElementType());
    } else o["bytes"] = (int64_t)DL.getTypeAllocSize(al->getAllocatedType());
  } else if (auto *a = dyn_cast<Argument>(base)) {
    o["kind"] = "argument"; o["arg"] = (int64_t)a->getArgNo();
  } else if (isa<CallBase>(base)) {
    o["kind"] = "heap_or_call";
    if (auto *cb = dyn_cast<CallBase>(base))
      if (auto *f = cb->getCalledFunction()) o["allocator"] = demangleName(f->getName());
  } else o["kind"] = "other";
  return o;
}

} // namespace

int main(int argc, char **argv) {
  cl::ParseCommandLineOptions(argc, argv, "ir-facts: dump verification facts from bitcode\n");
  LLVMContext ctx; SMDiagnostic err;
  std::unique_ptr<Module> M = parseIRFile(Input, err, ctx);
  if (!M) { err.print(argv[0], errs()); return 1; }
  const DataLayout &DL = M->getDataLayout();

  json::Array globals, ctorStores, geps, sizeCalls, allocas, fieldGeps;
  std::map<std::string, std::map<std::string, int>> pairVotes;   // struct -> "P:N" -> count

  for (const GlobalVariable &gv : M->globals()) {
    auto *at = dyn_cast<ArrayType>(gv.getValueType());
    if (!at) continue;
    json::Object o;
    o["name"] = gv.getName().str(); o["demangled"] = demangleName(gv.getName());
    o["elements"] = (int64_t)at->getNumElements();
    o["element_bytes"] = (int64_t)DL.getTypeAllocSize(at->getElementType());
    o["bytes"] = (int64_t)DL.getTypeAllocSize(at);
    o["is_constant"] = gv.isConstant(); o["has_initializer"] = gv.hasInitializer();
    o["loc"] = gloc(gv);
    globals.push_back(std::move(o));
  }

  for (int round = 0; round < 2; ++round)
    for (const Function &F : *M) {
      if (F.isDeclaration() || F.getReturnType()->isVoidTy()) continue;
      gThisClass = classOfMethod(F); gThisArg = (F.arg_size() && F.getArg(0)->getType()->isPointerTy() && !gThisClass.empty()) ? F.getArg(0) : nullptr;
      std::set<std::pair<std::string,int64_t>> deps;
      for (const BasicBlock &BB : F) if (auto *ret = dyn_cast<ReturnInst>(BB.getTerminator())) {
        std::set<const Value *> seen; fieldDeps(ret->getReturnValue(), deps, seen, 0);
      }
      if (!deps.empty()) gGetterDeps[&F] = deps;
    }
  // comparisons per function, with the field loads each depends on and the values it touches
  struct Cmp { const ICmpInst *I; std::set<std::pair<std::string,int64_t>> deps; std::set<const Value *> vals; };
  std::map<const Function *, std::vector<Cmp>> fnCmps;
  for (const Function &F : *M) {
    if (F.isDeclaration()) continue;
    gThisClass = classOfMethod(F); gThisArg = (F.arg_size() && F.getArg(0)->getType()->isPointerTy() && !gThisClass.empty()) ? F.getArg(0) : nullptr;
    for (const BasicBlock &BB : F) for (const Instruction &I : BB)
      if (auto *ic = dyn_cast<ICmpInst>(&I)) {
        Cmp c; c.I = ic; std::set<const Value *> seen;
        for (const Use &op : ic->operands()) fieldDeps(op.get(), c.deps, seen, 0);
        c.vals = seen; fnCmps[&F].push_back(std::move(c));
      }
  }
  auto boundedIn = [&](const Function *fn, const Value *val, const std::string &sname, int64_t pf, json::Array *fields) {
    bool any = false;
    for (const Cmp &c : fnCmps[fn]) {
      if (!c.vals.count(val)) continue;
      for (auto &d : c.deps) if (d.first == sname && d.second != pf) { any = true; if (fields) fields->push_back(json::Object{{"field", d.second}}); }
    }
    return any;
  };

  for (const Function &F : *M) {
    if (F.isDeclaration()) continue;
    const std::string fname = F.getName().str(), fdem = demangleName(F.getName());
    gThisClass = classOfMethod(F); gThisArg = (F.arg_size() && F.getArg(0)->getType()->isPointerTy() && !gThisClass.empty()) ? F.getArg(0) : nullptr;
    // constructors: MSVC mangling `??0Class@@...`; Itanium `_ZN...C1E...`/`C2E...` (complete/base object ctor)
    const bool isCtor = fname.rfind("??0", 0) == 0 ||
                        (fname.rfind("_ZN", 0) == 0 && (fname.find("C1E") != std::string::npos || fname.find("C2E") != std::string::npos));
    // GEPs through a pointer loaded from a struct field: is the index/result compared against
    // another field of the same struct — here, or (if the index is a parameter) at the call sites?
    for (const BasicBlock &BB : F) for (const Instruction &I : BB) {
      auto *gep = dyn_cast<GetElementPtrInst>(&I);
      if (!gep || gep->hasAllConstantIndices()) continue;
      std::string sname; int64_t pf;
      if (!loadedFromField(gep->getPointerOperand(), sname, pf)) continue;
      if (sname.find("__va_list_tag") != std::string::npos) continue;
      const Value *idx = nullptr;
      for (const Use &u : gep->indices()) if (!isa<ConstantInt>(u.get())) { idx = u.get(); break; }
      json::Object o; o["function"] = fname; o["demangled"] = fdem; o["struct"] = sname; o["ptr_field"] = pf; o["loc"] = loc(I.getDebugLoc());
      json::Array bounds;
      bool here = boundedIn(&F, idx, sname, pf, &bounds); here = boundedIn(&F, gep, sname, pf, &bounds) || here;
      for (auto &b : bounds) pairVotes[sname][std::to_string(pf) + ":" + std::to_string(*b.getAsObject()->getInteger("field"))]++;
      o["bounded_by_fields"] = std::move(bounds);
      std::set<const Value *> seen1; std::string via; o["index_depends_on_arg"] = dependsOnArg(idx, seen1, 0, via);
      if (auto *z = dyn_cast_or_null<ZExtInst>(idx)) o["index_zext_from_bits"] = (int64_t)z->getSrcTy()->getIntegerBitWidth();
      // interprocedural: index comes from parameter argN (operator[](n) is not inlined at -O0; the
      // check `i < v.size()` is in the CALLER). Examine every call site of this function.
      int ip = indexParam(idx);
      if (!here && ip >= 0) {
        unsigned argNo = (unsigned)ip;
        o["index_arg"] = (int64_t)argNo;
        json::Array sites; int nb = 0, nu = 0;
        for (const User *u : F.users()) {
          auto *cb = dyn_cast<CallBase>(u);
          if (!cb || cb->getCalledFunction() != &F || argNo >= cb->arg_size()) continue;
          const Function *caller = cb->getFunction();
          const Value *actual = cb->getArgOperand(argNo);
          json::Array cf;
          bool b = boundedIn(caller, actual, sname, pf, &cf);
          if (!b) {   // the argument may be a load/zext of a local that is compared elsewhere in the caller
            std::set<const Value *> seen2; std::string via2; (void)dependsOnArg(actual, seen2, 0, via2);
            for (const Value *v : seen2) if (v != actual && boundedIn(caller, v, sname, pf, &cf)) { b = true; break; }
          }
          b ? ++nb : ++nu;
          if (!b || sites.size() < 8)
            sites.push_back(json::Object{{"caller", demangleName(caller->getName())}, {"loc", loc(cb->getDebugLoc())}, {"bounded", b}});
        }
        o["callsites_bounded"] = (int64_t)nb; o["callsites_unbounded"] = (int64_t)nu; o["callsites"] = std::move(sites);
      }
      fieldGeps.push_back(std::move(o));
    }
    for (const BasicBlock &BB : F) for (const Instruction &I : BB) {
      if (isCtor) if (auto *st = dyn_cast<StoreInst>(&I)) if (auto *c = dyn_cast<ConstantInt>(st->getValueOperand())) {
        // store <const> through a GEP on `this` (arg 0)
        const Value *p = st->getPointerOperand()->stripPointerCasts();
        const GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(p);
        const Value *base = gep ? gep->getPointerOperand()->stripPointerCasts() : p;
        // -O0: `this` is loaded from its spill slot; resolve load -> slot -> stored argument
        if (auto *ld = dyn_cast<LoadInst>(base)) {
          const Value *slot = ld->getPointerOperand()->stripPointerCasts();
          for (const User *u : slot->users())
            if (auto *s2 = dyn_cast<StoreInst>(u)) if (s2->getPointerOperand() == slot) { base = s2->getValueOperand()->stripPointerCasts(); break; }
        }
        if (auto *a = dyn_cast<Argument>(base); a && a->getArgNo() == 0 && F.arg_size() > 0) {
          json::Object o; o["function"] = fname; o["demangled"] = fdem; o["value"] = c->getSExtValue();
          o["bits"] = (int64_t)c->getBitWidth();
          if (gep && gep->getNumIndices() >= 2)
            if (auto *fi = dyn_cast<ConstantInt>(gep->getOperand(gep->getNumOperands() - 1))) o["field_index"] = fi->getSExtValue();
          if (gep) if (auto *sty = dyn_cast<StructType>(gep->getSourceElementType())) o["struct"] = sty->getName().str();
          o["loc"] = loc(I.getDebugLoc());
          ctorStores.push_back(std::move(o));
        }
      }
      if (auto *gep = dyn_cast<GetElementPtrInst>(&I)) {
        if (gep->hasAllConstantIndices()) continue;
        json::Object o; o["function"] = fname; o["demangled"] = fdem; o["loc"] = loc(I.getDebugLoc());
        o["base"] = describeBase(gep->getPointerOperand(), DL);
        if (auto *at = dyn_cast<ArrayType>(gep->getSourceElementType())) o["source_elements"] = (int64_t)at->getNumElements();
        json::Array idxs;
        for (const Use &u : gep->indices()) {
          if (isa<ConstantInt>(u.get())) continue;
          json::Object ix; const Value *v = u.get();
          ix["bits"] = (int64_t)v->getType()->getIntegerBitWidth();
          if (auto *z = dyn_cast<ZExtInst>(v)) { ix["zext_from_bits"] = (int64_t)z->getSrcTy()->getIntegerBitWidth(); ix["unsigned_bounded"] = true; }
          if (auto *s = dyn_cast<SExtInst>(v)) ix["sext_from_bits"] = (int64_t)s->getSrcTy()->getIntegerBitWidth();
          std::set<const Value *> seen; std::string via;
          ix["depends_on_arg"] = dependsOnArg(v, seen, 0, via); if (!via.empty()) ix["via"] = via;
          std::string s; raw_string_ostream os(s); v->print(os, true); ix["expr"] = os.str();
          idxs.push_back(std::move(ix));
        }
        o["indices"] = std::move(idxs);
        geps.push_back(std::move(o));
      }
      if (auto *cb = dyn_cast<CallBase>(&I)) {
        const Function *callee = cb->getCalledFunction();
        if (!callee) continue;
        const StringRef cn = callee->getName();
        int sizeArg = -1; std::string kind;
        if (isa<MemIntrinsic>(cb)) { sizeArg = 2; kind = cn.starts_with("llvm.memset") ? "memset" : "memcpy"; }
        else if (cn == "??_U@YAPEAX_K@Z" || cn == "??2@YAPEAX_K@Z") { sizeArg = 0; kind = cn == "??_U@YAPEAX_K@Z" ? "new[]" : "new"; }
        else if (cn == "malloc" || cn == "HeapAlloc") { sizeArg = cn == "HeapAlloc" ? 2 : 0; kind = cn.str(); }
        else if (cn.starts_with("??0?$basic_string@") && cb->arg_size() >= 3 && cb->getArgOperand(2)->getType()->isIntegerTy()) { sizeArg = 2; kind = "basic_string(ptr,n)"; }
        else if (cn == "strncpy" || cn == "wcsncpy" || cn == "memcmp" || cn == "strncmp") { sizeArg = 2; kind = cn.str(); }
        if (sizeArg < 0 || (unsigned)sizeArg >= cb->arg_size()) continue;
        json::Object o; o["function"] = fname; o["demangled"] = fdem; o["kind"] = kind; o["callee"] = cn.str(); o["loc"] = loc(I.getDebugLoc());
        bool isC; int64_t cv; const Value *sz = cb->getArgOperand(sizeArg);
        o["size_expr"] = constOrExpr(sz, isC, cv); o["size_is_constant"] = isC; if (isC) o["size"] = cv;
        std::set<const Value *> seen; std::string via;
        o["size_depends_on_arg"] = dependsOnArg(sz, seen, 0, via); if (!via.empty()) o["size_via"] = via;
        if (kind == "memcpy" || kind == "memset" || kind == "strncpy" || kind == "wcsncpy") o["dst"] = describeBase(cb->getArgOperand(0), DL);
        if (kind == "memcpy" || kind == "basic_string(ptr,n)" || kind == "memcmp" || kind == "strncmp") o["src"] = describeBase(cb->getArgOperand(1), DL);
        sizeCalls.push_back(std::move(o));
      }
      if (auto *al = dyn_cast<AllocaInst>(&I)) {
        auto *at = dyn_cast<ArrayType>(al->getAllocatedType());
        if (!at) continue;
        json::Object o; o["function"] = fname; o["demangled"] = fdem; o["elements"] = (int64_t)at->getNumElements();
        o["element_bytes"] = (int64_t)DL.getTypeAllocSize(at->getElementType()); o["loc"] = loc(I.getDebugLoc());
        allocas.push_back(std::move(o));
      }
    }
  }

  json::Object root;
  root["module"] = Input; root["globals"] = std::move(globals); root["ctor_stores"] = std::move(ctorStores);
  root["geps"] = std::move(geps); root["size_calls"] = std::move(sizeCalls); root["allocas"] = std::move(allocas);
  root["field_geps"] = std::move(fieldGeps);
  // data+size pair table: per struct, which (ptr field -> bound field) pairs the code itself uses in checks
  json::Object pairs;
  for (auto &[st, votes] : pairVotes) { json::Object v; for (auto &[k, n] : votes) v[k] = (int64_t)n; pairs[st] = std::move(v); }
  root["field_pairs"] = std::move(pairs);
  std::error_code ec; raw_fd_ostream out(Output, ec);
  if (ec) { errs() << "cannot write " << Output << ": " << ec.message() << "\n"; return 1; }
  out << json::Value(std::move(root)) << "\n";
  errs() << "ir-facts -> " << Output << "\n";
  return 0;
}
