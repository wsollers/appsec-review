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
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

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

  json::Array globals, ctorStores, geps, sizeCalls, allocas;

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

  for (const Function &F : *M) {
    if (F.isDeclaration()) continue;
    const std::string fname = F.getName().str(), fdem = demangleName(F.getName());
    const bool isCtor = fname.rfind("??0", 0) == 0;
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
  std::error_code ec; raw_fd_ostream out(Output, ec);
  if (ec) { errs() << "cannot write " << Output << ": " << ec.message() << "\n"; return 1; }
  out << json::Value(std::move(root)) << "\n";
  errs() << "ir-facts -> " << Output << "\n";
  return 0;
}
