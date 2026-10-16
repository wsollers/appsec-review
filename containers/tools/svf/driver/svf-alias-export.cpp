// svf-alias-export: bounded points-to and indirect-call export for one linked LLVM module.
//
// Repository-owned driver for the tool-svf image (appsec-review). It runs SVF's field-sensitive
// AndersenWaveDiff analysis over one module and writes one JSON document
// (appsec-review/svf-alias-output/1) with:
//   * pointer sites: dereferenced pointers (loads and stores whose address is not a direct local or
//     global), pointer arguments of direct calls, and pointer comparisons, each located by its
//     DILocation and carrying a bounded points-to set of abstract-object keys;
//   * abstract objects: allocation site location, kind and field index, keyed per module;
//   * indirect calls: located call instructions and their resolved target names;
//   * open-world reasons: dynamic loading, pointer inline assembly, and external functions with
//     pointer effects that neither SVF's ExtAPI models nor the driver's non-capturing list covers.
// Every bound that is reached is reported; nothing is silently dropped.
//
// Usage: svf-alias-export <request.json>
//   request: {"module": path, "output": path, "extapi": path,
//             "bounds": {"field_limit", "max_sites", "max_pts_size", "max_indirect_calls",
//                        "max_targets_per_call", "max_unmodeled_names", "andersen_time_limit_seconds"}}
// Andersen's own time limit exits the process with status 101 (SVFUtil::timeLimitReached).

#include "SVF-LLVM/LLVMModule.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/CommandLine.h"
#include "Util/Options.h"
#include "WPA/Andersen.h"

#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugProgramInstruction.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace llvm;
using namespace SVF;

namespace {

constexpr const char* kSchema = "appsec-review/svf-alias-output/1";
constexpr const char* kDriver = "svf-alias-export/1";

struct Bounds {
    int64_t fieldLimit = 64;
    int64_t maxSites = 20000;
    int64_t maxPts = 256;
    int64_t maxIndirect = 20000;
    int64_t maxTargets = 64;
    int64_t maxUnmodeled = 64;
    int64_t anderTimeLimit = 900;
};

struct Loc {
    std::string file;
    unsigned line = 0;
    unsigned column = 0;
    bool valid() const { return !file.empty() && line > 0; }
};

// External functions whose pointer arguments cannot create an alias SVF fails to see: deallocation,
// formatted output and read-only string/memory inspection. A call to any other unmodeled external
// with a pointer argument or result makes the module open-world.
const std::set<std::string>& nonCapturing() {
    static const std::set<std::string> names = {
        "_ZdlPv", "_ZdlPvm", "_ZdaPv", "_ZdaPvm", "_ZdlPvSt11align_val_t", "_ZdaPvSt11align_val_t",
        "_ZdlPvmSt11align_val_t", "_ZdaPvmSt11align_val_t", "free", "printf", "fprintf", "puts",
        "fputs", "perror", "strlen", "strnlen", "strcmp", "strncmp", "memcmp", "abort", "exit",
        "_exit", "__assert_fail", "__stack_chk_fail", "pthread_mutex_lock", "pthread_mutex_unlock",
        "pthread_mutex_trylock", "pthread_mutex_destroy", "pthread_mutex_clocklock", "atoi", "atol", "atoll",
        "atof", "__cxa_free_exception",
        "__cxa_pure_virtual", "__gxx_personality_v0", "__cxa_begin_catch", "__cxa_end_catch",
        "_ZSt9terminatev", "__clang_call_terminate", "_ZSt20__throw_length_errorPKc",
        "_ZSt17__throw_bad_allocv", "_ZSt28__throw_bad_array_new_lengthv",
        "_ZSt24__throw_out_of_range_fmtPKcz", "_ZSt19__throw_logic_errorPKc",
    };
    return names;
}

const std::set<std::string>& dynamicLoaders() {
    static const std::set<std::string> names = {
        "dlopen", "dlmopen", "dlsym", "dlvsym", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
        "LoadLibraryExW", "GetProcAddress",
    };
    return names;
}

std::string joinPath(StringRef directory, StringRef file) {
    if (file.empty()) return "";
    if (file.starts_with("/") || directory.empty()) return file.str();
    return (directory + "/" + file).str();
}

Loc locationOf(const DILocation* location) {
    Loc result;
    if (!location) return result;
    while (const DILocation* outer = location->getInlinedAt()) location = outer;
    result.file = joinPath(location->getDirectory(), location->getFilename());
    result.line = location->getLine();
    result.column = location->getColumn();
    return result;
}

Loc locationOf(const Instruction& instruction) {
    return locationOf(instruction.getDebugLoc().get());
}

json::Object locJson(const Loc& loc) {
    return json::Object{{"file", loc.file}, {"line", static_cast<int64_t>(loc.line)},
                        {"column", static_cast<int64_t>(loc.column)}};
}

std::string functionName(const Function* function) {
    if (!function) return "";
    if (const DISubprogram* subprogram = function->getSubprogram()) {
        StringRef linkage = subprogram->getLinkageName();
        if (!linkage.empty()) return linkage.str();
    }
    return function->getName().str();
}

std::set<std::string> loadExtApiNames(const std::string& path) {
    std::set<std::string> names;
    LLVMContext context;
    SMDiagnostic error;
    std::unique_ptr<Module> module = parseIRFile(path, error, context);
    if (!module) return names;
    for (const Function& function : *module)
        if (!function.isDeclaration()) names.insert(function.getName().str());
    return names;
}

bool hasPointerEffect(const CallBase& call) {
    if (call.getType()->isPointerTy()) return true;
    for (const Use& argument : call.args())
        if (argument->getType()->isPointerTy()) return true;
    return false;
}

bool isDebugOrMarker(const Function* callee) {
    if (!callee || !callee->isIntrinsic()) return false;
    switch (callee->getIntrinsicID()) {
    case Intrinsic::lifetime_start:
    case Intrinsic::lifetime_end:
    case Intrinsic::dbg_declare:
    case Intrinsic::dbg_value:
    case Intrinsic::dbg_label:
    case Intrinsic::invariant_start:
    case Intrinsic::invariant_end:
        return true;
    default:
        return false;
    }
}

class Exporter {
public:
    Exporter(PointerAnalysis* pta, SVFIR* pag, const Bounds& bounds, const std::set<std::string>& extApi,
             const std::string& extApiPath)
        : pta_(pta), pag_(pag), bounds_(bounds), extApi_(extApi), extApiPath_(extApiPath),
          lms_(LLVMModuleSet::getLLVMModuleSet()) {
        for (const auto& entry : lms_->objSyms()) objectValues_[entry.second] = entry.first;
    }

    json::Object run() {
        collectDeclares();
        for (Module& module : lms_->getLLVMModules()) {
            if (isExtApiModule(module)) continue;
            for (Function& function : module) {
                if (function.isDeclaration()) continue;
                ++definedFunctions_;
                for (BasicBlock& block : function)
                    for (Instruction& instruction : block) visit(function, instruction);
            }
        }
        json::Array openWorld;
        if (dynamicLoading_) openWorld.push_back("dynamic_loading");
        if (pointerInlineAsm_) openWorld.push_back("pointer_inline_asm");
        if (!unmodeled_.empty()) openWorld.push_back("unmodeled_external_functions");
        json::Array unmodeled;
        int64_t count = 0;
        for (const std::string& name : unmodeled_) {
            if (count++ >= bounds_.maxUnmodeled) break;
            unmodeled.push_back(name);
        }
        json::Object objects;
        for (const auto& entry : objects_) objects[entry.first] = json::Value(json::Object(entry.second));
        return json::Object{
            {"schema", kSchema},
            {"driver", kDriver},
            {"llvm_version", LLVM_VERSION_STRING},
            {"module", json::Object{
                {"defined_functions", definedFunctions_},
                {"pointer_sites", static_cast<int64_t>(sites_.size())},
                {"abstract_objects", static_cast<int64_t>(objects_.size())},
                {"open_world_reasons", std::move(openWorld)},
                {"unmodeled_externals", std::move(unmodeled)},
                {"unmodeled_external_count", static_cast<int64_t>(unmodeled_.size())},
            }},
            {"andersen", json::Object{{"completed", true}}},
            {"sites", std::move(sites_)},
            {"sites_truncated", sitesTruncated_},
            {"objects", std::move(objects)},
            {"indirect_calls", std::move(indirect_)},
            {"indirect_calls_truncated", indirectTruncated_},
        };
    }

private:
    bool isExtApiModule(const Module& module) const {
        StringRef identifier = module.getModuleIdentifier();
        return identifier == extApiPath_ || identifier.ends_with("extapi.bc");
    }

    // dbg.declare records name each stack object's source variable and declaration line.
    void collectDeclares() {
        for (Module& module : lms_->getLLVMModules()) {
            if (isExtApiModule(module)) continue;
            for (Function& function : module)
                for (BasicBlock& block : function)
                    for (Instruction& instruction : block)
                        for (DbgVariableRecord& record : filterDbgVars(instruction.getDbgRecordRange())) {
                            if (!record.isDbgDeclare()) continue;
                            const Value* address = record.getVariableLocationOp(0);
                            const DILocalVariable* variable = record.getVariable();
                            if (!address || !variable || declares_.count(address)) continue;
                            Loc loc;
                            loc.file = joinPath(variable->getDirectory(), variable->getFilename());
                            loc.line = variable->getLine();
                            declares_[address] = {loc, variable->getName().str()};
                        }
        }
    }

    void visit(Function& function, Instruction& instruction) {
        if (auto* call = dyn_cast<CallBase>(&instruction)) {
            visitCall(function, *call);
            return;
        }
        if (auto* load = dyn_cast<LoadInst>(&instruction)) {
            if (isDereference(load->getPointerOperand()))
                addSite(function, instruction, load->getPointerOperand(), "load", -1, "");
            return;
        }
        if (auto* store = dyn_cast<StoreInst>(&instruction)) {
            if (isDereference(store->getPointerOperand()))
                addSite(function, instruction, store->getPointerOperand(), "store", -1, "");
            return;
        }
        if (auto* compare = dyn_cast<ICmpInst>(&instruction)) {
            if (compare->getOperand(0)->getType()->isPointerTy()) {
                addSite(function, instruction, compare->getOperand(0), "compare", 0, "");
                addSite(function, instruction, compare->getOperand(1), "compare", 1, "");
            }
        }
    }

    // Direct local and global accesses resolve trivially; only dereferenced pointers carry
    // aliasing information worth exporting.
    static bool isDereference(const Value* pointer) {
        const Value* stripped = pointer->stripPointerCasts();
        return !isa<AllocaInst>(stripped) && !isa<GlobalVariable>(stripped);
    }

    void visitCall(Function& function, CallBase& call) {
        const Value* calledOperand = call.getCalledOperand();
        if (call.isInlineAsm()) {
            if (hasPointerEffect(call)) pointerInlineAsm_ = true;
            return;
        }
        const auto* callee = dyn_cast<Function>(calledOperand->stripPointerCasts());
        if (!callee) {
            addIndirectCall(function, call);
            return;
        }
        if (isDebugOrMarker(callee)) return;
        std::string name = callee->getName().str();
        if (dynamicLoaders().count(name)) dynamicLoading_ = true;
        if (callee->isDeclaration() && !callee->isIntrinsic() && hasPointerEffect(call) &&
            !extApi_.count(name) && !nonCapturing().count(name))
            unmodeled_.insert(name);
        for (unsigned index = 0; index < call.arg_size(); ++index) {
            const Value* argument = call.getArgOperand(index);
            if (argument->getType()->isPointerTy() && !isa<ConstantPointerNull>(argument))
                addSite(function, call, argument, "call_arg", static_cast<int>(index), name);
        }
    }

    void addIndirectCall(Function& function, CallBase& call) {
        Loc loc = locationOf(call);
        if (!loc.valid()) return;
        if (static_cast<int64_t>(indirect_.size()) >= bounds_.maxIndirect) {
            indirectTruncated_ = true;
            return;
        }
        json::Array targets;
        bool truncated = false;
        std::vector<std::string> names;
        const CallICFGNode* node = lms_->getCallICFGNode(&call);
        if (node) {
            auto& map = pta_->getIndCallMap();
            auto found = map.find(node);
            if (found != map.end())
                for (const FunObjVar* target : found->second) names.push_back(target->getName());
        }
        std::sort(names.begin(), names.end());
        names.erase(std::unique(names.begin(), names.end()), names.end());
        for (const std::string& name : names) {
            if (static_cast<int64_t>(targets.size()) >= bounds_.maxTargets) {
                truncated = true;
                break;
            }
            targets.push_back(json::Object{{"name", name}, {"demangled", llvm::demangle(name)}});
        }
        json::Object record = locJson(loc);
        record["function"] = functionName(&function);
        record["function_demangled"] = llvm::demangle(functionName(&function));
        record["targets"] = std::move(targets);
        record["target_count"] = static_cast<int64_t>(names.size());
        record["truncated"] = truncated;
        indirect_.push_back(std::move(record));
    }

    void addSite(Function& function, Instruction& instruction, const Value* pointer, const char* role,
                 int operand, const std::string& callee) {
        Loc loc = locationOf(instruction);
        if (!loc.valid()) return;
        if (static_cast<int64_t>(sites_.size()) >= bounds_.maxSites) {
            sitesTruncated_ = true;
            return;
        }
        json::Array incomplete;
        json::Array pts;
        bool truncated = false;
        if (!lms_->hasValueNode(pointer)) {
            incomplete.push_back("pointer_not_modeled");
        } else {
            NodeID id = lms_->getValueNode(pointer);
            const PointsTo& set = pta_->getPts(id);
            std::vector<std::string> keys;
            for (NodeID object : set) {
                std::string key = objectKey(object, incomplete);
                if (!key.empty()) keys.push_back(key);
            }
            std::sort(keys.begin(), keys.end());
            keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
            for (const std::string& key : keys) {
                if (static_cast<int64_t>(pts.size()) >= bounds_.maxPts) {
                    truncated = true;
                    break;
                }
                pts.push_back(key);
            }
            if (keys.empty() && incomplete.empty()) incomplete.push_back("empty_points_to_set");
        }
        json::Object record = locJson(loc);
        record["role"] = role;
        record["operand"] = static_cast<int64_t>(operand);
        record["function"] = functionName(&function);
        if (!callee.empty()) record["callee"] = callee;
        record["points_to"] = std::move(pts);
        record["truncated"] = truncated;
        record["incomplete_reasons"] = std::move(incomplete);
        sites_.push_back(std::move(record));
    }

    // A stable per-module key for one abstract object: allocation site plus field. Unknown and
    // black-hole objects mark the set incomplete instead of becoming keys.
    std::string objectKey(NodeID id, json::Array& incomplete) {
        auto cached = keys_.find(id);
        if (cached != keys_.end()) {
            if (cached->second.empty()) addReason(incomplete, "unknown_object");
            return cached->second;
        }
        const SVFVar* node = pag_->getGNode(id);
        const BaseObjVar* base = nullptr;
        int64_t field = 0;
        if (const auto* gep = SVFUtil::dyn_cast<GepObjVar>(node)) {
            base = gep->getBaseObj();
            field = static_cast<int64_t>(gep->getConstantFieldIdx());
        } else {
            base = SVFUtil::dyn_cast<BaseObjVar>(node);
        }
        // SVF folds constant data (string literals, constant globals) into one shared constant object:
        // a real, read-only object, keyed explicitly rather than treated as unknown memory.
        if (base && !pag_->isBlkObj(base->getId()) && pag_->isConstantObj(base->getId())) {
            keys_[id] = "obj:constant:shared";
            objects_["obj:constant:shared"] = json::Object{{"kind", "constant"}, {"name", "constant data"},
                                                           {"field", static_cast<int64_t>(0)}};
            return keys_[id];
        }
        if (!base || SVFUtil::isa<DummyObjVar>(base) || pag_->isBlkObj(base->getId())) {
            keys_[id] = "";
            addReason(incomplete, "unknown_object");
            return "";
        }
        std::string kind = base->isFunction() ? "function" : base->isHeap() ? "heap"
                         : base->isStack() ? "stack" : base->isGlobalObj() ? "global" : "other";
        Loc loc;
        std::string name = base->getName();
        auto value = objectValues_.find(base->getId());
        if (value != objectValues_.end()) {
            const Value* allocation = value->second;
            if (const auto* instruction = dyn_cast<Instruction>(allocation)) loc = locationOf(*instruction);
            auto declared = declares_.find(allocation);
            if (declared != declares_.end()) {
                if (!loc.valid()) loc = declared->second.first;
                name = declared->second.second;
            }
            if (const auto* global = dyn_cast<GlobalVariable>(allocation)) {
                SmallVector<DIGlobalVariableExpression*, 1> expressions;
                global->getDebugInfo(expressions);
                if (!expressions.empty()) {
                    const DIGlobalVariable* variable = expressions.front()->getVariable();
                    loc.file = joinPath(variable->getDirectory(), variable->getFilename());
                    loc.line = variable->getLine();
                }
                name = global->getName().str();
            }
            if (const auto* function = dyn_cast<Function>(allocation)) {
                name = function->getName().str();
                if (const DISubprogram* subprogram = function->getSubprogram()) {
                    loc.file = joinPath(subprogram->getDirectory(), subprogram->getFilename());
                    loc.line = subprogram->getLine();
                }
            }
        }
        std::string key = "obj:" + kind + ":" + (loc.valid() ? loc.file + ":" + std::to_string(loc.line) + ":" +
                                                 std::to_string(loc.column) : "nodebug") +
                          ":" + name + "#" + std::to_string(field) + "@" + std::to_string(base->getId());
        keys_[id] = key;
        json::Object record{{"kind", kind}, {"name", name}, {"field", field}};
        if (loc.valid()) record["location"] = locJson(loc);
        objects_[key] = std::move(record);
        return key;
    }

    static void addReason(json::Array& reasons, const char* reason) {
        for (const json::Value& existing : reasons)
            if (existing.getAsString() && *existing.getAsString() == reason) return;
        reasons.push_back(reason);
    }

    PointerAnalysis* pta_;
    SVFIR* pag_;
    Bounds bounds_;
    const std::set<std::string>& extApi_;
    std::string extApiPath_;
    LLVMModuleSet* lms_;
    std::map<NodeID, const Value*> objectValues_;
    std::map<const Value*, std::pair<Loc, std::string>> declares_;
    std::map<NodeID, std::string> keys_;
    std::map<std::string, json::Object> objects_;
    json::Array sites_;
    json::Array indirect_;
    std::set<std::string> unmodeled_;
    int64_t definedFunctions_ = 0;
    bool sitesTruncated_ = false;
    bool indirectTruncated_ = false;
    bool dynamicLoading_ = false;
    bool pointerInlineAsm_ = false;
};

int fail(const std::string& message) {
    errs() << "svf-alias-export: " << message << "\n";
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) return fail("usage: svf-alias-export <request.json>");
    auto buffer = MemoryBuffer::getFile(argv[1]);
    if (!buffer) return fail("request is unreadable");
    Expected<json::Value> parsed = json::parse((*buffer)->getBuffer());
    if (!parsed) return fail("request is not JSON");
    const json::Object* request = parsed->getAsObject();
    if (!request) return fail("request is not an object");
    std::optional<StringRef> module = request->getString("module");
    std::optional<StringRef> output = request->getString("output");
    std::optional<StringRef> extApi = request->getString("extapi");
    const json::Object* rawBounds = request->getObject("bounds");
    if (!module || !output || !extApi || !rawBounds) return fail("request lacks module, output, extapi or bounds");
    Bounds bounds;
    auto bound = [&](const char* key, int64_t& target) {
        if (std::optional<int64_t> value = rawBounds->getInteger(key)) target = *value;
    };
    bound("field_limit", bounds.fieldLimit);
    bound("max_sites", bounds.maxSites);
    bound("max_pts_size", bounds.maxPts);
    bound("max_indirect_calls", bounds.maxIndirect);
    bound("max_targets_per_call", bounds.maxTargets);
    bound("max_unmodeled_names", bounds.maxUnmodeled);
    bound("andersen_time_limit_seconds", bounds.anderTimeLimit);
    if (bounds.fieldLimit < 1 || bounds.maxSites < 1 || bounds.maxPts < 1 || bounds.maxIndirect < 1 ||
        bounds.maxTargets < 1 || bounds.maxUnmodeled < 1 || bounds.anderTimeLimit < 1)
        return fail("bounds must be positive");

    std::vector<std::string> storage = {
        "svf-alias-export",
        "-extapi=" + extApi->str(),
        "-field-limit=" + std::to_string(bounds.fieldLimit),
        "-ander-time-limit=" + std::to_string(bounds.anderTimeLimit),
        "-stat=false",
        module->str(),
    };
    std::vector<char*> svfArgv;
    for (std::string& value : storage) svfArgv.push_back(value.data());
    std::vector<std::string> modules = OptionBase::parseOptions(
        static_cast<int>(svfArgv.size()), svfArgv.data(), "svf-alias-export", "[options] <input-bitcode>");

    LLVMModuleSet::buildSVFModule(modules);
    SVFIRBuilder builder;
    SVFIR* pag = builder.build();
    AndersenWaveDiff* andersen = AndersenWaveDiff::createAndersenWaveDiff(pag);

    std::set<std::string> extApiNames = loadExtApiNames(extApi->str());
    Exporter exporter(andersen, pag, bounds, extApiNames, extApi->str());
    json::Object document = exporter.run();
    document["svf_version"] = "SVF-3.3";
    document["bounds"] = json::Object{
        {"field_limit", bounds.fieldLimit}, {"max_sites", bounds.maxSites}, {"max_pts_size", bounds.maxPts},
        {"max_indirect_calls", bounds.maxIndirect}, {"max_targets_per_call", bounds.maxTargets},
        {"andersen_time_limit_seconds", bounds.anderTimeLimit}};

    std::error_code error;
    raw_fd_ostream stream(output->str(), error);
    if (error) return fail("output is not writable");
    stream << json::Value(std::move(document)) << "\n";
    stream.close();

    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();
    LLVMModuleSet::releaseLLVMModuleSet();
    return stream.has_error() ? 3 : 0;
}
