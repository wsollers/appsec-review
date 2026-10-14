// Bounded structured export of one analyzed program for appsec-review.
//
// The program is data. Nothing in it is executed, and every name, string, and decompiled line
// written here is target-controlled text that downstream consumers must treat as data.
//
// Output (all UTF-8, one JSON object per line unless noted), written beneath output=<dir>:
//   program.json      single object: identity, format, language, memory blocks
//   functions.jsonl   one row per non-external function, in address order
//   decompiled.jsonl  pseudo-C per function
//   pcode.jsonl       high P-code per function
//   calls.jsonl       call and tail-jump edges, plus unresolved indirect call sites
//   imports.jsonl     external symbols
//   exports.jsonl     external entry points
//   strings.jsonl     defined strings with bounded cross-references
//   gaps.jsonl        every named coverage gap
//   complete.json     single object written last; its absence means the export failed
//@category AppsecReview

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

public class AppsecExportProgram extends HeadlessScript {

	private static final String SCHEMA = "appsec-review/ghidra-export/1";
	private static final int MAX_NAME_CHARS = 1024;
	private static final int MAX_STRING_CHARS = 4096;
	private static final int MAX_XREFS = 64;
	private static final int MAX_MESSAGE_CHARS = 512;

	private Path output;
	private int decompileTimeout = 60;
	private int maxFunctions = 50000;
	private int maxFunctionBytes = 262144;
	private int maxPcodeOps = 20000;
	private int maxStrings = 100000;
	private int minStringLength = 4;

	private BufferedWriter gaps;
	private final Map<String, Integer> gapCounts = new LinkedHashMap<>();
	private final Map<String, Integer> decompileCounts = new LinkedHashMap<>();

	@Override
	protected void run() throws Exception {
		readArguments();
		Files.createDirectories(output);
		Files.deleteIfExists(output.resolve("complete.json"));
		gaps = open("gaps.jsonl");
		try {
			if (analysisTimeoutOccurred()) {
				gap("analysis_timeout", null,
					"automatic analysis hit its time limit; functions and references may be missing");
			}
			writeProgram();
			int[] functionCounts = writeFunctions();
			int calls = writeCalls();
			int imports = writeImports();
			int exports = writeExports();
			int[] stringCounts = writeStrings();

			JsonObject complete = new JsonObject();
			complete.addProperty("schema", SCHEMA);
			complete.addProperty("ghidra_version", Application.getApplicationVersion());
			complete.addProperty("executable_sha256", currentProgram.getExecutableSHA256());
			complete.addProperty("analysis_timed_out", analysisTimeoutOccurred());
			JsonObject counts = new JsonObject();
			counts.addProperty("functions", functionCounts[0]);
			counts.addProperty("functions_not_exported", functionCounts[1]);
			counts.addProperty("calls", calls);
			counts.addProperty("imports", imports);
			counts.addProperty("exports", exports);
			counts.addProperty("strings", stringCounts[0]);
			counts.addProperty("strings_not_exported", stringCounts[1]);
			complete.add("counts", counts);
			complete.add("decompile_status", toJson(decompileCounts));
			complete.add("gaps", toJson(gapCounts));
			JsonObject limits = new JsonObject();
			limits.addProperty("decompile_timeout", decompileTimeout);
			limits.addProperty("max_functions", maxFunctions);
			limits.addProperty("max_function_bytes", maxFunctionBytes);
			limits.addProperty("max_pcode_ops", maxPcodeOps);
			limits.addProperty("max_strings", maxStrings);
			limits.addProperty("min_string_length", minStringLength);
			complete.add("limits", limits);
			gaps.close();
			gaps = null;
			Files.writeString(output.resolve("complete.json"), complete.toString() + "\n",
				StandardCharsets.UTF_8);
			println("appsec export complete: " + counts);
		}
		finally {
			if (gaps != null) {
				gaps.close();
			}
		}
	}

	private void readArguments() {
		for (String argument : getScriptArgs()) {
			int split = argument.indexOf('=');
			if (split < 1) {
				throw new IllegalArgumentException("argument is not key=value: " + argument);
			}
			String key = argument.substring(0, split);
			String value = argument.substring(split + 1);
			switch (key) {
				case "output":
					output = Paths.get(value);
					break;
				case "decompile_timeout":
					decompileTimeout = positive(key, value);
					break;
				case "max_functions":
					maxFunctions = positive(key, value);
					break;
				case "max_function_bytes":
					maxFunctionBytes = positive(key, value);
					break;
				case "max_pcode_ops":
					maxPcodeOps = positive(key, value);
					break;
				case "max_strings":
					maxStrings = positive(key, value);
					break;
				case "min_string_length":
					minStringLength = positive(key, value);
					break;
				default:
					throw new IllegalArgumentException("unknown argument: " + key);
			}
		}
		if (output == null) {
			throw new IllegalArgumentException("output=<directory> is required");
		}
	}

	private static int positive(String key, String value) {
		int parsed = Integer.parseInt(value);
		if (parsed < 1) {
			throw new IllegalArgumentException(key + " must be positive");
		}
		return parsed;
	}

	private BufferedWriter open(String name) throws IOException {
		return Files.newBufferedWriter(output.resolve(name), StandardCharsets.UTF_8);
	}

	private static void line(BufferedWriter writer, JsonObject record) throws IOException {
		writer.write(record.toString());
		writer.write('\n');
	}

	private static JsonObject toJson(Map<String, Integer> values) {
		JsonObject object = new JsonObject();
		for (Map.Entry<String, Integer> entry : values.entrySet()) {
			object.addProperty(entry.getKey(), entry.getValue());
		}
		return object;
	}

	private static String clip(String value, int limit) {
		if (value == null) {
			return null;
		}
		return value.length() <= limit ? value : value.substring(0, limit);
	}

	/** Default-space addresses are written as 0x-prefixed hex; anything else keeps its space. */
	private String format(Address address) {
		if (address == null) {
			return null;
		}
		if (address.getAddressSpace() == currentProgram.getAddressFactory().getDefaultAddressSpace()) {
			return "0x" + Long.toHexString(address.getOffset());
		}
		return address.toString();
	}

	private void gap(String kind, Address address, String detail) throws IOException {
		JsonObject record = new JsonObject();
		record.addProperty("kind", kind);
		record.addProperty("address", format(address));
		record.addProperty("detail", clip(detail, MAX_MESSAGE_CHARS));
		line(gaps, record);
		gapCounts.merge(kind, 1, Integer::sum);
	}

	private void writeProgram() throws IOException {
		JsonObject program = new JsonObject();
		program.addProperty("schema", SCHEMA);
		program.addProperty("ghidra_version", Application.getApplicationVersion());
		program.addProperty("name", clip(currentProgram.getName(), MAX_NAME_CHARS));
		program.addProperty("executable_format", currentProgram.getExecutableFormat());
		program.addProperty("executable_sha256", currentProgram.getExecutableSHA256());
		program.addProperty("executable_md5", currentProgram.getExecutableMD5());
		program.addProperty("language", currentProgram.getLanguageID().getIdAsString());
		program.addProperty("compiler_spec",
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
		program.addProperty("compiler", clip(currentProgram.getCompiler(), MAX_NAME_CHARS));
		program.addProperty("big_endian", currentProgram.getLanguage().isBigEndian());
		program.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
		program.addProperty("image_base", format(currentProgram.getImageBase()));
		program.addProperty("min_address", format(currentProgram.getMinAddress()));
		program.addProperty("max_address", format(currentProgram.getMaxAddress()));
		program.addProperty("analysis_timed_out", analysisTimeoutOccurred());
		JsonArray blocks = new JsonArray();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			JsonObject item = new JsonObject();
			item.addProperty("name", clip(block.getName(), MAX_NAME_CHARS));
			item.addProperty("start", format(block.getStart()));
			item.addProperty("end", format(block.getEnd()));
			item.addProperty("size", block.getSize());
			item.addProperty("read", block.isRead());
			item.addProperty("write", block.isWrite());
			item.addProperty("execute", block.isExecute());
			item.addProperty("initialized", block.isInitialized());
			blocks.add(item);
		}
		program.add("memory_blocks", blocks);
		Files.writeString(output.resolve("program.json"), program.toString() + "\n",
			StandardCharsets.UTF_8);
	}

	/** Returns {exported, not exported because of max_functions}. */
	private int[] writeFunctions() throws Exception {
		FunctionManager manager = currentProgram.getFunctionManager();
		SymbolTable symbols = currentProgram.getSymbolTable();
		DecompInterface decompiler = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(currentProgram);
		decompiler.setOptions(options);
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");
		boolean available = decompiler.openProgram(currentProgram);
		if (!available) {
			gap("decompiler_unavailable", null, decompiler.getLastMessage());
		}
		int exported = 0;
		int skipped = 0;
		try (BufferedWriter functions = open("functions.jsonl");
				BufferedWriter decompiled = open("decompiled.jsonl");
				BufferedWriter pcode = open("pcode.jsonl")) {
			for (Function function : manager.getFunctions(true)) {
				monitor.checkCancelled();
				if (exported >= maxFunctions) {
					skipped++;
					continue;
				}
				Address entry = function.getEntryPoint();
				String address = format(entry);
				JsonObject row = new JsonObject();
				row.addProperty("address", address);
				row.addProperty("name", clip(function.getName(), MAX_NAME_CHARS));
				row.addProperty("qualified_name", clip(function.getName(true), MAX_NAME_CHARS));
				row.addProperty("name_source", function.getSymbol().getSource().toString());
				row.addProperty("signature",
					clip(function.getPrototypeString(false, false), MAX_NAME_CHARS));
				row.addProperty("calling_convention", function.getCallingConventionName());
				row.addProperty("parameter_count", function.getParameterCount());
				row.addProperty("body_bytes", function.getBody().getNumAddresses());
				row.addProperty("no_return", function.hasNoReturn());
				row.addProperty("is_export", symbols.isExternalEntryPoint(entry));
				MemoryBlock block = currentProgram.getMemory().getBlock(entry);
				row.addProperty("memory_block", block == null ? null : clip(block.getName(), MAX_NAME_CHARS));
				row.addProperty("is_thunk", function.isThunk());
				if (function.isThunk()) {
					Function target = function.getThunkedFunction(true);
					if (target != null) {
						row.addProperty("thunk_target", clip(target.getName(true), MAX_NAME_CHARS));
						row.addProperty("thunk_target_external", target.isExternal());
						row.addProperty("thunk_target_address",
							target.isExternal() ? null : format(target.getEntryPoint()));
					}
				}
				String status;
				if (function.isThunk()) {
					status = "skipped_thunk";
				}
				else if (!available) {
					status = "unavailable";
				}
				else {
					status = decompile(decompiler, function, address, decompiled, pcode);
				}
				row.addProperty("decompile_status", status);
				decompileCounts.merge(status, 1, Integer::sum);
				line(functions, row);
				exported++;
			}
		}
		finally {
			decompiler.dispose();
		}
		if (skipped > 0) {
			gap("function_limit", null,
				skipped + " functions were not exported because max_functions=" + maxFunctions);
		}
		return new int[] { exported, skipped };
	}

	private String decompile(DecompInterface decompiler, Function function, String address,
			BufferedWriter decompiled, BufferedWriter pcode) throws Exception {
		DecompileResults results = decompiler.decompileFunction(function, decompileTimeout, monitor);
		if (results == null || !results.decompileCompleted()) {
			boolean timedOut = results != null && results.isTimedOut();
			String status = timedOut ? "timeout" : "failed";
			gap("decompile_" + status, function.getEntryPoint(),
				results == null ? "no result" : results.getErrorMessage());
			return status;
		}
		DecompiledFunction text = results.getDecompiledFunction();
		if (text == null || text.getC() == null) {
			gap("decompile_failed", function.getEntryPoint(), "decompiler produced no C text");
			return "failed";
		}
		String c = text.getC();
		boolean truncated = false;
		if (c.getBytes(StandardCharsets.UTF_8).length > maxFunctionBytes) {
			// Characters never exceed bytes, so this prefix is within the byte limit for ASCII
			// and conservative otherwise; the normalizer records the exact stored size.
			c = c.substring(0, Math.min(c.length(), maxFunctionBytes / 4));
			truncated = true;
			gap("pseudo_c_truncated", function.getEntryPoint(),
				"pseudo-C exceeded max_function_bytes=" + maxFunctionBytes);
		}
		JsonObject record = new JsonObject();
		record.addProperty("address", address);
		record.addProperty("truncated", truncated);
		record.addProperty("c", c);
		line(decompiled, record);

		HighFunction high = results.getHighFunction();
		if (high == null) {
			gap("pcode_unavailable", function.getEntryPoint(), "no high function");
			return "ok";
		}
		JsonArray operations = new JsonArray();
		boolean pcodeTruncated = false;
		Iterator<PcodeOpAST> iterator = high.getPcodeOps();
		while (iterator.hasNext()) {
			PcodeOpAST operation = iterator.next();
			if (operations.size() >= maxPcodeOps) {
				pcodeTruncated = true;
				break;
			}
			JsonObject item = new JsonObject();
			item.addProperty("address", format(operation.getSeqnum().getTarget()));
			item.addProperty("order", operation.getSeqnum().getOrder());
			item.addProperty("mnemonic", operation.getMnemonic());
			Varnode result = operation.getOutput();
			item.addProperty("output", result == null ? null : result.toString());
			JsonArray inputs = new JsonArray();
			for (Varnode input : operation.getInputs()) {
				inputs.add(input == null ? null : input.toString());
			}
			item.add("inputs", inputs);
			if (operation.getOpcode() == PcodeOp.CALL && operation.getNumInputs() > 0) {
				Varnode target = operation.getInput(0);
				Function callee = target == null || !target.isAddress() ? null
						: currentProgram.getFunctionManager().getFunctionAt(target.getAddress());
				if (callee != null) {
					Function resolved = callee.isThunk() ? callee.getThunkedFunction(true) : callee;
					item.addProperty("callee",
						clip((resolved == null ? callee : resolved).getName(true), MAX_NAME_CHARS));
				}
			}
			operations.add(item);
		}
		if (pcodeTruncated) {
			gap("pcode_truncated", function.getEntryPoint(),
				"high P-code exceeded max_pcode_ops=" + maxPcodeOps);
		}
		JsonObject pcodeRecord = new JsonObject();
		pcodeRecord.addProperty("address", address);
		pcodeRecord.addProperty("truncated", pcodeTruncated);
		pcodeRecord.add("operations", operations);
		line(pcode, pcodeRecord);
		return "ok";
	}

	private int writeCalls() throws Exception {
		FunctionManager manager = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		int count = 0;
		try (BufferedWriter calls = open("calls.jsonl")) {
			for (Function function : manager.getFunctions(true)) {
				monitor.checkCancelled();
				String from = format(function.getEntryPoint());
				InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
				while (instructions.hasNext()) {
					Instruction instruction = instructions.next();
					boolean isCall = instruction.getFlowType().isCall();
					boolean resolved = false;
					for (Reference reference : instruction.getReferencesFrom()) {
						RefType type = reference.getReferenceType();
						if (!type.isFlow()) {
							continue;
						}
						JsonObject edge = new JsonObject();
						edge.addProperty("from_function", from);
						edge.addProperty("call_site", format(instruction.getAddress()));
						if (reference.isExternalReference()) {
							ExternalLocation location =
								((ExternalReference) reference).getExternalLocation();
							edge.addProperty("to", (String) null);
							edge.addProperty("to_name", clip(location.getLabel(), MAX_NAME_CHARS));
							edge.addProperty("resolved_name", clip(location.getLabel(), MAX_NAME_CHARS));
							edge.addProperty("resolved_external", true);
						}
						else {
							Function target = manager.getFunctionAt(reference.getToAddress());
							if (target == null) {
								// A flow reference that does not land on a function entry is
								// intra-function control flow, not a call edge.
								if (!type.isCall()) {
									continue;
								}
								edge.addProperty("to", format(reference.getToAddress()));
								edge.addProperty("to_name", (String) null);
							}
							else {
								if (!type.isCall() && target.equals(function)) {
									continue;
								}
								Function end = target.isThunk() ? target.getThunkedFunction(true) : target;
								if (end == null) {
									end = target;
								}
								edge.addProperty("to", format(target.getEntryPoint()));
								edge.addProperty("to_name", clip(target.getName(true), MAX_NAME_CHARS));
								edge.addProperty("resolved_name", clip(end.getName(true), MAX_NAME_CHARS));
								edge.addProperty("resolved_external", end.isExternal());
							}
						}
						edge.addProperty("kind", type.isCall() ? "call" : "jump");
						edge.addProperty("computed", type.isComputed() || type.isIndirect());
						line(calls, edge);
						count++;
						resolved = resolved || type.isCall();
					}
					if (isCall && !resolved) {
						JsonObject edge = new JsonObject();
						edge.addProperty("from_function", from);
						edge.addProperty("call_site", format(instruction.getAddress()));
						edge.addProperty("to", (String) null);
						edge.addProperty("to_name", (String) null);
						edge.addProperty("kind", "call");
						edge.addProperty("computed", true);
						edge.addProperty("unresolved", true);
						line(calls, edge);
						count++;
					}
				}
			}
		}
		return count;
	}

	private int writeImports() throws Exception {
		SymbolTable symbols = currentProgram.getSymbolTable();
		int count = 0;
		try (BufferedWriter imports = open("imports.jsonl")) {
			for (Symbol symbol : symbols.getExternalSymbols()) {
				monitor.checkCancelled();
				SymbolType type = symbol.getSymbolType();
				if (type != SymbolType.FUNCTION && type != SymbolType.LABEL) {
					continue;
				}
				JsonObject record = new JsonObject();
				record.addProperty("name", clip(symbol.getName(), MAX_NAME_CHARS));
				record.addProperty("library", clip(symbol.getParentNamespace().getName(), MAX_NAME_CHARS));
				record.addProperty("kind", type == SymbolType.FUNCTION ? "function" : "data");
				ExternalLocation location =
					currentProgram.getExternalManager().getExternalLocation(symbol);
				if (location != null) {
					record.addProperty("original_name",
						clip(location.getOriginalImportedName(), MAX_NAME_CHARS));
				}
				JsonArray thunks = new JsonArray();
				if (symbol.getObject() instanceof Function) {
					Address[] addresses = ((Function) symbol.getObject()).getFunctionThunkAddresses(true);
					if (addresses != null) {
						for (Address address : addresses) {
							if (thunks.size() < MAX_XREFS) {
								thunks.add(format(address));
							}
						}
					}
				}
				record.add("thunks", thunks);
				line(imports, record);
				count++;
			}
		}
		return count;
	}

	private int writeExports() throws Exception {
		SymbolTable symbols = currentProgram.getSymbolTable();
		FunctionManager manager = currentProgram.getFunctionManager();
		int count = 0;
		try (BufferedWriter exports = open("exports.jsonl")) {
			AddressIterator entries = symbols.getExternalEntryPointIterator();
			while (entries.hasNext()) {
				monitor.checkCancelled();
				Address address = entries.next();
				Symbol primary = symbols.getPrimarySymbol(address);
				JsonObject record = new JsonObject();
				record.addProperty("address", format(address));
				record.addProperty("name", primary == null ? null : clip(primary.getName(true), MAX_NAME_CHARS));
				record.addProperty("is_function", manager.getFunctionAt(address) != null);
				line(exports, record);
				count++;
			}
		}
		return count;
	}

	/** Returns {exported, not exported because of max_strings}. */
	private int[] writeStrings() throws Exception {
		FunctionManager manager = currentProgram.getFunctionManager();
		ReferenceManager references = currentProgram.getReferenceManager();
		int exported = 0;
		int skipped = 0;
		try (BufferedWriter strings = open("strings.jsonl")) {
			for (Data data : currentProgram.getListing().getDefinedData(true)) {
				monitor.checkCancelled();
				if (!StringDataInstance.isString(data)) {
					continue;
				}
				String value = StringDataInstance.getStringDataInstance(data).getStringValue();
				if (value == null || value.length() < minStringLength) {
					continue;
				}
				if (exported >= maxStrings) {
					skipped++;
					continue;
				}
				JsonObject record = new JsonObject();
				record.addProperty("address", format(data.getAddress()));
				record.addProperty("length", value.length());
				record.addProperty("truncated", value.length() > MAX_STRING_CHARS);
				record.addProperty("value", clip(value, MAX_STRING_CHARS));
				record.addProperty("data_type", data.getDataType().getName());
				MemoryBlock block = currentProgram.getMemory().getBlock(data.getAddress());
				record.addProperty("memory_block", block == null ? null : clip(block.getName(), MAX_NAME_CHARS));
				JsonArray xrefs = new JsonArray();
				boolean more = false;
				ReferenceIterator incoming = references.getReferencesTo(data.getAddress());
				while (incoming.hasNext()) {
					Reference reference = incoming.next();
					if (xrefs.size() >= MAX_XREFS) {
						more = true;
						break;
					}
					JsonObject xref = new JsonObject();
					xref.addProperty("from", format(reference.getFromAddress()));
					Function container = manager.getFunctionContaining(reference.getFromAddress());
					xref.addProperty("function",
						container == null ? null : format(container.getEntryPoint()));
					xrefs.add(xref);
				}
				record.add("xrefs", xrefs);
				record.addProperty("xrefs_truncated", more);
				line(strings, record);
				exported++;
			}
		}
		if (skipped > 0) {
			gap("string_limit", null,
				skipped + " strings were not exported because max_strings=" + maxStrings);
		}
		return new int[] { exported, skipped };
	}
}
