// Point Ghidra's PDB analyzer at one operator-supplied, hash-verified debug-symbol file.
//
// Runs as a -preScript, after import and before auto-analysis. It never contacts a symbol server:
// the only symbol source is the file the runner staged beside the binary under /target. Whether
// the symbols were applied is recorded by AppsecExportProgram as program.json debug_symbols_loaded.
//@category AppsecReview

import java.io.File;

import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.util.headless.HeadlessScript;

public class AppsecLoadDebugSymbols extends HeadlessScript {

	@Override
	protected void run() throws Exception {
		String path = null;
		for (String argument : getScriptArgs()) {
			int split = argument.indexOf('=');
			if (split < 1) {
				throw new IllegalArgumentException("script arguments must be key=value");
			}
			String key = argument.substring(0, split);
			String value = argument.substring(split + 1);
			switch (key) {
				case "debug_symbols":
					path = value;
					break;
				default:
					throw new IllegalArgumentException("unknown script argument " + key);
			}
		}
		if (path == null || !path.matches("/target/[A-Za-z0-9._-]+")) {
			throw new IllegalArgumentException("debug_symbols must name one file directly under /target");
		}
		File file = new File(path);
		if (!file.isFile()) {
			throw new IllegalArgumentException("debug symbols are not a regular file");
		}
		PdbUniversalAnalyzer.setPdbFileOption(currentProgram, file);
		PdbUniversalAnalyzer.setAllowRemoteOption(currentProgram, false);
	}
}
