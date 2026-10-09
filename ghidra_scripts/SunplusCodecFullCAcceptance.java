// Read-only high-level regression for already-discovered SPHE audio DSP functions.
// Import/analyze the firmware in a separate Ghidra project first; never use this
// acceptance script to overwrite an annotated canonical Analysis database.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.util.Map;

public class SunplusCodecFullCAcceptance extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null ||
                !"SunplusSPHEAudioDSP:BE:16:default".equals(
                    currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Expected an analyzed Sunplus audio DSP program");
        }
        Map<String,Integer> corpus = Map.of(
            "srvdsp.bin", 9,
            "aux-profile.bin", 61,
            "pcm-profile.bin", 4,
            "ac3-profile.bin", 25,
            "dts-profile.bin", 98);
        String program = currentProgram.getName();
        Integer expected = corpus.get(program);
        if (expected == null) {
            throw new IllegalStateException("Unsupported acceptance target: " + program);
        }
        if (currentProgram.getFunctionManager().getFunctionCount() != expected) {
            throw new IllegalStateException("Incorrect function inventory " + program +
                ": expected " + expected + " got " +
                currentProgram.getFunctionManager().getFunctionCount());
        }

        int ok = 0, failed = 0, warnings = 0;
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Unable to open decompiler");
        }
        try {
            FunctionIterator functions =
                currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function function = functions.next();
                DecompileResults result = decompiler.decompileFunction(function, 6, monitor);
                String c = result.getDecompiledFunction() == null ? "" :
                    result.getDecompiledFunction().getC();
                if (result.decompileCompleted() && !c.isBlank()) {
                    ok++;
                }
                else {
                    failed++;
                    println("SUNPLUS_CODEC_C_FAILURE " + program + " " +
                        function.getEntryPoint() + " " +
                        result.getErrorMessage().replace('\n',' '));
                }
                if (c.contains("WARNING:")) {
                    warnings++;
                }
            }
        }
        finally {
            decompiler.dispose();
        }
        println("SUNPLUS_CODEC_FULL_C " + program + " " + ok + "/" + expected +
            " failed=" + failed + " warning_functions=" + warnings);
        if (failed != 0 || ok != expected) {
            throw new IllegalStateException("Incomplete C decompilation for " + program);
        }
        println("SUNPLUS_CODEC_FULL_C_ACCEPTANCE=PASS module=" + program +
            " functions=" + expected);
    }
}
