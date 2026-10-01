// Acceptance gate for the recovered srvdsp.bin analysis path.
// Run after SunplusSrvdspAnalyze.java.  Requires complete instruction coverage,
// nine vector-seeded functions, and successful decompiler output for each.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;

public class SunplusSrvdspAcceptance extends GhidraScript {
    private static final long CODE_FIRST = 0x1820L;
    private static final long CODE_LAST = 0x1894L;
    private static final long[] HANDLERS = {
        0x1820L, 0x1824L, 0x1855L, 0x1867L, 0x186fL,
        0x187aL, 0x188dL, 0x188fL, 0x1891L
    };

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new AssertionError("No current program");
        }
        AddressSpace pm = currentProgram.getAddressFactory().getAddressSpace("PM");
        if (pm == null) {
            throw new AssertionError("PM address space missing");
        }

        int missing = 0;
        for (long off = CODE_FIRST; off <= CODE_LAST; off++) {
            if (currentProgram.getListing().getInstructionAt(pm.getAddress(off * pm.getAddressableUnitSize())) == null) {
                missing++;
            }
        }
        if (missing != 0) {
            throw new AssertionError("Undefined srvdsp code words: " + missing);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            decompiler.setOptions(options);
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(currentProgram)) {
                throw new AssertionError(
                    "Decompiler failed to open program: " + decompiler.getLastMessage());
            }

            int functionCount = 0;
            int decompiledCount = 0;
            for (long off : HANDLERS) {
                Address entry = pm.getAddress(off * pm.getAddressableUnitSize());
                Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (function == null) {
                    throw new AssertionError("Missing seeded function at " + entry);
                }
                functionCount++;

                DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
                if (!results.decompileCompleted() || results.getHighFunction() == null) {
                    throw new AssertionError(
                        "Decompiler failed at " + entry + ": " + results.getErrorMessage());
                }
                DecompiledFunction c = results.getDecompiledFunction();
                if (c == null || c.getC() == null || c.getC().isBlank()) {
                    throw new AssertionError("No C output for " + entry);
                }
                decompiledCount++;
                println("DECOMPILED " + entry + " " + function.getName());
            }

            println("SUNPLUS_SRVDSP_ACCEPTANCE=PASS code_words=" +
                (CODE_LAST - CODE_FIRST + 1) + " functions=" + functionCount +
                " decompiled=" + decompiledCount);
        }
        finally {
            decompiler.dispose();
        }
    }
}
