// Isolated acceptance on synthetic PCM-native instructions at PM:12B8..12BE.
// Never run this script against an annotated canonical project.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

public class SunplusDSPCeLoopRegression extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(
                currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("Incorrect target language");
        Address start = currentProgram.getAddressFactory().getAddress("PM:12b8");
        if (start == null || !currentProgram.getMemory().contains(start))
            throw new IllegalStateException("Synthetic PCM fixture not mapped at PM:12B8");
        if (!disassemble(start))
            throw new IllegalStateException("PCM CE fixture disassembly failed");
        Instruction setup = getInstructionAt(currentProgram.getAddressFactory().getAddress("PM:12b9"));
        Instruction end = getInstructionAt(currentProgram.getAddressFactory().getAddress("PM:12bd"));
        if (setup == null || end == null)
            throw new IllegalStateException("PCM CE setup/end instruction missing");
        int setupCalls=0, dec=0, cond=0, indirect=0, opaque=0;
        for (PcodeOp op : setup.getPcode()) {
            if (op.getOpcode() == PcodeOp.CALLOTHER) opaque++;
            if (op.getOpcode() == PcodeOp.CALL) setupCalls++;
        }
        for (PcodeOp op : end.getPcode()) {
            if (op.getOpcode() == PcodeOp.INT_SUB) dec++;
            if (op.getOpcode() == PcodeOp.CBRANCH) cond++;
            if (op.getOpcode() == PcodeOp.BRANCHIND) indirect++;
        }
        println("PCM_CE_PCODE setup=" + setup + " end=" + end +
            " setupUserops=" + opaque + " endDecrements=" + dec +
            " endConditionalBranches=" + cond + " endIndirectBranches=" + indirect +
            " setupCalls=" + setupCalls);
        if (opaque != 0 || dec == 0 || cond == 0 || indirect == 0)
            throw new IllegalStateException("Loop end still opaque or lacks real back-edge");
        Function function = currentProgram.getFunctionManager().getFunctionAt(start);
        if (function == null) {
            function = createFunction(start, "ProcessPcmSyntheticCeLoop");
        }
        if (function == null) throw new IllegalStateException("Failed to create synthetic function");
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException("Failed to open decompiler");
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            String c = result.getDecompiledFunction() == null ? "" :
                result.getDecompiledFunction().getC();
            println("PCM_CE_C_DECOMPILED=" + result.decompileCompleted() +
                " bytes=" + c.length() + " opaque=" + c.contains("dsp_do_until_ce") +
                " warnings=" + c.contains("Removing unreachable block") +
                " error=" + result.getErrorMessage() +
                " bodySize=" + function.getBody().getNumAddresses());
            if (!result.decompileCompleted() || c.isBlank() ||
                c.contains("dsp_do_until_ce") || c.contains("Removing unreachable block"))
                throw new IllegalStateException("PCM CE loop still not representable as C");
        }
        finally { decompiler.dispose(); }
        println("SUNPLUS_CODEC_CE_LOOP_ACCEPTANCE=PASS");
    }
}
