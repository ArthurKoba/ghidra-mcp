// Synthetic non-firmware CE nesting regressions for the Sunplus codec model.
// Acceptance for 2 and 4 levels, with counter restoration observed at runtime.
// Never run on canonical annotated firmware.
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;

public class SunplusNestedCeLoopAcceptance extends GhidraScript {
    private Address pm(long word) {
        return currentProgram.getAddressFactory().getAddress("PM:" + Long.toHexString(word));
    }

    @Override
    public void run() throws Exception {
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("Wrong DSP processor");
        String program = currentProgram.getName();
        boolean deep = "nested_ce_4deep.bin".equals(program);
        boolean dmCounter = "nested_ce_dmread_2x3.bin".equals(program);
        if (!deep && !dmCounter && !"nested_ce_2x3.bin".equals(program))
            throw new IllegalStateException("Unexpected fixture: " + program);
        long first = deep ? 0x200 : 0x100;
        long last = deep ? 0x212 : 0x109;
        long[] loopEnds = deep ? new long[]{0x209, 0x20d, 0x20f, 0x211} :
                                  new long[]{0x105, 0x108};
        long innermost = deep ? 0x208 : 0x104;
        long outermost = deep ? 0x211 : 0x108;
        int expectedInner = deep ? 24 : 6;
        int expectedOuter = 2;

        int tx = currentProgram.startTransaction("Isolated nested CE fixture");
        try {
            if (!currentProgram.getMemory().contains(pm(first)) ||
                !currentProgram.getMemory().contains(pm(last)))
                throw new IllegalStateException("Fixture is not mapped at expected PM base");
            Register nestedMode = currentProgram.getProgramContext().getRegister("codec_ce_nested_mode");
            if (nestedMode == null)
                throw new IllegalStateException("Nested CE context selector missing");
            // Use narrow per-instruction context, not a whole-function override.
            // Outer counter loads stay on the proven default path (no loop active yet).
            long[] nestedWords = deep ?
                new long[]{0x201,0x202,0x203,0x204,0x205,0x206,0x207,
                           0x209,0x20d,0x20f,0x211} :
                new long[]{0x101,0x102,0x103,0x105,0x108};
            for (long w : nestedWords) {
                currentProgram.getProgramContext().setValue(
                    nestedMode, pm(w), pm(w), BigInteger.ONE);
            }
            if (currentProgram.getProgramContext().getValue(
                    nestedMode, pm(first), false) != null)
                throw new IllegalStateException("Nested mode escaped proved instruction set");
            disassemble(pm(first));
            for (long w = first; w <= last; ++w) {
                if (currentProgram.getListing().getInstructionAt(pm(w)) == null)
                    disassemble(pm(w));
                if (currentProgram.getListing().getInstructionAt(pm(w)) == null)
                    throw new IllegalStateException("Undecoded PM:" + Long.toHexString(w));
            }
            Register endContext = currentProgram.getProgramContext().getRegister("codec_ce_loop_end");
            if (endContext == null)
                throw new IllegalStateException("CE-end context missing");
            for (long end : loopEnds) {
                Address a = pm(end);
                clearListing(a, a);
                currentProgram.getProgramContext().setValue(endContext, a, a, BigInteger.ONE);
                if (!disassemble(a))
                    throw new IllegalStateException("Failed to re-disassemble loop end");
                Instruction ins = currentProgram.getListing().getInstructionAt(a);
                int sub = 0, branch = 0, indirect = 0;
                for (PcodeOp op : ins.getPcode()) {
                    if (op.getOpcode() == PcodeOp.INT_SUB) ++sub;
                    if (op.getOpcode() == PcodeOp.CBRANCH) ++branch;
                    if (op.getOpcode() == PcodeOp.BRANCHIND) ++indirect;
                }
                if (sub == 0 || branch == 0 || indirect == 0)
                    throw new IllegalStateException("Loop end lacks counter/back edge at " + a);
            }

            EmulatorHelper emulator = new EmulatorHelper(currentProgram);
            try {
                // EmulatorHelper re-decodes with its own context; listing context is not enough.
                emulator.setContextRegister(nestedMode, BigInteger.ONE);
                emulator.writeRegister("DSP_LOOP_DEPTH", 0);
                emulator.writeRegister("DSP_COUNT_DEPTH", 0);
                emulator.writeRegister("DSP_LOOP_START", 0);
                emulator.writeRegister("CNTR", 0);
                emulator.writeRegister("PC", pm(first).getAddressableWordOffset());
                if (dmCounter) {
                    Address counterAddress = currentProgram.getAddressFactory().getAddress("DM:0780");
                    emulator.writeMemoryValue(counterAddress, 2, 3);
                }

                int inner = 0, outer = 0, steps = 0;
                int stepBound = deep ? 200 : 85;
                while (steps < stepBound) {
                    Address pc = emulator.getExecutionAddress();
                    if (pc == null)
                        throw new IllegalStateException("Null emulator PC");
                    if (pc.equals(pm(innermost))) ++inner;
                    if (pc.equals(pm(outermost))) {
                        ++outer;
                        long expectedRemaining = expectedOuter - outer + 1;
                        long actual = emulator.readRegister("CNTR").longValue();
                        if (actual != expectedRemaining)
                            throw new IllegalStateException("Outer count restoration: " + actual +
                                " instead of " + expectedRemaining + ", iteration " + outer);
                    }
                    if (pc.equals(pm(last)))
                        break;
                    // Context does not flow automatically from Ghidra Listing to EmulatorHelper.
                    // Reapply the opted-in nested mode at every word boundary.
                    emulator.setContextRegister(nestedMode, BigInteger.ONE);
                    if (!emulator.step(monitor))
                        throw new IllegalStateException("Emulator failure: " + emulator.getLastError());
                    ++steps;
                }
                long depth = emulator.readRegister("DSP_LOOP_DEPTH").longValue();
                long countDepth = emulator.readRegister("DSP_COUNT_DEPTH").longValue();
                println("NESTED_CE_EXECUTION fixture=" + program +
                    " inner=" + inner + " outer=" + outer + " steps=" + steps +
                    " loopDepth=" + depth + " countDepth=" + countDepth);
                if (inner != expectedInner || outer != expectedOuter ||
                    depth != 0 || countDepth != 0 || steps == stepBound)
                    throw new IllegalStateException("Nested CE runtime contract failed");
                println("NESTED_CE_RUNTIME_ACCEPTANCE=PASS " + program);
            }
            finally { emulator.dispose(); }
        }
        finally { currentProgram.endTransaction(tx, false); }
    }
}
