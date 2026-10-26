package com.xebyte.sunplus;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * General Sunplus codec raw-image reset-vector bootstrap.
 *
 * Native machine evidence: a bounded PM24 reset page either initializes
 * IMASK/ICNTL then JUMPs at word 2, or JUMPs immediately at word 0 and
 * exposes a native four-word interrupt vector table. Both decode to an
 * independently checked entry, with no codec filenames or guessed owners.
 * No cross-program references. Default ABI comes from compiler spec.
 */
public final class SunplusDspResetVectorBootstrap {
    private static final byte[] RESET_PREFIX = {
        (byte) 0x3c, 0x00, 0x03, // LDI IMASK,0x0
        (byte) 0x3c, 0x00, 0x04  // LDI ICNTL,0x0
    };

    private SunplusDspResetVectorBootstrap() {}

    public record Result(boolean recognized, boolean changed, Address entry) {
        static Result absent() { return new Result(false, false, null); }
    }

    public static Result prepare(Program program, TaskMonitor monitor) throws Exception {
        if (program == null || !SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
                program.getLanguageID().getIdAsString())) return Result.absent();
        var pm = program.getAddressFactory().getAddressSpace("PM");
        if (pm == null || pm.getAddressableUnitSize() != 3) return Result.absent();
        var memory = program.getMemory();
        Address vector = pm.getAddress(0);
        MemoryBlock block = memory.getBlock(vector);
        if (block == null || !block.isInitialized() || !block.isExecute() ||
                !vector.equals(block.getStart()) || block.getSize() < 9) return Result.absent();
        byte[] raw = new byte[9];
        if (memory.getBytes(vector, raw) != raw.length) return Result.absent();
        boolean maskControlReset = Arrays.equals(Arrays.copyOf(raw, 6), RESET_PREFIX);
        // A second source-proven architectural reset form is an immediate
        // absolute JUMP followed by the beginning of a four-word vector page.
        // The page shape is verified below before any program mutation.
        boolean directReset = !maskControlReset &&
            Arrays.equals(Arrays.copyOfRange(raw, 3, 9), new byte[6]);
        if (!maskControlReset && !directReset) return Result.absent();
        int jumpByte = maskControlReset ? 6 : 0;
        int instruction = (raw[jumpByte] & 255) << 16 |
            (raw[jumpByte + 1] & 255) << 8 | (raw[jumpByte + 2] & 255);
        // Source-native unconditional JUMP has opcode 6 and low operand 0xf.
        if ((instruction >>> 18) != 6 || (instruction & 15) != 15)
            return Result.absent();
        int word = (instruction >>> 4) & 0x3fff;
        if (directReset) {
            // An isolated branch in raw data is not enough to classify a
            // reset page. Independently verify its native IRQ slots: at
            // least three RTI returns and one directly encoded JUMP.
            if (word < 12 || word > 64) return Result.absent();
            int returns = 0, branches = 0;
            byte[] slot = new byte[3];
            for (int w = 4; w < word; w += 4) {
                monitor.checkCancelled();
                Address at = pm.getAddress((long) w * pm.getAddressableUnitSize());
                if (!block.contains(at) || !block.contains(at.add(2)) ||
                    memory.getBytes(at, slot) != 3) return Result.absent();
                int bits = (slot[0] & 255) << 16 | (slot[1] & 255) << 8 | (slot[2] & 255);
                if (bits == 0x0a001f) returns++;
                else if (bits == 0) continue; // native NOP vector
                else if ((bits >>> 18) == 6 && (bits & 15) == 15) {
                    int handlerWord = (bits >>> 4) & 0x3fff;
                    if (handlerWord < word || handlerWord >= block.getSize() / 3)
                        return Result.absent();
                    branches++;
                }
                else return Result.absent(); // not a proven IRQ vector slot
            }
            if (returns < 3 || branches < 1) return Result.absent();
        }
        // Ghidra AddressSpace.getAddress() takes a BYTE offset, whereas
        // encoded DSP PM destinations are 24-bit WORD addresses (3 bytes).
        Address root = pm.getAddress((long) word * pm.getAddressableUnitSize());
        if (word < 3 || word >= block.getSize() / 3 ||
                !block.contains(root) || !block.contains(root.add(2))) return Result.absent();

        // Idempotent on saved/previously analyzed programs.
        if (program.getFunctionManager().getFunctionAt(root) != null)
            return new Result(true, false, root);
        if (program.getFunctionManager().getFunctionCount() != 0)
            return new Result(true, false, root);
        int tx = program.startTransaction("Source-native DSP reset vector/function bootstrap");
        boolean commit = false;
        try {
            var listing = program.getListing();
            // Decode the bounded reset/interrupt-vector region. Both the
            // extent and targets come from native instructions: no codec
            // names, hard-coded interrupt handler addresses, or guessed calls.
            DisassembleCommand vectors = new DisassembleCommand(
                new AddressSet(vector, pm.getAddress((long) word * 3L - 1L)), null, true);
            vectors.enableCodeAnalysis(false);
            if (!vectors.applyTo(program, monitor))
                throw new IllegalStateException("Native DSP reset vector could not decode");
            Instruction reset = listing.getInstructionAt(vector),
                control = listing.getInstructionAt(vector.add(3)),
                jump = listing.getInstructionAt(vector.add(6));
            Instruction entryJump = maskControlReset ? jump : reset;
            if (entryJump == null || !"JUMP".equals(entryJump.getMnemonicString()) ||
                    entryJump.getFlows().length != 1 || !root.equals(entryJump.getFlows()[0]) ||
                    (maskControlReset && (reset == null || control == null ||
                    !"LDI IMASK,0x0".equals(reset.toString().trim()) ||
                    !"LDI ICNTL,0x0".equals(control.toString().trim()))))
                throw new IllegalStateException("Source PM24 reset vector flow proof failed" +
                    " reset=" + reset + " control=" + control + " jump=" + entryJump +
                    " jumpFlows=" + (entryJump == null ? "NONE" :
                        Arrays.toString(entryJump.getFlows())) + " expectedRoot=" + root);
            Set<Address> roots = new LinkedHashSet<>();
            roots.add(root);
            // The reset word gives the end of the vector page. Scan only
            // 4-word interrupt slots before the main entry. Native JUMP
            // targets (not labels/GUIDs) are the sole entry evidence.
            if (word <= 64) {
                for (int w = 4; w < word; w += 4) {
                    monitor.checkCancelled();
                    Instruction irq = listing.getInstructionAt(
                        pm.getAddress((long)w * pm.getAddressableUnitSize()));
                    if (irq == null || irq.getLength() != 3 ||
                        !"JUMP".equals(irq.getMnemonicString()) ||
                        irq.getFlowType().isComputed() || irq.getFlows().length != 1)
                        continue;
                    Address branch = irq.getFlows()[0];
                    if (branch.getAddressSpace().equals(pm) &&
                        branch.compareTo(root) >= 0 &&
                        block.contains(branch) && block.contains(branch.add(2)))
                        roots.add(branch);
                }
            }
            for (Address entry : roots) {
                monitor.checkCancelled();
                DisassembleCommand code = new DisassembleCommand(
                    new AddressSet(entry, entry.add(2)), null, true);
                code.enableCodeAnalysis(false);
                if (!code.applyTo(program, monitor) || listing.getInstructionAt(entry) == null)
                    throw new IllegalStateException("Native DSP vector entry could not decode: "+entry);
                if (program.getFunctionManager().getFunctionContaining(entry) != null) continue;
                CreateFunctionCmd cmd = new CreateFunctionCmd(entry);
                if (!cmd.applyTo(program, monitor))
                    throw new IllegalStateException("Source vector function discovery failed at "+entry+
                        ": "+cmd.getStatusMsg());
                Function fn = program.getFunctionManager().getFunctionAt(entry);
                if (fn == null) throw new IllegalStateException("Native vector function missing: "+entry);
                if (fn.getSignatureSource() != SourceType.USER_DEFINED &&
                        "unknown".equals(fn.getCallingConventionName()))
                    fn.setCallingConvention(
                        program.getCompilerSpec().getDefaultCallingConvention().getName());
            }
            // PM:0 is an independently decoded native reset function:
            // two machine register initializers + JUMP, or a direct JUMP.
            if (program.getFunctionManager().getFunctionContaining(vector)==null) {
                CreateFunctionCmd resetFn = new CreateFunctionCmd(vector);
                if (!resetFn.applyTo(program,monitor) ||
                    program.getFunctionManager().getFunctionAt(vector)==null)
                    throw new IllegalStateException("Native PM reset source function not recoverable");
            }
            commit = true;
        }
        finally { program.endTransaction(tx, commit); }
        return new Result(true, true, root);
    }
}
