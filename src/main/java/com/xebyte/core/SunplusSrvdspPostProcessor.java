package com.xebyte.core;

import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Target-specific pre-analysis preparation for the recovered {@code srvdsp.bin} image.
 *
 * <p>The raw binary has no container metadata, so a generic binary import places it at PM:0 and
 * leaves Ghidra with no function seeds.  The image itself proves an effective PM base of 0x1800:
 * its first 32 24-bit words are unconditional direct jumps and the first local target is PM:1820.
 * This helper applies that recovered load contract before ordinary auto-analysis.</p>
 */
public final class SunplusSrvdspPostProcessor {
    public static final String LANGUAGE_ID = "SunplusSPHEAudioDSP:BE:16:default";
    public static final long EXPECTED_SIZE_BYTES = 1128L;
    public static final long PM_BASE = 0x1800L;
    public static final long VECTOR_WORDS = 0x20L;
    public static final long CODE_FIRST = 0x1820L;
    public static final long CODE_LAST = 0x1894L;
    public static final long DEFAULT_VECTOR_TARGET = 0x1895L;
    public static final int EXPECTED_LOCAL_HANDLERS = 9;
    public static final long DM_STATE_SIZE_BYTES = 0x300L;

    private SunplusSrvdspPostProcessor() {
    }

    private static Address pmWord(AddressSpace pm, long wordAddress) {
        return pm.getAddress(wordAddress * pm.getAddressableUnitSize());
    }

    public record Result(boolean applicable, boolean changed, int handlerCount, int functionCount) {
        static Result notApplicable() {
            return new Result(false, false, 0, 0);
        }
    }

    /**
     * Prepare srvdsp for normal Ghidra analysis.  Non-target programs are left untouched.
     */
    public static Result prepare(Program program, TaskMonitor monitor) throws Exception {
        if (!isApplicable(program)) {
            return Result.notApplicable();
        }

        AddressSpace pm = program.getAddressFactory().getAddressSpace("PM");
        if (pm == null) {
            throw new IllegalStateException("Sunplus srvdsp language has no PM address space");
        }

        boolean changed = false;
        int tx = program.startTransaction("Prepare Sunplus srvdsp analysis");
        boolean commit = false;
        try {
            Address desiredBase = pmWord(pm, PM_BASE);
            if (!program.getImageBase().equals(desiredBase)) {
                program.setImageBase(desiredBase, true);
                changed = true;
            }

            if (ensureDmStateBlock(program)) {
                changed = true;
            }

            Set<Long> handlers = collectLocalHandlerTargets(program, pm);
            if (handlers.size() != EXPECTED_LOCAL_HANDLERS) {
                throw new IllegalStateException(
                    "Expected " + EXPECTED_LOCAL_HANDLERS + " local srvdsp handlers, got " + handlers);
            }

            Address decodeStart = pmWord(pm, PM_BASE);
            Address decodeEnd = pmWord(pm, CODE_LAST);
            DisassembleCommand disassemble =
                new DisassembleCommand(new AddressSet(decodeStart, decodeEnd), null, true);
            if (!disassemble.applyTo(program, monitor)) {
                throw new IllegalStateException(
                    "Sunplus srvdsp disassembly failed: " + disassemble.getStatusMsg());
            }
            changed = true;

            for (long target : handlers) {
                Address entry = pmWord(pm, target);
                Function function = program.getFunctionManager().getFunctionAt(entry);
                if (function == null) {
                    String name = String.format("srvdsp_handler_%04x", target);
                    CreateFunctionCmd create =
                        new CreateFunctionCmd(name, entry, null, SourceType.ANALYSIS);
                    if (!create.applyTo(program, monitor)) {
                        throw new IllegalStateException(
                            "Unable to create srvdsp function at " + entry + ": " + create.getStatusMsg());
                    }
                    function = program.getFunctionManager().getFunctionAt(entry);
                    if (function == null) {
                        throw new IllegalStateException("Created srvdsp action missing at " + entry);
                    }
                    changed = true;
                }
                if (function.getSignatureSource() != SourceType.USER_DEFINED &&
                        function.getReturnType().getName().startsWith("undefined")) {
                    function.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
                    changed = true;
                }
            }

            int missing = countMissingInstructions(program, pm);
            if (missing != 0) {
                throw new IllegalStateException(
                    "Sunplus srvdsp processor coverage incomplete: " + missing +
                    " undefined instruction word(s) in PM:1820..1894");
            }

            commit = true;
            return new Result(
                true,
                changed,
                handlers.size(),
                program.getFunctionManager().getFunctionCount());
        }
        finally {
            program.endTransaction(tx, commit);
        }
    }

    static boolean isApplicable(Program program) throws Exception {
        if (program == null || !LANGUAGE_ID.equals(program.getLanguageID().getIdAsString())) {
            return false;
        }
        return findCanonicalPmImageBlock(program) != null;
    }

    private static MemoryBlock findCanonicalPmImageBlock(Program program) throws Exception {
        Memory memory = program.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.getSize() != EXPECTED_SIZE_BYTES ||
                    !"PM".equals(block.getStart().getAddressSpace().getName())) {
                continue;
            }
            byte[] signature = new byte[3];
            memory.getBytes(block.getStart(), signature);
            if ((signature[0] & 0xff) == 0x19 &&
                    (signature[1] & 0xff) == 0x82 &&
                    (signature[2] & 0xff) == 0x0f) {
                return block;
            }
        }
        return null;
    }

    private static boolean ensureDmStateBlock(Program program) throws Exception {
        AddressSpace dm = program.getAddressFactory().getAddressSpace("DM");
        if (dm == null) {
            throw new IllegalStateException("Sunplus srvdsp language has no DM address space");
        }
        Memory memory = program.getMemory();
        Address start = dm.getAddress(0);
        if (memory.getBlock(start) != null) {
            return false;
        }
        MemoryBlock block = memory.createUninitializedBlock(
            "SRVDSP_DM_STATE", start, DM_STATE_SIZE_BYTES, false);
        block.setRead(true);
        block.setWrite(true);
        block.setExecute(false);
        block.setVolatile(false);
        block.setComment(
            "Backing data-memory region for srvdsp state used by recovered wrapper actions.");
        return true;
    }

    static Set<Long> collectLocalHandlerTargets(Program program, AddressSpace pm) throws Exception {
        Set<Long> targets = new LinkedHashSet<>();
        for (long slot = 0; slot < VECTOR_WORDS; slot++) {
            Address address = pmWord(pm, PM_BASE + slot);
            int word = readWord24(program, address);
            if (!isUnconditionalDirectJump(word)) {
                throw new IllegalStateException(
                    "Unexpected srvdsp vector word at " + address + ": 0x" +
                    Integer.toHexString(word));
            }
            long target = jumpTarget(word);
            if (target >= CODE_FIRST && target <= CODE_LAST && target != DEFAULT_VECTOR_TARGET) {
                targets.add(target);
            }
        }
        return targets;
    }

    static int readWord24(Program program, Address address) throws Exception {
        byte[] bytes = new byte[3];
        program.getMemory().getBytes(address, bytes);
        return ((bytes[0] & 0xff) << 16) |
            ((bytes[1] & 0xff) << 8) |
            (bytes[2] & 0xff);
    }

    static boolean isUnconditionalDirectJump(int word) {
        int type10 = (word >>> 19) & 0x1f;
        int call = (word >>> 18) & 1;
        int cond = word & 0xf;
        return type10 == 3 && call == 0 && cond == 0xf;
    }

    static long jumpTarget(int word) {
        return (word >>> 4) & 0x3fffL;
    }

    static int countMissingInstructions(Program program, AddressSpace pm) {
        int missing = 0;
        for (long off = CODE_FIRST; off <= CODE_LAST; off++) {
            if (program.getListing().getInstructionAt(pmWord(pm, off)) == null) {
                missing++;
            }
        }
        return missing;
    }
}
