// Rebase, disassemble, and seed functions for the recovered srvdsp.bin image.
// The image carries a 32-word vector table at effective PM:0x1800; local
// handlers occupy PM:0x1820..0x1894.  Resident targets outside this image are
// intentionally left as external flows.

import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;

public class SunplusSrvdspAnalyze extends GhidraScript {
    private static final long EXPECTED_BASE = 0x1800L;
    private static final long VECTOR_WORDS = 32L;
    private static final long CODE_FIRST = 0x1820L;
    private static final long CODE_LAST = 0x1894L;
    private static final long DEFAULT_VECTOR_TARGET = 0x1895L;
    private static final long EXPECTED_SIZE_BYTES = 1128L;

    private AddressSpace pm;

    private Address pmWord(long wordAddress) {
        return pm.getAddress(wordAddress * pm.getAddressableUnitSize());
    }

    private int readWord24(Address address) throws Exception {
        byte[] bytes = new byte[3];
        currentProgram.getMemory().getBytes(address, bytes);
        return ((bytes[0] & 0xff) << 16) |
            ((bytes[1] & 0xff) << 8) |
            (bytes[2] & 0xff);
    }

    private boolean isUnconditionalDirectJump(int word) {
        int type10 = (word >>> 19) & 0x1f;
        int call = (word >>> 18) & 1;
        int cond = word & 0xf;
        return type10 == 3 && call == 0 && cond == 0xf;
    }

    private long jumpTarget(int word) {
        return (word >>> 4) & 0x3fffL;
    }

    private void ensureImageBase() throws Exception {
        Address desired = pmWord(EXPECTED_BASE);
        if (currentProgram.getImageBase().equals(desired)) {
            return;
        }
        int tx = currentProgram.startTransaction("Rebase srvdsp to recovered PM base");
        boolean commit = false;
        try {
            currentProgram.setImageBase(desired, true);
            commit = true;
        }
        finally {
            currentProgram.endTransaction(tx, commit);
        }
        println("Rebased srvdsp to " + desired);
    }

    private Set<Long> collectHandlerTargets() throws Exception {
        Set<Long> targets = new LinkedHashSet<>();
        for (long slot = 0; slot < VECTOR_WORDS; slot++) {
            Address address = pmWord(EXPECTED_BASE + slot);
            int word = readWord24(address);
            if (!isUnconditionalDirectJump(word)) {
                throw new AssertionError(
                    "Unexpected vector word at " + address + ": 0x" +
                    Integer.toHexString(word));
            }
            long target = jumpTarget(word);
            if (target >= CODE_FIRST && target <= CODE_LAST &&
                    target != DEFAULT_VECTOR_TARGET) {
                targets.add(target);
            }
        }
        return targets;
    }

    private void disassembleRecoveredCode() throws Exception {
        for (long off = EXPECTED_BASE; off <= CODE_LAST; off++) {
            Address address = pmWord(off);
            if (currentProgram.getListing().getInstructionAt(address) == null) {
                if (!disassemble(address)) {
                    throw new AssertionError("Unable to disassemble " + address);
                }
            }
        }
    }

    private int seedFunctions(Set<Long> targets) throws Exception {
        int created = 0;
        for (long target : targets) {
            Address entry = pmWord(target);
            Function existing = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (existing != null) {
                continue;
            }
            String name = String.format("srvdsp_handler_%04x", target);
            Function function = createFunction(entry, name);
            if (function == null) {
                throw new AssertionError("Unable to create function at " + entry);
            }
            created++;
        }
        return created;
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new AssertionError("No current program");
        }
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            throw new AssertionError("Unexpected language: " + currentProgram.getLanguageID());
        }
        Memory memory = currentProgram.getMemory();
        if (memory.getSize() != EXPECTED_SIZE_BYTES) {
            throw new AssertionError(
                "Unexpected srvdsp size: " + memory.getSize() + " bytes");
        }
        pm = currentProgram.getAddressFactory().getAddressSpace("PM");
        if (pm == null) {
            throw new AssertionError("PM address space is missing");
        }

        ensureImageBase();
        Set<Long> targets = collectHandlerTargets();
        if (targets.size() != 9) {
            throw new AssertionError("Expected 9 local vector handlers, got " + targets);
        }
        disassembleRecoveredCode();
        int created = seedFunctions(targets);
        analyzeAll(currentProgram);

        int missing = 0;
        for (long off = EXPECTED_BASE; off <= CODE_LAST; off++) {
            if (currentProgram.getListing().getInstructionAt(pmWord(off)) == null) {
                missing++;
            }
        }
        int functionCount = currentProgram.getFunctionManager().getFunctionCount();
        println("SUNPLUS_SRVDSP_ANALYZE handlers=" + targets.size() +
            " created=" + created + " functions=" + functionCount +
            " missing_code_words=" + missing);
        if (missing != 0) {
            throw new AssertionError("Undefined instructions remain in recovered code: " + missing);
        }
        if (functionCount < 9) {
            throw new AssertionError("Expected at least 9 srvdsp functions, got " + functionCount);
        }
    }
}
