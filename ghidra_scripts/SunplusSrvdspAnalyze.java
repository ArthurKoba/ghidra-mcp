// Rebase, disassemble, and seed functions for the recovered srvdsp.bin image.
// The image carries a 32-word vector table at effective PM:0x1800; local
// handlers occupy PM:0x1820..0x1894.  Resident targets outside this image are
// intentionally left as external flows.

import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.framework.options.Options;

public class SunplusSrvdspAnalyze extends GhidraScript {
    private static final long EXPECTED_BASE = 0x1800L;
    private static final long VECTOR_WORDS = 32L;
    private static final long CODE_FIRST = 0x1820L;
    private static final long CODE_LAST = 0x1894L;
    private static final long DEFAULT_VECTOR_TARGET = 0x1895L;
    private static final long EXPECTED_SIZE_BYTES = 1128L;
    private static final long DM_STATE_SIZE_BYTES = 0x300L;
    private static final int ANALYSIS_MODEL_VERSION = 3;
    private static final String ANALYSIS_OPTIONS = "Sunplus SPHE Audio DSP";
    private static final String MODEL_VERSION_OPTION = "srvdsp.analysis_model_version";
    private static final String WRAPPER_CONTEXT_REGISTER = "srvdsp_wrapper_mode";
    private static final long[] MODEL_REFRESH_WORDS = {
        0x1823L, 0x183dL, 0x1842L, 0x1847L, 0x184eL, 0x1853L, 0x1854L,
        0x1866L, 0x186bL, 0x186cL, 0x186eL, 0x1875L, 0x1878L, 0x1879L,
        0x188cL, 0x188eL, 0x1890L, 0x1894L
    };

    private AddressSpace pm;

    private Address pmWord(long wordAddress) {
        return pm.getAddress(wordAddress * pm.getAddressableUnitSize());
    }

    private MemoryBlock findCanonicalPmImageBlock() throws Exception {
        Memory memory = currentProgram.getMemory();
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

    private void ensureDmStateBlock() throws Exception {
        AddressSpace dm = currentProgram.getAddressFactory().getAddressSpace("DM");
        if (dm == null) {
            throw new AssertionError("DM address space is missing");
        }
        Memory memory = currentProgram.getMemory();
        Address start = dm.getAddress(0);
        if (memory.getBlock(start) != null) {
            return;
        }
        int tx = currentProgram.startTransaction("Create srvdsp DM state backing");
        boolean commit = false;
        try {
            MemoryBlock block = memory.createUninitializedBlock(
                "SRVDSP_DM_STATE", start, DM_STATE_SIZE_BYTES, false);
            block.setRead(true);
            block.setWrite(true);
            block.setExecute(false);
            block.setVolatile(false);
            block.setComment(
                "Backing data-memory region for srvdsp state used by recovered wrapper actions.");
            commit = true;
        }
        finally {
            currentProgram.endTransaction(tx, commit);
        }
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

    private void ensureSrvdspDecodeContext() throws Exception {
        ProgramContext context = currentProgram.getProgramContext();
        Register wrapperMode = context.getRegister(WRAPPER_CONTEXT_REGISTER);
        if (wrapperMode == null) {
            throw new AssertionError("Missing wrapper context register: " + WRAPPER_CONTEXT_REGISTER);
        }
        Address start = pmWord(EXPECTED_BASE);
        Address end = pmWord(EXPECTED_BASE + (EXPECTED_SIZE_BYTES / 3L) - 1L);
        context.setValue(wrapperMode, start, end, BigInteger.ONE);
    }

    private void ensureInstructionModelRevision() throws Exception {
        Options options = currentProgram.getOptions(ANALYSIS_OPTIONS);
        int storedVersion = options.getInt(MODEL_VERSION_OPTION, 0);
        if (storedVersion >= ANALYSIS_MODEL_VERSION) {
            return;
        }

        Listing listing = currentProgram.getListing();
        int tx = currentProgram.startTransaction("Refresh srvdsp processor model");
        boolean commit = false;
        try {
            for (long word : MODEL_REFRESH_WORDS) {
                Address start = pmWord(word);
                Address end = start.add(pm.getAddressableUnitSize() - 1L);
                listing.clearCodeUnits(start, end, false);
                if (!disassemble(start) || listing.getInstructionAt(start) == null) {
                    throw new AssertionError(
                        "Unable to refresh srvdsp instruction model at " + start);
                }
            }
            options.setInt(MODEL_VERSION_OPTION, ANALYSIS_MODEL_VERSION);
            commit = true;
        }
        finally {
            currentProgram.endTransaction(tx, commit);
        }
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
            Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (function == null) {
                String name = String.format("srvdsp_handler_%04x", target);
                function = createFunction(entry, name);
                if (function == null) {
                    throw new AssertionError("Unable to create function at " + entry);
                }
                created++;
            }
            if (function.getSignatureSource() != SourceType.USER_DEFINED &&
                    function.getReturnType().getName().startsWith("undefined")) {
                function.setReturnType(VoidDataType.dataType, SourceType.ANALYSIS);
            }
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
        if (findCanonicalPmImageBlock() == null) {
            throw new AssertionError("Canonical srvdsp PM image/signature not found");
        }
        pm = currentProgram.getAddressFactory().getAddressSpace("PM");
        if (pm == null) {
            throw new AssertionError("PM address space is missing");
        }

        ensureImageBase();
        ensureDmStateBlock();
        ensureSrvdspDecodeContext();
        Set<Long> targets = collectHandlerTargets();
        if (targets.size() != 9) {
            throw new AssertionError("Expected 9 local vector handlers, got " + targets);
        }
        disassembleRecoveredCode();
        ensureInstructionModelRevision();
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
