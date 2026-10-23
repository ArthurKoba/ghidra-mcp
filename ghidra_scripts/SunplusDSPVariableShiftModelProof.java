//@category Sunplus/Architecture
// Read-only model differential. Decode the same original native words using
// an explicit baseline language and the current candidate; no Program imports,
// instruction refreshes, or firmware execution claims. apply-safe stores only
// a model-proof option after the same read-only verification succeeds.
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.util.DefaultLanguageService;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class SunplusDSPVariableShiftModelProof extends GhidraScript {
    private SleighLanguage baselineLanguage;
    private SleighLanguage candidateLanguage;

    private int actualStale;
    private int selectedNativeForms;
    private int unchangedNativeForms;
    private static final String ISA = "SunplusSPHEAudioDSP:BE:16:default";
    private static final String OPTION_GROUP = "RUSH DSP Variable Shift Model";
    private static final String OPTION_KEY = "Native execution proof";
    private enum Family { LOGICAL_LO_REGISTER, ARITH_LO_REGISTER, ARITH_LO_DM_READ, ARITH_LO_DM_WRITE, LOGICAL_LO_BARE }
    private record Site(Instruction old, PseudoInstruction fresh, Family family,
        byte[] bytes, String oldPcode, String freshPcode, String owner, String scope) {}
    private record Result(byte[] registers, byte[] dm, byte[] pm, String userops, String counter) {}

    private void need(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private int count(PcodeOp[] ops, int opcode) {
        int n = 0;
        for (PcodeOp op : ops) if (op.getOpcode() == opcode) n++;
        return n;
    }

    private String pcode(Instruction ins) {
        StringBuilder out = new StringBuilder();
        for (PcodeOp op : ins.getPcode()) out.append(op).append(';');
        return out.toString();
    }

    // Recompilation may relocate unique-space temporaries without changing
    // operations. Canonicalize their individual bytes, retaining overlap.
    private String normalizedNode(Varnode value, Map<Long,Integer> uniqueBytes) {
        if (value == null) return "-";
        if (!value.isUnique()) return value.getAddress().getAddressSpace().getName() + ":" + value.getOffset() + ":" + value.getSize();
        StringBuilder result = new StringBuilder("u[");
        for (int n = 0; n < value.getSize(); n++) {
            long at = value.getOffset() + n;
            if (!uniqueBytes.containsKey(at)) uniqueBytes.put(at, uniqueBytes.size());
            result.append(uniqueBytes.get(at)).append(',');
        }
        return result.append(']').toString();
    }

    private String normalizedPcode(Instruction ins) {
        Map<Long,Integer> uniqueBytes = new HashMap<>(); StringBuilder result = new StringBuilder();
        for (PcodeOp op : ins.getPcode()) {
            result.append(op.getOpcode()).append(':').append(normalizedNode(op.getOutput(), uniqueBytes));
            for (Varnode input : op.getInputs()) result.append('|').append(normalizedNode(input, uniqueBytes));
            result.append(';');
        }
        return result.toString();
    }

    private Family family(byte[] raw) {
        if (raw.length != 3) return null;
        int word = ((raw[0] & 255) << 16) | ((raw[1] & 255) << 8) | (raw[2] & 255);
        int opcode = (word >>> 16) & 255;
        int sf = (word >>> 11) & 15;
        // Type 16 leaves bit 15 unconstrained, as does the native constructor.
        // ShiftX selector 1 has no defined operand in this language.
        if (opcode == 0x0e && sf == 2 && ((word >>> 4) & 15) == 0 &&
            (word & 15) == 15 && ((word >>> 8) & 7) != 1) return Family.LOGICAL_LO_BARE;
        if (opcode == 0x10 && sf == 2) return Family.LOGICAL_LO_REGISTER;
        if (opcode == 0x10 && sf == 6) return Family.ARITH_LO_REGISTER;
        if ((word >>> 17) == 9 && sf == 6)
            return ((word >>> 15) & 1) == 0 ? Family.ARITH_LO_DM_READ : Family.ARITH_LO_DM_WRITE;
        return null;
    }

    private PseudoInstruction parseWith(Instruction ins, Language language) throws Exception {
        return parseWith(ins, language, Map.of());
    }

    private PseudoInstruction parseWith(Instruction ins, Language language, Map<String,BigInteger> overrides) throws Exception {
        Address at = language.getAddressFactory().getAddressSpace(ins.getAddress().getAddressSpace().getName()).getAddress(ins.getAddress().getOffset());
        ByteMemBufferImpl buffer = new ByteMemBufferImpl(at, ins.getBytes(), true);
        ProcessorContextImpl context = new ProcessorContextImpl(language);
        for (Register reg : language.getContextRegisters()) {
            Register saved = currentProgram.getProgramContext().getRegister(reg.getName());
            need(saved != null && saved.getNumBytes() == reg.getNumBytes(), "Context schema changed " + reg.getName());
            BigInteger value = currentProgram.getProgramContext().getValue(saved, ins.getAddress(), false);
            if (value != null) context.setValue(reg, value);
        }
        for (var entry : overrides.entrySet()) {
            Register reg = language.getRegister(entry.getKey());
            need(reg != null && reg.isProcessorContext(), "Unknown local context override " + entry.getKey());
            context.setValue(reg, entry.getValue());
        }
        var prototype = language.parse(buffer, context, false);
        return new PseudoInstruction(language.getAddressFactory(), at,
            prototype, buffer, context);
    }

    private String nativeFlow(Instruction ins) {
        StringBuilder result = new StringBuilder(ins.getFlowType().toString());
        for (Address at : ins.getFlows()) result.append('|').append(at.getAddressSpace().getName()).append(':').append(at.getOffset());
        return result.toString();
    }

    private List<Site> candidates() throws Exception {
        List<Site> sites = new ArrayList<>();
        int examined = 0;
        for (Instruction actual : currentProgram.getListing().getInstructions(true)) {
            monitor.checkCancelled();
            if (!"PM".equals(actual.getAddress().getAddressSpace().getName())) continue;
            need(++examined <= 20000, "Native corpus exceeds bounded audit inventory");
            need(actual.getLength() == 3, "Unexpected native instruction width " + actual.getAddress());
            Family kind = family(actual.getBytes());
            if (kind == null) continue;
            selectedNativeForms++;
            Instruction old = parseWith(actual, baselineLanguage);
            PseudoInstruction fresh = parseWith(actual, candidateLanguage);
            need(old.toString().equals(fresh.toString()) && Arrays.equals(old.getBytes(), fresh.getBytes()),
                "Native encoding/mnemonic changed " + old.getAddress());
            boolean stale = !actual.toString().equals(fresh.toString()) ||
                !normalizedPcode(actual).equals(normalizedPcode(fresh)) ||
                !nativeFlow(actual).equals(nativeFlow(fresh));
            if (stale) {
                actualStale++;
                println("DSP_VARSHIFT_ACTUAL_STALE at=" + actual.getAddress() + " family=" + kind);
            }
            String previous = pcode(old);
            String updated = pcode(fresh);
            if (previous.equals(updated) || normalizedPcode(old).equals(normalizedPcode(fresh))) {
                unchangedNativeForms++;
                println("DSP_VARSHIFT_UNCHANGED at=" + actual.getAddress() + " family=" + kind +
                    " normalized_pcode_match=true actual_stale=" + stale);
                continue;
            }
            int oldBranches = count(old.getPcode(), PcodeOp.CBRANCH);
            int freshBranches = count(fresh.getPcode(), PcodeOp.CBRANCH);
            need(oldBranches == freshBranches + 1,
                "Unexpected variable shift P-code delta " + old.getAddress() + " " + oldBranches + "->" + freshBranches);
            verifyShape(old, fresh, kind);
            Function owner = currentProgram.getFunctionManager().getFunctionContaining(actual.getAddress());
            need(owner != null && !owner.isExternal(), "Unowned native candidate " + old.getAddress());
            sites.add(new Site(old, fresh, kind, old.getBytes(), previous, updated, owner.getEntryPoint().toString(), "NATIVE"));
        }
        need(selectedNativeForms == unchangedNativeForms + sites.size(), "Selected native form inventory is incomplete");
        need(sites.size() <= 1500, "Too many native algebraic candidates");
        return sites;
    }

    private void verifyShape(Instruction old, Instruction fresh, Family kind) {
        boolean bare = kind == Family.LOGICAL_LO_BARE;
        boolean logical = bare || kind == Family.LOGICAL_LO_REGISTER;
        boolean operandShape = bare ? old.toString().endsWith(" (LO)") && !old.toString().contains(",") :
            old.toString().contains("(LO),");
        need(old.toString().startsWith(logical ? "SR = LSHIFT " : "SR = ASHIFT ") &&
            operandShape, "Shift selector/native mnemonic mismatch " + old.getAddress());
        need(nativeFlow(old).equals(nativeFlow(fresh)), "Variable shift changed native flow " + old.getAddress());
        need(count(old.getPcode(), PcodeOp.CBRANCH) == count(fresh.getPcode(), PcodeOp.CBRANCH) + 1 &&
            count(old.getPcode(), PcodeOp.BRANCH) == count(fresh.getPcode(), PcodeOp.BRANCH) + 1,
            "Expected exactly one internal conditional and unconditional branch removed " + old.getAddress());
        for (int opcode : new int[]{PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT})
            need(count(old.getPcode(), opcode) == count(fresh.getPcode(), opcode), "Native shift operation inventory changed " + old.getAddress());
        need(count(old.getPcode(), PcodeOp.CALLOTHER) == 0 && count(fresh.getPcode(), PcodeOp.CALLOTHER) == 0,
            "Opaque userop in variable shift proof " + old.getAddress());
    }

    private List<Site> withLocalCeVariants(List<Site> nativeSites) throws Exception {
        List<Site> proofSites = new ArrayList<>(nativeSites);
        EnumSet<Family> sampled = EnumSet.noneOf(Family.class);
        Map<String,BigInteger> ce = Map.of("codec_ce_loop_end", BigInteger.ONE,
            "codec_ce_phase", BigInteger.ZERO, "codec_ce_nested_mode", BigInteger.ZERO,
            "codec_ce_direct_backedge", BigInteger.ZERO);
        for (Site source : nativeSites) {
            if (!sampled.add(source.family())) continue;
            Address at = currentProgram.getAddressFactory().getAddressSpace("PM").getAddress(source.old().getAddress().getOffset());
            Instruction actual = currentProgram.getListing().getInstructionAt(at);
            need(actual != null, "Missing original native instruction for local CE model test");
            Instruction old = parseWith(actual, baselineLanguage, ce);
            PseudoInstruction fresh = parseWith(actual, candidateLanguage, ce);
            verifyShape(old, fresh, source.family());
            need(writesRegister(old, "CNTR") && writesRegister(fresh, "CNTR"), "Local CE model test missing counter suffix");
            proofSites.add(new Site(old, fresh, source.family(), actual.getBytes(), pcode(old), pcode(fresh), source.owner(), "LOCAL_CE_VARIANT"));
        }
        return proofSites;
    }

    public final class Pm24Library extends AnnotatedPcodeUseropLibrary<byte[]> {
        private final AddressSpace pm;
        private final StringBuilder trace = new StringBuilder();
        Pm24Library(SleighLanguage language) { pm = language.getAddressFactory().getAddressSpace("PM"); }
        private long word(byte[] bytes) {
            need(bytes.length == 2, "PM userop requires 16-bit word address");
            return ((bytes[0] & 255L) << 8) | (bytes[1] & 255L);
        }
        @PcodeUserop(hasSideEffects=true)
        public byte[] dsp_pm_load24(@OpExecutor PcodeExecutor<byte[]> executor, byte[] address) {
            long offset = word(address);
            trace.append('L').append(offset).append(';');
            return executor.getState().getVar(pm, offset, 3, true, executor.getReason());
        }
        @PcodeUserop(hasSideEffects=true)
        public void dsp_pm_store24(@OpExecutor PcodeExecutor<byte[]> executor, byte[] address, byte[] value) {
            need(value.length == 3, "PM userop requires complete 24-bit value");
            long offset = word(address);
            trace.append('S').append(offset).append('=').append(HexFormat.of().formatHex(value)).append(';');
            executor.getState().setVar(pm, offset, 3, true, value);
        }
    }

    private byte[] bigEndian(long value, int size) {
        byte[] bytes = new byte[size];
        for (int index = size - 1; index >= 0; index--) { bytes[index] = (byte)value; value >>>= 8; }
        return bytes;
    }

    private void set(PcodeThread<byte[]> thread, String name, long value) {
        Register reg = thread.getLanguage().getRegister(name);
        need(reg != null, "Required native register absent " + name);
        thread.getState().setVar(reg, bigEndian(value, reg.getNumBytes()));
    }

    private Result execute(Instruction instruction, SleighLanguage language, int x, int encodedSe, int counter, int variant) throws Exception {
        Pm24Library pmUseropLibrary = new Pm24Library(language);
        PcodeEmulator emulator = new PcodeEmulator(language) {
            @Override protected PcodeUseropLibrary<byte[]> createUseropLibrary() { return pmUseropLibrary; }
        };
        PcodeThread<byte[]> thread = emulator.newThread();
        for (String name : new String[]{"dsp_pm_load24", "dsp_pm_store24"})
            need(pmUseropLibrary.getUserops().containsKey(name) &&
                thread.getUseropLibrary().getUserops().get(name) == pmUseropLibrary.getUserops().get(name),
                "Explicit PM24 userop binding missing or replaced " + name);
        AddressSpace registers = language.getAddressFactory().getRegisterSpace();
        AddressSpace dm = language.getAddressFactory().getAddressSpace("DM");
        AddressSpace pm = language.getAddressFactory().getAddressSpace("PM");
        byte[] registerSeed = new byte[0x200];
        for (int n = 0; n < registerSeed.length; n++) registerSeed[n] = (byte)(n * 29 + 13);
        thread.getState().setVar(registers, 0L, registerSeed.length, false, registerSeed);
        byte[] dataSeed = new byte[0x8000];
        byte[] programSeed = new byte[0x3000];
        for (int n = 0; n < dataSeed.length; n++) dataSeed[n] = (byte)(n * 37 + variant * 11);
        for (int n = 0; n < programSeed.length; n++) programSeed[n] = (byte)(n * 43 + variant * 7);
        emulator.getSharedState().setVar(dm, 0L, dataSeed.length, false, dataSeed);
        emulator.getSharedState().setVar(pm, 0L, programSeed.length, false, programSeed);
        for (String reg : new String[]{"SI", "AR", "MR0", "MR1", "MR2", "SR0", "SR1"}) set(thread, reg, x);
        set(thread, "SE", encodedSe);
        for (int n = 0; n < 8; n++) {
            set(thread, "I" + n, 0x200 + n * 16 + (variant & 3));
            set(thread, "M" + n, (n & 1) == 0 ? 1 : 0xffff);
            set(thread, "L" + n, (variant & 1) == 0 ? 0 : 8);
        }
        set(thread, "MSTAT", (variant & 2) == 0 ? 0 : 2);
        set(thread, "CNTR", counter);
        set(thread, "DSP_LOOP_DEPTH", 1 + (variant & 3));
        set(thread, "DSP_COUNT_DEPTH", variant & 3);
        set(thread, "DSP_LOOP_START", 0x180);
        set(thread, "DSP_LOOP_START_SHADOW", 0x190);
        set(thread, "DSP_LOOP_START_SHADOW2", 0x1a0);
        set(thread, "DSP_LOOP_START_SHADOW3", 0x1b0);
        set(thread, "DSP_LOOP_COUNT_SHADOW", 7);
        set(thread, "DSP_STATIC_START_OUTER", 0x1c0);
        set(thread, "DSP_STATIC_START_INNER", 0x1d0);
        set(thread, "DSP_STATIC_CNTR_OUTER", 9);
        for (int n = 0; n < 4; n++) set(thread, "DSP_COUNT" + n, 3 + n);
        set(thread, "ANF", 0x55); set(thread, "AVF", 0xaa); set(thread, "AZF", 0xff); set(thread, "MVF", 1);
        // Raw P-code frames do not perform the implicit native fallthrough.
        // Both models keep the same implicit fallthrough and any native CE backedge.
        set(thread, "PC", instruction.getAddress().add(3).getAddressableWordOffset());
        thread.setCounter(instruction.getAddress().add(3));
        PcodeProgram program = PcodeProgram.fromInstruction(instruction);
        thread.getExecutor().execute(program, thread.getUseropLibrary());
        return new Result(thread.getState().getVar(registers, 0L, registerSeed.length, false, Reason.INSPECT),
            emulator.getSharedState().getVar(dm, 0L, dataSeed.length, false, Reason.INSPECT),
            emulator.getSharedState().getVar(pm, 0L, programSeed.length, false, Reason.INSPECT), pmUseropLibrary.trace.toString(), thread.getCounter().getAddressSpace().getName() + ":" + thread.getCounter().getOffset());
    }

    private static final int[] SE_CASES = {0x8000,0x8001,0xff00,0xff80,0xffdf,0xffe0,0xffe1,
        0xfff0,0xfff1,0xffff,0,1,15,16,31,32,33,127,128,255,256,0x7fff};
    private static final int[] SOURCE_CASES = {0,1,0x7fff,0x8000,0xffff,0x5555,0xaaaa};

    private void compare(Site site, int x, int se, int counter, int variant) throws Exception {
        Result previous = execute(site.old(), baselineLanguage, x, se, counter, variant);
        Result updated = execute(site.fresh(), candidateLanguage, x, se, counter, variant);
        need(Arrays.equals(previous.registers(), updated.registers()) && Arrays.equals(previous.dm(), updated.dm()) &&
            Arrays.equals(previous.pm(), updated.pm()) && previous.userops().equals(updated.userops()) &&
            previous.counter().equals(updated.counter()),
            "Native P-code equivalence conflict at=" + site.old().getAddress() + " family=" + site.family() +
            " scope=" + site.scope() + " x=" + x + " SE=" + se + " CNTR=" + counter + " variant=" + variant);
    }

    private int verify(List<Site> sites) throws Exception {
        int cases = 0;
        for (Site site : sites) {
            monitor.checkCancelled();
            int before = cases;
            for (int se : SE_CASES) for (int source : SOURCE_CASES) for (int counter : new int[]{1,2}) {
                monitor.checkCancelled();
                compare(site, source, se, counter, counter == 1 ? 0 : 3);
                cases++;
            }
            println("DSP_VARSHIFT_NATIVE_EQUIVALENCE at=" + site.old().getAddress() + " family=" + site.family() +
                " owner=" + site.owner() + " scope=" + site.scope() + " cases=" + (cases - before) + " all_registers_DM_PM=true");
        }
        long nativeSites = sites.stream().filter(site -> site.scope().equals("NATIVE")).count();
        println("DSP_VARSHIFT_MODEL_PASS native_sites=" + nativeSites + " local_ce_sites=" + (sites.size() - nativeSites) +
            " cases=" + cases + " hardware=UNKNOWN");
        return cases;
    }

    private boolean writesRegister(Instruction ins, String name) {
        Register reg = currentProgram.getRegister(name);
        need(reg != null, "Missing modeled register " + name);
        for (PcodeOp op : ins.getPcode()) {
            Varnode out = op.getOutput();
            if (out != null && out.isRegister() && out.getOffset() < reg.getAddress().getOffset() + reg.getNumBytes() &&
                out.getOffset() + out.getSize() > reg.getAddress().getOffset()) return true;
        }
        return false;
    }

    private void verifySchema() {
        need(!baselineLanguage.getLanguageID().equals(candidateLanguage.getLanguageID()), "Baseline must be a distinct explicit language variant");
        need(baselineLanguage.isBigEndian() && candidateLanguage.isBigEndian(), "Expected matching big-endian models");
        for (String name : new String[]{"PM", "DM", "IO", "register"}) {
            AddressSpace old = baselineLanguage.getAddressFactory().getAddressSpace(name);
            AddressSpace fresh = candidateLanguage.getAddressFactory().getAddressSpace(name);
            need(old != null && fresh != null && old.getAddressableUnitSize() == fresh.getAddressableUnitSize() && old.getSize() == fresh.getSize(),
                "Address-space schema mismatch " + name);
        }
        for (Register current : candidateLanguage.getRegisters()) {
            Register previous = baselineLanguage.getRegister(current.getName());
            need(previous != null && previous.getNumBytes() == current.getNumBytes() && previous.getAddress().getOffset() == current.getAddress().getOffset(),
                "Register schema mismatch " + current.getName());
        }
    }

    private int plannedCases(List<Site> sites) {
        return sites.size() * SE_CASES.length * SOURCE_CASES.length * 2;
    }

    private String proofAnnotation(List<Site> sites, String sourceSha) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (Site site : sites) {
            String identity = site.old().getAddress().getAddressSpace().getName() + ":" +
                site.old().getAddress().getOffset() + ":" + site.owner() + ":" + site.family() + ":" + site.scope() + ":" +
                HexFormat.of().formatHex(site.bytes()) + ":" + normalizedPcode(site.old()) + ":" + normalizedPcode(site.fresh());
            digest.update(identity.getBytes(StandardCharsets.UTF_8));
            digest.update((byte)'\n');
        }
        return "CONFIRMED-MODEL version=1 image=" + sourceSha +
            " baseline_language=" + baselineLanguage.getLanguageID() + " candidate_language=" + candidateLanguage.getLanguageID() +
            " proof_sites=" + sites.size() + " cases=" + plannedCases(sites) +
            " model_digest=" + HexFormat.of().formatHex(digest.digest()) +
            " actual_stale=0 native_C=NOT_CHECKED hardware=UNKNOWN";
    }

    private void materialize(String annotation) {
        int transaction = currentProgram.startTransaction("Record native variable shift model execution proof");
        boolean committed = false;
        try {
            currentProgram.getOptions(OPTION_GROUP).setString(OPTION_KEY, annotation);
            need(annotation.equals(currentProgram.getOptions(OPTION_GROUP).getString(OPTION_KEY, "")), "Proof option readback mismatch");
            committed = true;
        } finally {
            currentProgram.endTransaction(transaction, committed);
        }
        println("DSP_VARSHIFT_MATERIALIZED_PASS option_group=" + OPTION_GROUP + " option_key=" + OPTION_KEY +
            " instruction_refreshes=0 native_C=NOT_CHECKED caller_save_required=true");
    }

    public void run() throws Exception {
        need(currentProgram != null && ISA.equals(currentProgram.getLanguageID().toString()), "Expected current native Sunplus DSP variable shift program");
        String[] args = getScriptArgs();
        need(args.length == 3 && Set.of("audit", "verify-model", "apply-safe").contains(args[0]), "Use audit|verify-model|apply-safe BASELINE_LANGUAGE_ID ORIGINAL_EXECUTABLE_SHA");
        need(args[2].equals(currentProgram.getExecutableSHA256()), "Original executable SHA mismatch");
        candidateLanguage = (SleighLanguage)currentProgram.getLanguage();
        baselineLanguage = (SleighLanguage)DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(args[1]));
        verifySchema();
        boolean changed = currentProgram.isChanged(); int version = currentProgram.getDomainFile().getVersion();
        List<Site> sites = candidates(); Map<Family,Integer> families = new EnumMap<>(Family.class);
        for (Site site : sites) families.merge(site.family(), 1, Integer::sum);
        println("DSP_VARSHIFT_PLAN program=" + currentProgram.getName() + " model_sites=" + sites.size() +
            " actual_stale=" + actualStale + " selected_native_forms=" + selectedNativeForms +
            " unchanged_native_forms=" + unchangedNativeForms + " families=" + families +
            " baseline_language=" + baselineLanguage.getLanguageID() + " candidate_language=" + candidateLanguage.getLanguageID() + " mode=" + args[0]);
        need(actualStale == 0, "Actual instruction semantics are stale; no refresh is authorized by this proof script");
        List<Site> proofSites = withLocalCeVariants(sites);
        println("DSP_VARSHIFT_LOCAL_CE_PLAN variants=" + (proofSites.size() - sites.size()) +
            " scope=LOCAL_CONTEXT_ONLY actual_ProgramContext_changes=0");
        String annotation = proofAnnotation(proofSites, args[2]);
        String stored = currentProgram.getOptions(OPTION_GROUP).getString(OPTION_KEY, "");
        println("DSP_VARSHIFT_MATERIALIZED_READBACK present=" + !stored.isEmpty() + " matches_current_plan=" + annotation.equals(stored));
        if (args[0].equals("audit")) {
            for (Site site : sites) println("DSP_VARSHIFT_SITE at=" + site.old().getAddress() + " owner=" + site.owner() + " family=" + site.family() + " text=" + site.old());
            println("DSP_VARSHIFT_AUDIT_PASS");
        } else {
            need(!sites.isEmpty(), "No changed native sites: no new execution proof was performed");
            need(verify(proofSites) == plannedCases(proofSites), "Native execution case inventory differs from proof annotation");
        }
        need(changed == currentProgram.isChanged() && version == currentProgram.getDomainFile().getVersion(), "Read-only differential changed saved program");
        println("DSP_VARSHIFT_READONLY_PASS source=" + args[2] + " C_not_modified=true");
        if (args[0].equals("apply-safe")) materialize(annotation);
    }
}
