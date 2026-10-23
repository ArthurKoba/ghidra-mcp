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

public class SunplusDSPBranchlessModelProof extends GhidraScript {
    private SleighLanguage baselineLanguage;
    private SleighLanguage candidateLanguage;
    private final Set<Long> nativeDoEndpoints = new HashSet<>();
    private int actualStale;
    private int selectedNativeForms;
    private static final String ISA = "SunplusSPHEAudioDSP:BE:16:default";
    private static final String OPTION_GROUP = "RUSH DSP Branchless Model";
    private static final String OPTION_KEY = "Native execution proof";
    private enum Family { PRODUCT_SIGN, PREDICATED_MOVE }
    private record Site(Instruction old, PseudoInstruction fresh, Family family,
        byte[] bytes, String oldPcode, String freshPcode, String owner) {}
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
        int type9 = (word >>> 19) & 31;
        int amf = (word >>> 13) & 31;
        int z = (word >>> 18) & 1;
        int mid = (word >>> 4) & 15;
        int cond = word & 15;
        if (type9 == 4 && z == 0 && amf == 16 && mid == 0 && cond == 4)
            return Family.PREDICATED_MOVE;
        if ((word >>> 22) == 3 && amf == 4) return Family.PRODUCT_SIGN;
        if (type9 == 5 && z == 0 && (amf == 4 || amf == 5 || amf == 6))
            return Family.PRODUCT_SIGN;
        if ((word >>> 21) == 3 && z == 0 && (amf == 4 ||
            (amf == 5 && ((word >>> 19) & 1) == 1))) return Family.PRODUCT_SIGN;
        if ((word >>> 20) == 5 && z == 0 && amf == 4) return Family.PRODUCT_SIGN;
        if (type9 == 4 && z == 0 && cond == 15 &&
            ((amf == 5 && mid == 0) || (amf == 4 && mid == 1 && ((word >>> 11) & 3) == 0)))
            return Family.PRODUCT_SIGN;
        return null;
    }

    private PseudoInstruction parseWith(Instruction ins, Language language) throws Exception {
        return parseWith(ins, language, null);
    }

    private PseudoInstruction parseWith(Instruction ins, Language language, BigInteger ceOverride) throws Exception {
        Address at = language.getAddressFactory().getAddressSpace(ins.getAddress().getAddressSpace().getName()).getAddress(ins.getAddress().getOffset());
        ByteMemBufferImpl buffer = new ByteMemBufferImpl(at, ins.getBytes(), true);
        ProcessorContextImpl context = new ProcessorContextImpl(language);
        for (Register reg : language.getContextRegisters()) {
            Register saved = currentProgram.getProgramContext().getRegister(reg.getName());
            need(saved != null && saved.getNumBytes() == reg.getNumBytes(), "Context schema changed " + reg.getName());
            BigInteger value = currentProgram.getProgramContext().getValue(saved, ins.getAddress(), false);
            if (value != null) context.setValue(reg, value);
        }
        if (ceOverride != null) context.setValue(language.getRegister("codec_ce_loop_end"), ceOverride);
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
                println("DSP_BRANCHLESS_ACTUAL_STALE at=" + actual.getAddress() + " family=" + kind);
            }
            String previous = pcode(old);
            String updated = pcode(fresh);
            if (previous.equals(updated) || normalizedPcode(old).equals(normalizedPcode(fresh))) continue;
            int oldBranches = count(old.getPcode(), PcodeOp.CBRANCH);
            int freshBranches = count(fresh.getPcode(), PcodeOp.CBRANCH);
            need(oldBranches == freshBranches + 1,
                "Unexpected branchless P-code delta " + old.getAddress() + " " + oldBranches + "->" + freshBranches);
            if (kind == Family.PRODUCT_SIGN) {
                need(old.toString().startsWith("MR = ") && !old.toString().startsWith("MR = MR ") &&
                    (old.toString().contains("(SS)") || old.toString().contains("(SU)") || old.toString().contains("(US)")),
                    "Product constructor selector does not match native instruction " + old.getAddress());
                need(nativeFlow(old).equals(nativeFlow(fresh)),
                    "Product arithmetic changed native control flow " + old.getAddress());
            } else {
                need(old.toString().startsWith("IF LT AR = "), "Predicated selector/mnemonic conflict");
                verifyNonCe(actual, old, fresh);
                int removed = 0;
                for (PcodeOp op : old.getPcode()) if (op.getOpcode() == PcodeOp.CBRANCH &&
                    op.getInput(0).getAddress().equals(old.getAddress().add(3))) removed++;
                need(removed == 1, "Old predicate must branch only to native fallthrough " + old.getAddress());
            }
            Function owner = currentProgram.getFunctionManager().getFunctionContaining(actual.getAddress());
            need(owner != null && !owner.isExternal(), "Unowned native candidate " + old.getAddress());
            sites.add(new Site(old, fresh, kind, old.getBytes(), previous, updated, owner.getEntryPoint().toString()));
        }
        need(sites.size() <= 1500, "Too many native algebraic candidates");
        return sites;
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

    private Result execute(Instruction instruction, SleighLanguage language, int x, int y, int anf, int avf, int azf,
                           int variant) throws Exception {
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
        for (String reg : new String[]{"MX0", "MX1", "AR", "MR0", "MR1", "MR2", "SR0", "SR1"}) set(thread, reg, x);
        for (String reg : new String[]{"MY0", "MY1", "MF", "AY0", "AY1", "AF"}) set(thread, reg, y);
        for (int n = 0; n < 8; n++) {
            set(thread, "I" + n, 0x200 + n * 16 + (variant & 3));
            set(thread, "M" + n, (n & 1) == 0 ? 1 : 0xffff);
            set(thread, "L" + n, (variant & 1) == 0 ? 0 : 8);
        }
        set(thread, "MSTAT", (variant & 2) == 0 ? 0 : 2);
        set(thread, "CNTR", (variant & 1) == 0 ? 1 : 2);
        set(thread, "DSP_LOOP_DEPTH", 1);
        set(thread, "DSP_COUNT_DEPTH", 0);
        set(thread, "ANF", anf); set(thread, "AVF", avf); set(thread, "AZF", azf); set(thread, "MVF", 1);
        // Raw P-code frames do not perform the implicit native fallthrough.
        // Starting PC at next makes old 'goto inst_next' and straightline agree.
        set(thread, "PC", instruction.getAddress().add(3).getAddressableWordOffset());
        thread.setCounter(instruction.getAddress().add(3));
        PcodeProgram program = PcodeProgram.fromInstruction(instruction);
        thread.getExecutor().execute(program, thread.getUseropLibrary());
        return new Result(thread.getState().getVar(registers, 0L, registerSeed.length, false, Reason.INSPECT),
            emulator.getSharedState().getVar(dm, 0L, dataSeed.length, false, Reason.INSPECT),
            emulator.getSharedState().getVar(pm, 0L, programSeed.length, false, Reason.INSPECT), pmUseropLibrary.trace.toString(), thread.getCounter().getAddressSpace().getName() + ":" + thread.getCounter().getOffset());
    }

    private void compare(Site site, int x, int y, int anf, int avf, int azf, int variant) throws Exception {
        Result previous = execute(site.old(), baselineLanguage, x, y, anf, avf, azf, variant);
        Result updated = execute(site.fresh(), candidateLanguage, x, y, anf, avf, azf, variant);
        need(Arrays.equals(previous.registers(), updated.registers()) && Arrays.equals(previous.dm(), updated.dm()) &&
            Arrays.equals(previous.pm(), updated.pm()) && previous.userops().equals(updated.userops()) &&
            previous.counter().equals(updated.counter()),
            "Native P-code equivalence conflict at=" + site.old().getAddress() + " family=" + site.family() +
            " x=" + x + " y=" + y + " ANF=" + anf + " AVF=" + avf + " AZF=" + azf);
    }

    private int verify(List<Site> sites) throws Exception {
        int cases = 0;
        int[][] products = {{0,0}, {0,0xffff}, {1,1}, {1,0xffff}, {0xffff,1}, {0xffff,0xffff},
            {0x7fff,0x7fff}, {0x8000,0x8000}, {0x8000,0xffff}, {0xffff,0x8000},
            {0x8000,0x7fff}, {0x7fff,0x8000}, {0x1234,0xabcd}, {0xabcd,0x1234}};
        int[][] flags = {{0,0}, {0,1}, {1,0}, {1,1}, {0x55,0x55}, {0x55,0xaa}};
        int[] words = {0,1,0x7fff,0x8000,0xffff};
        for (Site site : sites) {
            monitor.checkCancelled();
            int before = cases;
            if (site.family() == Family.PRODUCT_SIGN) {
                for (int n = 0; n < products.length; n++) {
                    compare(site, products[n][0], products[n][1], 0x55, 0xaa, 0xff, n); cases++;
                }
            } else {
                for (int[] flag : flags) for (int azf : new int[]{0,1,0xff})
                    for (int x : words) for (int y : words) {
                        monitor.checkCancelled(); compare(site, x, y, flag[0], flag[1], azf, cases & 3); cases++;
                    }
            }
            println("DSP_BRANCHLESS_NATIVE_EQUIVALENCE at=" + site.old().getAddress() + " family=" + site.family() +
                " owner=" + site.owner() + " cases=" + (cases - before) + " all_registers_DM_PM=true");
        }
        println("DSP_BRANCHLESS_MODEL_PASS native_sites=" + sites.size() + " cases=" + cases + " hardware=UNKNOWN");
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

    private boolean readsRegister(Instruction ins, String name) {
        Register reg = currentProgram.getRegister(name);
        need(reg != null, "Missing modeled register " + name);
        for (PcodeOp op : ins.getPcode()) for (Varnode input : op.getInputs())
            if (input.isRegister() && input.getOffset() < reg.getAddress().getOffset() + reg.getNumBytes() &&
                input.getOffset() + input.getSize() > reg.getAddress().getOffset()) return true;
        return false;
    }

    private void collectNativeDoEndpoints() throws Exception {
        int count = 0;
        for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
            monitor.checkCancelled();
            if (!"PM".equals(ins.getAddress().getAddressSpace().getName())) continue;
            need(++count <= 20000, "Native DO audit bound exceeded");
            byte[] raw = ins.getBytes(); need(raw.length == 3, "Unexpected native instruction width " + ins.getAddress());
            int word = ((raw[0] & 255) << 16) | ((raw[1] & 255) << 8) | (raw[2] & 255);
            boolean nativeDo = (word >>> 18) == 5;
            need(nativeDo == ins.toString().startsWith("DO "), "Native DO encoding/mnemonic mismatch " + ins.getAddress());
            if (nativeDo) nativeDoEndpoints.add((long)((word >>> 4) & 0x3fff));
        }
    }

    private void verifyNonCe(Instruction actual, Instruction old, Instruction fresh) throws Exception {
        Register ce = currentProgram.getProgramContext().getRegister("codec_ce_loop_end");
        need(ce != null, "CE context register absent");
        BigInteger value = currentProgram.getProgramContext().getValue(ce, actual.getAddress(), false);
        need(value == null || BigInteger.ZERO.equals(value), "Predicated CE endpoint needs its unchanged fallback " + actual.getAddress());
        need(!nativeDoEndpoints.contains(actual.getAddress().getAddressableWordOffset()), "Native DO targets predicated candidate " + actual.getAddress());
        need(!writesRegister(old, "CNTR") && !writesRegister(fresh, "CNTR") &&
            !readsRegister(old, "CNTR") && !readsRegister(fresh, "CNTR") && count(fresh.getPcode(), PcodeOp.CBRANCH) == 0,
            "Predicated instruction contains CE suffix or extra control semantics " + actual.getAddress());
        Instruction oldZero = parseWith(actual, baselineLanguage, BigInteger.ZERO);
        Instruction freshZero = parseWith(actual, candidateLanguage, BigInteger.ZERO);
        Instruction oldOne = parseWith(actual, baselineLanguage, BigInteger.ONE);
        Instruction freshOne = parseWith(actual, candidateLanguage, BigInteger.ONE);
        need(normalizedPcode(old).equals(normalizedPcode(oldZero)) &&
            normalizedPcode(fresh).equals(normalizedPcode(freshZero)),
            "Observed predicate context differs from explicit local CE=0 " + actual.getAddress());
        need(normalizedPcode(oldOne).equals(normalizedPcode(freshOne)) &&
            !normalizedPcode(freshOne).equals(normalizedPcode(freshZero)) &&
            writesRegister(oldOne, "CNTR") && writesRegister(freshOne, "CNTR") &&
            count(freshOne.getPcode(), PcodeOp.CBRANCH) >= 2,
            "Explicit local CE=1 must retain baseline predicate and loop suffix " + actual.getAddress());
        println("DSP_PREDICATE_NON_CE_PROOF at=" + actual.getAddress() + " context=" + (value == null ? "UNSET" : value) +
            " native_DO_target=false CNTR_reads=0 CNTR_writes=0 explicit_CE0_matches=true explicit_CE1_fallback_unchanged=true");
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
        int total = 0;
        for (Site site : sites) total += site.family() == Family.PRODUCT_SIGN ? 14 : 450;
        return total;
    }

    private String proofAnnotation(List<Site> sites, String sourceSha) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (Site site : sites) {
            String identity = site.old().getAddress().getAddressSpace().getName() + ":" +
                site.old().getAddress().getOffset() + ":" + site.owner() + ":" + site.family() + ":" +
                HexFormat.of().formatHex(site.bytes()) + ":" + normalizedPcode(site.old()) + ":" + normalizedPcode(site.fresh());
            digest.update(identity.getBytes(StandardCharsets.UTF_8));
            digest.update((byte)'\n');
        }
        return "CONFIRMED-MODEL version=1 image=" + sourceSha +
            " baseline_language=" + baselineLanguage.getLanguageID() + " candidate_language=" + candidateLanguage.getLanguageID() +
            " model_sites=" + sites.size() + " cases=" + plannedCases(sites) +
            " model_digest=" + HexFormat.of().formatHex(digest.digest()) +
            " actual_stale=0 native_C=NOT_CHECKED hardware=UNKNOWN";
    }

    private void materialize(String annotation) {
        int transaction = currentProgram.startTransaction("Record native branchless model execution proof");
        boolean committed = false;
        try {
            currentProgram.getOptions(OPTION_GROUP).setString(OPTION_KEY, annotation);
            need(annotation.equals(currentProgram.getOptions(OPTION_GROUP).getString(OPTION_KEY, "")), "Proof option readback mismatch");
            committed = true;
        } finally {
            currentProgram.endTransaction(transaction, committed);
        }
        println("DSP_BRANCHLESS_MATERIALIZED_PASS option_group=" + OPTION_GROUP + " option_key=" + OPTION_KEY +
            " instruction_refreshes=0 native_C=NOT_CHECKED caller_save_required=true");
    }

    public void run() throws Exception {
        need(currentProgram != null && ISA.equals(currentProgram.getLanguageID().toString()), "Expected current native Sunplus DSP program");
        String[] args = getScriptArgs();
        need(args.length == 3 && Set.of("audit", "verify-model", "apply-safe").contains(args[0]), "Use audit|verify-model|apply-safe BASELINE_LANGUAGE_ID ORIGINAL_EXECUTABLE_SHA");
        need(args[2].equals(currentProgram.getExecutableSHA256()), "Original executable SHA mismatch");
        candidateLanguage = (SleighLanguage)currentProgram.getLanguage();
        baselineLanguage = (SleighLanguage)DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(args[1]));
        verifySchema();
        boolean changed = currentProgram.isChanged(); int version = currentProgram.getDomainFile().getVersion();
        collectNativeDoEndpoints();
        List<Site> sites = candidates(); Map<Family,Integer> families = new EnumMap<>(Family.class);
        for (Site site : sites) families.merge(site.family(), 1, Integer::sum);
        println("DSP_BRANCHLESS_PLAN program=" + currentProgram.getName() + " model_sites=" + sites.size() +
            " actual_stale=" + actualStale + " selected_native_forms=" + selectedNativeForms + " families=" + families +
            " baseline_language=" + baselineLanguage.getLanguageID() + " candidate_language=" + candidateLanguage.getLanguageID() + " mode=" + args[0]);
        need(actualStale == 0, "Actual instruction semantics are stale; no refresh is authorized by this proof script");
        String annotation = proofAnnotation(sites, args[2]);
        String stored = currentProgram.getOptions(OPTION_GROUP).getString(OPTION_KEY, "");
        println("DSP_BRANCHLESS_MATERIALIZED_READBACK present=" + !stored.isEmpty() + " matches_current_plan=" + annotation.equals(stored));
        if (args[0].equals("audit")) {
            for (Site site : sites) println("DSP_BRANCHLESS_SITE at=" + site.old().getAddress() + " owner=" + site.owner() + " family=" + site.family() + " text=" + site.old());
            println("DSP_BRANCHLESS_AUDIT_PASS");
        } else {
            need(!sites.isEmpty(), "No changed native sites: no new execution proof was performed");
            need(verify(sites) == plannedCases(sites), "Native execution case inventory differs from proof annotation");
        }
        need(changed == currentProgram.isChanged() && version == currentProgram.getDomainFile().getVersion(), "Read-only differential changed saved program");
        println("DSP_BRANCHLESS_READONLY_PASS source=" + args[2] + " C_not_modified=true");
        if (args[0].equals("apply-safe")) materialize(annotation);
    }
}
