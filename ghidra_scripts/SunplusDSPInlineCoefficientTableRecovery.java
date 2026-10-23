//@category Sunplus/Architecture
// Recover an instruction table and its converging coefficient blocks, not a
// guessed selector domain. Computed-jump references are deliberately untouched.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import java.security.MessageDigest;
import java.util.*;

public class SunplusDSPInlineCoefficientTableRecovery extends GhidraScript {
    private final NavigableMap<Address, PseudoInstruction> decoded = new TreeMap<>();
    private void need(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }
    private int word(Address at) throws Exception {
        byte[] raw = new byte[3];
        need(currentProgram.getMemory().getBytes(at, raw) == 3, "Incomplete PM word at " + at);
        return ((raw[0] & 255) << 16) | ((raw[1] & 255) << 8) | (raw[2] & 255);
    }
    private PseudoInstruction parse(Address at) throws Exception {
        var language = (SleighLanguage) currentProgram.getLanguage();
        byte[] raw = new byte[3];
        need(currentProgram.getMemory().getBytes(at, raw) == 3, "Incomplete instruction at " + at);
        var buffer = new ByteMemBufferImpl(at, raw, true);
        var context = new ProcessorContextImpl(language);
        for (Register register : language.getContextRegisters()) {
            var value = currentProgram.getProgramContext().getValue(register, at, false);
            if (value != null) context.setValue(register, value);
        }
        var prototype = language.parse(buffer, context, false);
        var instruction = new PseudoInstruction(language.getAddressFactory(), at, prototype, buffer, context);
        need(instruction.getLength() == 3, "Unexpected native width at " + at);
        decoded.put(at, instruction);
        return instruction;
    }
    private String imageHash() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (var block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() || !block.getStart().getAddressSpace().getName().equals("PM")) continue;
            need(block.getSize() <= 1024 * 1024, "PM block exceeds bounded source check");
            byte[] raw = new byte[(int) block.getSize()];
            need(currentProgram.getMemory().getBytes(block.getStart(), raw) == raw.length, "Incomplete PM block");
            digest.update(raw);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private List<String> warnings(String c) {
        List<String> result = new ArrayList<>();
        for (String line : c.split("\n")) if (line.contains("WARNING:")) result.add(line.trim());
        Collections.sort(result);
        return result;
    }
    private void requireNoNewWarnings(String beforeC, String afterC) {
        // Occurrence-sensitive: disappearing warnings are permitted, newly
        // introduced ones are regressions. Do not hide or rewrite C diagnostics.
        List<String> previous = warnings(beforeC);
        for (String warning : warnings(afterC))
            need(previous.remove(warning), "New C diagnostic: " + warning);
    }
    private String c(Function function) throws Exception {
        var engine = new DecompInterface();
        try {
            need(engine.openProgram(currentProgram), "Cannot open local C generator");
            var result = engine.decompileFunction(function, 30, monitor);
            need(result.decompileCompleted() && result.getDecompiledFunction() != null,
                 "C generation failed: " + result.getErrorMessage());
            String text = result.getDecompiledFunction().getC();
            need(!text.isBlank() && !text.contains("halt_baddata"), "Invalid generated C");
            return text;
        } finally { engine.dispose(); }
    }
    private List<String> indirectReferences(Function function) {
        List<String> result = new ArrayList<>();
        for (var instruction : currentProgram.getListing().getInstructions(function.getBody(), true)) {
            if (!instruction.getFlowType().isComputed()) continue;
            for (var reference : currentProgram.getReferenceManager().getReferencesFrom(instruction.getAddress()))
                result.add(reference.toString());
        }
        Collections.sort(result);
        return result;
    }
    private Map<Address,String> otherFunctions(Function target) {
        Map<Address,String> result = new TreeMap<>();
        for (var function : currentProgram.getFunctionManager().getFunctions(true))
            if (!function.equals(target)) result.put(function.getEntryPoint(), function.getName() + ":" + function.getBody());
        return result;
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        need(args.length == 6, "mode image_sha256 owner table_start entry_count join");
        String mode = args[0];
        need(Set.of("audit", "apply-safe", "readback").contains(mode), "Unknown mode");
        need("SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().toString()), "Wrong ISA");
        String root = System.getenv("GHIDRA_MCP_PROJECT_ROOT");
        need(root != null && root.startsWith("/workspace/projects/") &&
             currentProgram.getDomainFile().getProjectLocator().getProjectDir().toPath().toRealPath()
                 .startsWith(java.nio.file.Path.of(root).toRealPath()), "Isolated local project required");
        need(!currentProgram.isChanged(), "Preserve pre-existing unsaved work");
        need(args[1].equals(currentProgram.getExecutableSHA256()) && args[1].equals(imageHash()), "Wrong original PM image");
        Address owner = toAddr(args[2]);
        Address table = toAddr(args[3]);
        int count = Integer.parseInt(args[4]);
        Address join = toAddr(args[5]);
        need(owner != null && table != null && join != null &&
             owner.getAddressSpace().getName().equals("PM") && table.getAddressSpace().equals(owner.getAddressSpace()) &&
             join.getAddressSpace().equals(owner.getAddressSpace()) && owner.compareTo(table) < 0 && table.compareTo(join) < 0 &&
             count > 1 && count <= 256 && table.getAddressSpace().getAddressableUnitSize() == 3,
             "Invalid table count or PM mapping");
        var function = currentProgram.getFunctionManager().getFunctionAt(owner);
        need(function != null && function.getBody().contains(join), "Join must belong to the existing owner");
        var joinInstruction = currentProgram.getListing().getInstructionAt(join);
        var returnInstruction = currentProgram.getListing().getInstructionAt(join.add(3));
        need(joinInstruction != null && joinInstruction.toString().startsWith("DMWRITE ") &&
             returnInstruction != null && word(join.add(3)) == 0x0a000f, "Expected existing store/RTS join");
        // Every table entry is a native direct JUMP. Cases are non-overlapping
        // LDI AR; LDI SR1; immediate OR shift; JUMP join (last may fall through).
        for (int index = 0; index < count; index++) {
            monitor.checkCancelled();
            Address at = table.add(index * 3L);
            var instruction = parse(at);
            need((word(at) & 0xfc000f) == 0x18000f && instruction.getFlows().length == 1,
                 "Not an unconditional native table JUMP: " + at);
            Address target = instruction.getFlows()[0];
            Address expected = table.add(count * 3L + index * 12L);
            need(target.equals(expected), "Case layout does not follow its encoded target: " + at);
            need((word(target) & 0xf0000f) == 0x40000a &&
                 (word(target.add(3)) & 0xf0000f) == 0x40000f && word(target.add(6)) == 0x0f0a08,
                 "Case does not implement the proven coefficient-construction pattern: " + target);
            parse(target); parse(target.add(3)); parse(target.add(6));
            Address end = target.add(9);
            if (end.equals(join)) need(index == count - 1, "Unexpected early fallthrough");
            else {
                var branch = parse(end);
                need((word(end) & 0xfc000f) == 0x18000f && branch.getFlows().length == 1 &&
                     branch.getFlows()[0].equals(join), "Case does not converge at the existing join: " + end);
            }
        }
        need(decoded.lastKey().add(3).equals(join), "Unaccounted gap before join");
        AddressSet body = new AddressSet(function.getBody());
        int missing = 0;
        for (var entry : decoded.entrySet()) {
            Address at = entry.getKey();
            var other = currentProgram.getFunctionManager().getFunctionContaining(at);
            need(other == null || other.equals(function), "Foreign function owns table/case " + at);
            need(currentProgram.getListing().getDefinedDataContaining(at) == null, "Preserve defined data at " + at);
            var existing = currentProgram.getListing().getInstructionAt(at);
            need(existing != null || currentProgram.getListing().getInstructionContaining(at) == null,
                 "Overlapping instruction at " + at);
            if (existing == null) missing++;
            else need(existing.toString().equals(entry.getValue().toString()) &&
                      Arrays.equals(existing.getBytes(), entry.getValue().getBytes()), "Existing instruction differs: " + at);
            body.add(at, at.add(2));
        }
        long nativeBefore = currentProgram.getListing().getNumInstructions();
        int functionCount = currentProgram.getFunctionManager().getFunctionCount();
        var others = otherFunctions(function);
        var references = indirectReferences(function);
        String beforeC = c(function);
        String key = owner + "-" + table;
        String proof = "CONFIRMED native structure: " + count + " direct table JUMPs; " + decoded.size() +
            " words; join=" + join + ". Selector domain and dynamic entry reachability UNKNOWN. " +
            "No computed-jump targets/overrides added. Arithmetic data width unresolved; no full-model acceptance.";
        println("INLINE_TABLE_PLAN owner=" + owner + " entries=" + count + " words=" + decoded.size() +
                " missing=" + missing + " selector_domain=UNKNOWN");
        if (mode.equals("apply-safe")) {
            int tx = currentProgram.startTransaction("Recover native inline coefficient table without selector assumptions");
            boolean commit = false;
            try {
                for (var entry : decoded.entrySet()) {
                    monitor.checkCancelled();
                    Address at = entry.getKey();
                    if (currentProgram.getListing().getInstructionAt(at) == null) {
                        var command = new DisassembleCommand(at, new AddressSet(at, at.add(2)), false);
                        command.enableCodeAnalysis(false);
                        need(command.applyTo(currentProgram, monitor), "Instruction recovery failed: " + at + " " + command.getStatusMsg());
                    }
                    var recovered = currentProgram.getListing().getInstructionAt(at);
                    need(recovered != null && recovered.toString().equals(entry.getValue().toString()) &&
                         Arrays.equals(recovered.getBytes(), entry.getValue().getBytes()), "Recovery mismatch at " + at);
                }
                function.setBody(body);
                need(indirectReferences(function).equals(references), "Computed-jump references changed");
                requireNoNewWarnings(beforeC, c(function));
                need(imageHash().equals(args[1]) && otherFunctions(function).equals(others) &&
                     currentProgram.getFunctionManager().getFunctionCount() == functionCount, "Source/functions changed");
                need(currentProgram.getListing().getNumInstructions() == nativeBefore + missing, "Instruction count mismatch");
                var options = currentProgram.getOptions("Sunplus Inline Coefficient Tables");
                String previous = options.getString(key, "");
                need(previous.isEmpty() || previous.equals(proof), "Preserve conflicting existing structural proof");
                options.setString(key, proof);
                commit = true;
            } finally { currentProgram.endTransaction(tx, commit); }
            println("INLINE_TABLE_APPLY_PASS added=" + missing + " warnings=" + warnings(beforeC).size() +
                    " caller_save_required=true computed_references_added=0");
        } else if (mode.equals("readback")) {
            need(missing == 0 && function.getBody().equals(body), "Recovered code/body not saved");
            need(currentProgram.getOptions("Sunplus Inline Coefficient Tables").getString(key, "").equals(proof),
                 "Local structural proof not saved");
            println("INLINE_TABLE_READBACK_PASS words=" + decoded.size() + " warnings=" + warnings(beforeC).size());
        }
        println("INLINE_TABLE_COMPLETE mode=" + mode + " functions=" + functionCount + " original_bytes=true " + proof);
    }
}
