// Bounded native-decode coverage probe for SunplusSPHEAudioDSP corpora.
// Argument 0: number of PM words to inspect (hex or decimal), default 0x200.

import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class SunplusCodecCorpusGapScan extends GhidraScript {
    private static long parseCount(String raw) {
        String s = raw == null ? "" : raw.trim().toLowerCase();
        if (s.isEmpty()) {
            return 0x200L;
        }
        return s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
    }

    private Address pm(long word) {
        var space = currentProgram.getAddressFactory().getAddressSpace("PM");
        if (space == null) {
            throw new AssertionError("Missing PM address space");
        }
        return space.getAddress(word * space.getAddressableUnitSize());
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new AssertionError("No current program");
        }
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new AssertionError("Unexpected language: " + currentProgram.getLanguageID());
        }

        String[] args = getScriptArgs();
        long requested = parseCount(args.length == 0 ? null : args[0]);
        if (requested <= 0 || requested > 0x4000L) {
            throw new IllegalArgumentException("PM word count must be 1..0x4000, got " + requested);
        }

        Memory memory = currentProgram.getMemory();
        long decoded = 0;
        long gaps = 0;
        int trailingBytes = 0;
        Map<String, Integer> unique = new LinkedHashMap<>();

        for (long word = 0; word < requested && !monitor.isCancelled(); word++) {
            Address address = pm(word);
            if (!memory.contains(address)) {
                break;
            }
            if (!memory.contains(address.add(2))) {
                trailingBytes = memory.contains(address.add(1)) ? 2 : 1;
                break;
            }
            Instruction instruction = currentProgram.getListing().getInstructionAt(address);
            if (instruction == null) {
                disassemble(address);
                instruction = currentProgram.getListing().getInstructionAt(address);
            }
            if (instruction != null) {
                decoded++;
                continue;
            }

            byte[] raw = new byte[3];
            int n = memory.getBytes(address, raw);
            if (n != 3) {
                throw new AssertionError("Short PM word read at " + address + ": " + n);
            }
            String key = String.format("%02X%02X%02X", raw[0] & 0xff, raw[1] & 0xff, raw[2] & 0xff);
            unique.put(key, unique.getOrDefault(key, 0) + 1);
            gaps++;
        }

        println("SUNPLUS_CORPUS_SCAN program=" + currentProgram.getName() +
            " decoded=" + decoded + " gaps=" + gaps + " unique=" + unique.size() +
            " trailing_bytes=" + trailingBytes);
        for (var entry : unique.entrySet()) {
            println("GAP " + entry.getKey() + " count=" + entry.getValue());
        }
    }
}
