// Reachable-code decode probe for SunplusSPHEAudioDSP codec profiles.
// Argument 0: maximum PM word count. Seeds the observed 9 vector slots
// PM:0000,0004,...,0020 and follows direct flows plus fallthroughs only.

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class SunplusCodecReachableScan extends GhidraScript {
    private AddressSpace pm;
    private long unit;
    private long maxWords;

    private long parseCount(String raw) {
        String s = raw == null ? "" : raw.trim().toLowerCase();
        if (s.isEmpty()) return 0x4000L;
        return s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
    }

    private Address addr(long word) { return pm.getAddress(word * unit); }
    private long word(Address address) { return address.getOffset() / unit; }
    private boolean inRange(Address address) {
        return address != null && address.getAddressSpace().equals(pm) && word(address) >= 0 && word(address) < maxWords;
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) throw new AssertionError("No current program");
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString())) {
            throw new AssertionError("Unexpected language: " + currentProgram.getLanguageID());
        }
        pm = currentProgram.getAddressFactory().getAddressSpace("PM");
        if (pm == null) throw new AssertionError("Missing PM space");
        unit = pm.getAddressableUnitSize();
        String[] args = getScriptArgs();
        maxWords = parseCount(args.length == 0 ? null : args[0]);
        if (maxWords <= 0 || maxWords > 0x4000L) throw new IllegalArgumentException("bad maxWords=" + maxWords);

        Memory memory = currentProgram.getMemory();
        ArrayDeque<Address> queue = new ArrayDeque<>();
        for (long seed = 0; seed <= 0x20; seed += 4) queue.add(addr(seed));
        queue.add(addr(0x24));

        Set<Long> visited = new HashSet<>();
        Map<String,Integer> gaps = new LinkedHashMap<>();
        long decoded = 0;
        long flowEdges = 0;

        while (!queue.isEmpty() && !monitor.isCancelled()) {
            Address a = queue.removeFirst();
            if (!inRange(a) || !memory.contains(a)) continue;
            long w = word(a);
            if (!visited.add(w)) continue;

            Instruction ins = currentProgram.getListing().getInstructionAt(a);
            if (ins == null) {
                disassemble(a);
                ins = currentProgram.getListing().getInstructionAt(a);
            }
            if (ins == null) {
                byte[] raw = new byte[3];
                if (memory.getBytes(a, raw) != 3) continue;
                String key = String.format("%02X%02X%02X", raw[0]&0xff, raw[1]&0xff, raw[2]&0xff);
                gaps.put(key, gaps.getOrDefault(key,0)+1);
                continue;
            }
            decoded++;
            Address ft = ins.getFallThrough();
            if (inRange(ft)) queue.addLast(ft);
            for (Address flow : ins.getFlows()) {
                if (inRange(flow)) {
                    queue.addLast(flow);
                    flowEdges++;
                }
            }
        }

        println("SUNPLUS_REACHABLE_SCAN program=" + currentProgram.getName() +
            " visited=" + visited.size() + " decoded=" + decoded + " gaps=" +
            gaps.values().stream().mapToInt(Integer::intValue).sum() + " unique=" + gaps.size() +
            " flow_edges=" + flowEdges);
        for (var e : gaps.entrySet()) println("GAP " + e.getKey() + " count=" + e.getValue());
    }
}
