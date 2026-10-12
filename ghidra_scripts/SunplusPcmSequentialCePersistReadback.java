// Persistent read-only acceptance after targeted PCM CE instruction migration.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.security.MessageDigest;

public class SunplusPcmSequentialCePersistReadback extends GhidraScript {
    private Address pm(String word) {
        return currentProgram.getAddressFactory().getAddress("PM:" + word);
    }
    private static void require(boolean cond, String message) {
        if (!cond) throw new IllegalStateException(message);
    }
    private String sha256() throws Exception {
        byte[] bytes = new byte[25052];
        require(currentProgram.getMemory().getBytes(pm("0000"), bytes) == bytes.length,
            "incomplete original PM image");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder out = new StringBuilder();
        for (byte b : digest) out.append(String.format("%02x", b & 255));
        return out.toString();
    }
    private int[] c(DecompInterface d, String addr) {
        Function f = currentProgram.getFunctionManager().getFunctionAt(pm(addr));
        require(f != null, "missing function PM:" + addr);
        DecompileResults r = d.decompileFunction(f, 45, monitor);
        require(r.decompileCompleted() && r.getDecompiledFunction() != null,
            "invalid C PM:" + addr + " " + r.getErrorMessage());
        String text = r.getDecompiledFunction().getC();
        int loops = 0;
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
            "\\bdo\\s*\\{").matcher(text);
        while (matcher.find()) loops++;
        int warnings = text.split("WARNING: Removing unreachable block", -1).length - 1;
        println("PCM_CE_REOPEN_C PM:" + addr + " loops=" + loops + " warnings=" + warnings);
        return new int[]{loops,warnings};
    }
    public void run() throws Exception {
        require(currentProgram != null && "pcm-profile.bin".equals(currentProgram.getName()),
            "expected canonical PCM program");
        require("SunplusSPHEAudioDSP:BE:16:default".equals(
            currentProgram.getLanguageID().getIdAsString()), "wrong language");
        require(currentProgram.getFunctionManager().getFunctionCount() == 115,
            "saved function count differs");
        Register end = currentProgram.getProgramContext().getRegister("codec_ce_loop_end");
        Register direct = currentProgram.getProgramContext().getRegister("codec_ce_direct_backedge");
        Register back = currentProgram.getProgramContext().getRegister("codec_ce_direct_start");
        require(end != null && direct != null && back != null, "missing direct CE context registers");
        for (String site : new String[]{"07a7","07b2"}) {
            Address a=pm(site);
            Instruction ins=currentProgram.getListing().getInstructionAt(a);
            require(ins!=null && BigInteger.ONE.equals(
                currentProgram.getProgramContext().getValue(end,a,false)),
                "missing persisted CE instruction context PM:" + site);
            String expected = "07a7".equals(site) ? "07a7" : "07ae";
            require(BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(direct,a,false)),
                "direct backedge mode not persisted PM:" + site);
            require(BigInteger.valueOf(Integer.parseInt(expected,16)).equals(
                currentProgram.getProgramContext().getValue(back,a,false)),
                "static backedge address not persisted PM:" + site);
            int conditional=0, backward=0;
            for (PcodeOp op:ins.getPcode()) {
                if (op.getOpcode()==PcodeOp.CBRANCH) conditional++;
                if (op.getOpcode()==PcodeOp.BRANCH) backward++;
            }
            require(conditional>=1 && backward>=1,
                "missing static CE loop in P-code PM:" + site + " cond=" + conditional + " direct=" + backward);
            boolean target=false;
            for (ghidra.program.model.symbol.Reference ref :
                    currentProgram.getReferenceManager().getReferencesFrom(a)) {
                if (ref.getToAddress().equals(pm(expected))) target=true;
            }
            require(target, "missing direct reference PM:"+site+" -> PM:"+expected);
        }
        DecompInterface d=new DecompInterface();
        try {
            require(d.openProgram(currentProgram), "decompiler unavailable");
            int[] pcm=c(d,"0753"), gm5=c(d,"12a3"), kernel=c(d,"06a2");
            require(pcm[0]==2 && gm5[0]==8 && gm5[1]==0 && kernel[1]==0,
                "saved C/GM5 regression after CE migration");
        } finally { d.dispose(); }
        println("PCM_CE_PERSIST_READBACK=PASS functions=115 loops=2 GM5_loops=8 bytes_sha256=" + sha256());
    }
}
