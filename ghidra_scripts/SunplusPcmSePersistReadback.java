import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Independent read-only post-reopen acceptance for the saved PCM Type-12
 * negative-SE decoder migration. Must run in a separate headless invocation
 * after the write-mode migration completes and releases its project handle.
 * Proves persisted context, unchanged native bytes, P-code and C output.
 */
public class SunplusPcmSePersistReadback extends GhidraScript {
    private Address pm(String hex) {
        return currentProgram.getAddressFactory().getAddress("PM:" + hex);
    }

    private int[] inspectC(DecompInterface decoder, String entry) throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctionAt(pm(entry));
        if (f == null) throw new IllegalStateException("Missing function PM:" + entry);
        DecompileResults r = decoder.decompileFunction(f, 30, monitor);
        if (!r.decompileCompleted() || r.getDecompiledFunction() == null)
            throw new IllegalStateException("No C for PM:" + entry + " " + r.getErrorMessage());
        String c = r.getDecompiledFunction().getC();
        int unreachable = 0;
        int doLoops = 0;
        for (String line : c.split("\n")) {
            if (line.trim().startsWith("/* WARNING: Removing unreachable block (PM,"))
                unreachable++;
            if (line.contains("do {")) doLoops++;
        }
        println("PERSIST_REOPEN_C PM:" + entry + " warnings=" + unreachable
            + " loops=" + doLoops + " c_length=" + c.length());
        return new int[]{unreachable, doLoops};
    }

    @Override public void run() throws Exception {
        if (currentProgram == null || !"pcm-profile.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("Expected isolated pcm_current115 target");
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(
                currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("DSP language mismatch");
        if (currentProgram.getFunctionManager().getFunctionCount() != 115)
            throw new IllegalStateException("PCM function count changed");
        Register mode = currentProgram.getProgramContext()
            .getRegister("codec_se_proven_negative");
        if (mode == null) throw new IllegalStateException("SE context missing");

        String[] sites = {"06c1", "12bb", "12bc"};
        String[] mnemonics = {
            "SR = ASHIFT SR0 (LO),MY0 = DM( I0 ,M3 )",
            "SR = ASHIFT AR (HI),AR = DM( I1 ,M1 )",
            "SR = ASHIFT AR (HI),DM( I2 ,M1 ) = SR1"
        };
        byte[][] nativeBytes = {
            {(byte)0x12,(byte)0x36,(byte)0x63},
            {(byte)0x12,(byte)0x22,(byte)0xa5},
            {(byte)0x12,(byte)0xa2,(byte)0xf9}
        };
        for(int i=0;i<sites.length;i++) {
            Address at=pm(sites[i]);
            BigInteger value=currentProgram.getProgramContext().getValue(mode,at,false);
            if (!BigInteger.ONE.equals(value))
                throw new IllegalStateException("Context not persisted at " + at + ": " + value);
            Function owner=currentProgram.getFunctionManager().getFunctionContaining(at);
            String expectedOwner=i==0 ? "06a2" : "12a3";
            if(owner==null || !owner.getEntryPoint().equals(pm(expectedOwner)))
                throw new IllegalStateException("Function boundary changed at " + at);
            Instruction ins=currentProgram.getListing().getInstructionAt(at);
            if(ins==null || !mnemonics[i].equals(ins.toString()))
                throw new IllegalStateException("Native instruction changed at " + at + ": " + ins);
            if(!Arrays.equals(nativeBytes[i],ins.getBytes()))
                throw new IllegalStateException("Firmware bytes differ at " + at);
            int right=0,branch=0;
            for(PcodeOp p:ins.getPcode()) {
                if(p.getOpcode()==PcodeOp.INT_SRIGHT) right++;
                if(p.getOpcode()==PcodeOp.CBRANCH) branch++;
            }
            if(right!=1 || branch!=0)
                throw new IllegalStateException("Unexpected site P-code at " + at +
                    " signedRight=" + right + " cbranch=" + branch);
            println("PERSIST_REOPEN_SITE " + at + " ctx=1 bytes=unchanged INT_SRIGHT=1 CBRANCH=0");
        }
        DecompInterface decomp=new DecompInterface();
        try {
            if(!decomp.openProgram(currentProgram))
                throw new IllegalStateException("Decompiler unavailable");
            int[] kernel=inspectC(decomp,"06a2");
            int[] gm5=inspectC(decomp,"12a3");
            if(kernel[0]!=0 || gm5[0]!=0 || gm5[1]!=8)
                throw new IllegalStateException("C regression: warnings=" +
                    kernel[0]+"/"+gm5[0]+", GM5 loops="+gm5[1]);
            println("SUNPLUS_PCM_PERSIST_READBACK=PASS warnings=0/0 gm5_loops=8 functions=115");
        } finally {
            decomp.dispose();
        }
    }
}
