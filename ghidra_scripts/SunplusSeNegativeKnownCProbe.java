// Isolated real-PCM validation of statically proven negative SE at three
// Type-12 ASHIFT sites. All context and listing edits are ROLLED BACK.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;

public class SunplusSeNegativeKnownCProbe extends GhidraScript {
    private Address pm(long word) {
        return currentProgram.getAddressFactory().getAddress(
            "PM:" + Long.toHexString(word));
    }

    private static int warningLines(String generatedC) {
        int count = 0;
        for (String line : generatedC.split("\\n")) {
            if (line.trim().startsWith(
                "/* WARNING: Removing unreachable block (PM,")) {
                count++;
            }
        }
        return count;
    }

    private int[] checkC(DecompInterface decompiler, long entry,
                         String phase) throws Exception {
        Function function = currentProgram.getFunctionManager()
            .getFunctionAt(pm(entry));
        if (function == null) {
            throw new IllegalStateException("Missing function " + pm(entry));
        }
        DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
            throw new IllegalStateException(
                "Decompiler incomplete at " + pm(entry) + ": "
                + result.getErrorMessage());
        }
        String c = result.getDecompiledFunction().getC();
        int warningCount = warningLines(c);
        int loops = c.split("do \\{", -1).length - 1;
        println("SE_KNOWN_C phase=" + phase + " address=" + pm(entry)
            + " warnings=" + warningCount + " doLoops=" + loops
            + " chars=" + c.length());
        return new int[]{warningCount,loops};
    }

    @Override public void run() throws Exception {
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(
                 currentProgram.getLanguageID().getIdAsString())
            || !"pcm-profile.bin".equals(currentProgram.getName())) {
            throw new IllegalStateException("Use only the isolated canonical PCM GZF");
        }
        Register proven = currentProgram.getProgramContext()
            .getRegister("codec_se_proven_negative");
        if (proven == null) {
            throw new IllegalStateException("Missing specialized SE language context");
        }

        long[] instrWords = {0x06c1, 0x12bb, 0x12bc};
        String[] requiredNames = {
            "SR = ASHIFT SR0 (LO), MY0 = DM(I0,M3)",
            "SR = ASHIFT AR (HI), AR = DM(I1,M1)",
            "SR = ASHIFT AR (HI), DM(I2,M1) = SR1"
        };
        String[] sources={"06b9","12b7"};
        String[] nativeCounts={"LDI SE,0xffff","LDI SE,0xfffe"};
        for(int j=0;j<sources.length;j++){
            long producer=Long.parseLong(sources[j],16);
            Instruction prior=currentProgram.getListing().getInstructionAt(pm(producer));
            if(prior==null || !nativeCounts[j].equals(prior.toString())){
                throw new IllegalStateException("Unexpected SE producer at "+pm(producer)+": "+prior);
            }
            long stop=(j==0)?0x06c1:0x12bc;
            for(long w=producer+1;w<=stop;w++){
                Instruction ins=currentProgram.getListing().getInstructionAt(pm(w));
                if(ins!=null && ins.toString().startsWith("LDI SE,")){
                    throw new IllegalStateException("Conflicting SE write "+pm(w));
                }
            }
        }
        println("SE_NEGATIVE_PRODUCER_GUARDS=PASS kernel=-1 GM5=-2");
        DecompInterface d = new DecompInterface();
        try {
            if (!d.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler unavailable");
            }
            int[] beforeKernel = checkC(d,0x06a2,"before");
            int[] beforeGm5 = checkC(d,0x12a3,"before");
            if (beforeKernel[0] != 1 || beforeGm5[0] != 2) {
                throw new IllegalStateException(
                    "Unexpected known-good baseline warnings: "
                    + beforeKernel[0] + "/" + beforeGm5[0]);
            }

            int transaction = currentProgram.startTransaction(
                "Isolated SE-negative specialized P-code acceptance; ALWAYS ROLLBACK");
            try {
                for (int i=0; i<instrWords.length; i++) {
                    Address at = pm(instrWords[i]);
                    Instruction original = currentProgram.getListing().getInstructionAt(at);
                    if (original == null) {
                        throw new IllegalStateException("No native instruction " + at);
                    }
                    println("SE_KNOWN_NATIVE at=" + at + " " + original);
                    // Preserve the word identity and native mnemonic across redecode.
                    clearListing(at,at);
                    currentProgram.getProgramContext().setValue(
                        proven,at,at,BigInteger.ONE);
                    if (!disassemble(at)) {
                        throw new IllegalStateException("Unable to re-decode " + at);
                    }
                    Instruction fixed = currentProgram.getListing().getInstructionAt(at);
                    int conditions=0,shiftRight=0;
                    if (fixed == null) {
                        throw new IllegalStateException("Missing decoded instruction " + at);
                    }
                    for (PcodeOp op : fixed.getPcode()) {
                        if (op.getOpcode() == PcodeOp.CBRANCH) conditions++;
                        if (op.getOpcode() == PcodeOp.INT_SRIGHT) shiftRight++;
                    }
                    println("SE_KNOWN_PCODE at=" + at + " instr=" + fixed
                       + " conditions=" + conditions + " arithmeticRight=" + shiftRight);
                    if (conditions != 0 || shiftRight < 1) {
                        throw new IllegalStateException("Specialized SE shift invalid: " + at);
                    }
                }
                int[] afterKernel = checkC(d,0x06a2,"after");
                int[] afterGm5 = checkC(d,0x12a3,"after");
                if (afterKernel[0] != 0 || afterGm5[0] != 0
                    || afterGm5[1] < beforeGm5[1]) {
                    throw new IllegalStateException("SE C did not improve safely");
                }
                println("SE_NEGATIVE_STATIC_C_ACCEPTANCE=PASS warnings=0/0");
            } finally {
                currentProgram.endTransaction(transaction,false);
                println("SE_NEGATIVE_TEST_TRANSACTION=ROLLED_BACK");
            }
        } finally {
            d.dispose();
        }
    }
}
