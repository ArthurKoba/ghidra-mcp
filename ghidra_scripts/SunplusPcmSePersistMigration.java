import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;

/**
 * Restore three proven negative-SE Type-12 shifts in canonical RUSH PCM.
 * Scoped Ghidra transaction: ALL checks pass or no changes are committed.
 * This changes decoder metadata, never original firmware bytes.
 */
public class SunplusPcmSePersistMigration extends GhidraScript {
    private Address pm(String hex) {
        return currentProgram.getAddressFactory().getAddress("PM:" + hex);
    }

    private int[] checkC(DecompInterface decoder, String entry) throws Exception {
        Function f = currentProgram.getFunctionManager().getFunctionAt(pm(entry));
        if (f == null) throw new IllegalStateException("Missing function PM:" + entry);
        DecompileResults r = decoder.decompileFunction(f, 30, monitor);
        if (!r.decompileCompleted() || r.getDecompiledFunction() == null)
            throw new IllegalStateException("Invalid C for " + entry + " " + r.getErrorMessage());
        String c = r.getDecompiledFunction().getC();
        int warnings = 0, loops = 0;
        for (String line : c.split("\\n")) {
            if (line.trim().startsWith("/* WARNING: Removing unreachable block (PM,"))
                warnings++;
            if (line.contains("do {")) loops++;
        }
        println("SE_MIGRATION_C PM:" + entry + " warnings=" + warnings +
            " loops=" + loops + " bytes=" + c.length());
        return new int[]{warnings, loops};
    }

    @Override public void run() throws Exception {
        if (currentProgram == null ||
            !"pcm-profile.bin".equals(currentProgram.getName()) ||
            !"SunplusSPHEAudioDSP:BE:16:default".equals(
                currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("Isolated PCM GZF/ISA mismatch");
        if (currentProgram.getFunctionManager().getFunctionCount() != 115)
            throw new IllegalStateException("Function count is not 115");
        Register mode = currentProgram.getProgramContext()
            .getRegister("codec_se_proven_negative");
        if (mode == null) throw new IllegalStateException("Deployed SE context absent");

        String[] at = {"06c1", "12bb", "12bc"};
        String[] nativeText = {
            "SR = ASHIFT SR0 (LO),MY0 = DM( I0 ,M3 )",
            "SR = ASHIFT AR (HI),AR = DM( I1 ,M1 )",
            "SR = ASHIFT AR (HI),DM( I2 ,M1 ) = SR1"
        };
        for (int i=0; i<at.length; i++) {
            Instruction ins = currentProgram.getListing().getInstructionAt(pm(at[i]));
            if (ins == null || !nativeText[i].equals(ins.toString()))
                throw new IllegalStateException("Unexpected instruction PM:" + at[i] + ": " + ins);
        }

        DecompInterface decoder = new DecompInterface();
        try {
            if (!decoder.openProgram(currentProgram))
                throw new IllegalStateException("Cannot open decoder");
            int[] beforeKernel = checkC(decoder, "06a2");
            int[] beforeGM5 = checkC(decoder, "12a3");
            if (beforeKernel[0] != 1 || beforeGM5[0] != 2 ||
                beforeGM5[1] != 8)
                throw new IllegalStateException("Expected saved baseline 1/2 warnings, eight GM5 loops");

            int tx = currentProgram.startTransaction(
                "PCM CE: proven negative SE P-code on three native shifts");
            boolean commit = false;
            try {
                CommentType[] commentKinds = {CommentType.EOL,
                    CommentType.PRE, CommentType.POST,
                    CommentType.PLATE, CommentType.REPEATABLE};
                for (int i=0; i<at.length; i++) {
                    Address site = pm(at[i]);
                    if (monitor.isCancelled())
                        throw new IllegalStateException("Cancelled");
                    String[] comments = new String[commentKinds.length];
                    for (int j=0; j<commentKinds.length; j++)
                        comments[j] = currentProgram.getListing()
                            .getComment(commentKinds[j], site);
                    clearListing(site, site);
                    currentProgram.getProgramContext()
                        .setValue(mode, site, site, BigInteger.ONE);
                    if (!disassemble(site))
                        throw new IllegalStateException("Cannot re-decode " + site);
                    Instruction fixed = currentProgram.getListing().getInstructionAt(site);
                    if (fixed == null || !nativeText[i].equals(fixed.toString()))
                        throw new IllegalStateException("Native identity changed at " + site);
                    int conditional = 0, signedRight = 0;
                    for (PcodeOp op : fixed.getPcode()) {
                        if (op.getOpcode() == PcodeOp.CBRANCH) conditional++;
                        if (op.getOpcode() == PcodeOp.INT_SRIGHT) signedRight++;
                    }
                    if (conditional != 0 || signedRight != 1)
                        throw new IllegalStateException("P-code regression " + site);
                    for (int j=0; j<commentKinds.length; j++) {
                        if (comments[j] != null)
                            currentProgram.getListing().setComment(
                                site, commentKinds[j], comments[j]);
                    }
                    println("SE_MIGRATION_SITE PM:" + at[i] +
                        " signedRight=1 conditional=0");
                }
                int[] afterKernel = checkC(decoder,"06a2");
                int[] afterGM5 = checkC(decoder,"12a3");
                if (afterKernel[0] != 0 || afterGM5[0] != 0 ||
                    afterGM5[1] != 8 ||
                    currentProgram.getFunctionManager().getFunctionCount() != 115)
                    throw new IllegalStateException("Decompiler/function acceptance failed");
                commit = true;
                println("RUSH_PCM_SE_MIGRATION_ACCEPTANCE=PASS");
            } finally {
                currentProgram.endTransaction(tx, commit);
                println("RUSH_PCM_SE_MIGRATION_COMMITTED=" + commit);
            }
        } finally {
            decoder.dispose();
        }
    }
}
