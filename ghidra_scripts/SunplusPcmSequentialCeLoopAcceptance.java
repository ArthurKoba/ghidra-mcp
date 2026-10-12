// Regression for two consecutive native DSP DO ... UNTIL CE loops, the
// second of which calls an external resident mailbox helper. Isolated fixture.
//@category Sunplus/Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;

public class SunplusPcmSequentialCeLoopAcceptance extends GhidraScript {
    private Address pm(String word) {
        return currentProgram.getAddressFactory().getAddress("PM:" + word);
    }
    private static void check(boolean result, String why) {
        if (!result) throw new IllegalStateException(why);
    }
    @Override public void run() throws Exception {
        check("SunplusSPHEAudioDSP:BE:16:default".equals(
            currentProgram.getLanguageID().getIdAsString()), "incorrect processor language");
        check(currentProgram.getMemory().contains(pm("07a4")) &&
              currentProgram.getMemory().contains(pm("07b5")), "incorrect fixture base/range");
        Register mode=currentProgram.getProgramContext().getRegister("codec_ce_direct_backedge");
        Register back=currentProgram.getProgramContext().getRegister("codec_ce_direct_start");
        check(mode!=null && back!=null,"new direct-CE context absent");
        int tx=currentProgram.startTransaction("Synthetic sequential CE test context");
        boolean commit=false;
        try {
            for (String[] pair : new String[][]{{"07a7","07a7"},{"07b2","07ae"}}) {
                Address end=pm(pair[0]);
                currentProgram.getProgramContext().setValue(mode,end,end,BigInteger.ONE);
                currentProgram.getProgramContext().setValue(back,end,end,
                    BigInteger.valueOf(Integer.parseInt(pair[1],16)));
            }
            check(disassemble(pm("07a4")), "failed to disassemble native test fixture");
            for (String[] pair : new String[][]{{"07a7","07a7"},{"07b2","07ae"}}) {
                Instruction end=getInstructionAt(pm(pair[0]));
                check(end!=null,"missing CE end "+pair[0]);
                int cb=0,branch=0,indirect=0;
                for(PcodeOp op:end.getPcode()){
                    if(op.getOpcode()==PcodeOp.CBRANCH)cb++;
                    if(op.getOpcode()==PcodeOp.BRANCH)branch++;
                    if(op.getOpcode()==PcodeOp.BRANCHIND)indirect++;
                }
                check(cb>=1 && branch>=1 && indirect==0,
                    "non-static CE branch "+pair[0]+": cb="+cb+" direct="+branch+" indirect="+indirect);
                boolean xref=false;
                for(ghidra.program.model.symbol.Reference ref :
                        currentProgram.getReferenceManager().getReferencesFrom(end.getAddress()))
                    if(ref.getToAddress().equals(pm(pair[1])))xref=true;
                check(xref,"missing CE edge "+pair[0]+"->"+pair[1]);
            }
            Instruction call=getInstructionAt(pm("07b0"));
            check(call!=null && call.getMnemonicString().contains("CALL"),"lost native mailbox call");
            Function f=currentProgram.getFunctionManager().getFunctionAt(pm("07a4"));
            if(f==null)f=createFunction(pm("07a4"),"ProcessSequentialPcmCeFixture");
            check(f!=null,"missing synthetic function");
            DecompInterface d=new DecompInterface();
            try {
                check(d.openProgram(currentProgram),"cannot open decompiler");
                DecompileResults result=d.decompileFunction(f,40,monitor);
                check(result.decompileCompleted() && result.getDecompiledFunction()!=null,
                    "synthetic C failed: "+result.getErrorMessage());
                String c=result.getDecompiledFunction().getC();
                int loops=0;
                java.util.regex.Matcher matcher=java.util.regex.Pattern.compile(
                    "\\bdo\\s*\\{").matcher(c);
                while(matcher.find())loops++;
                println("SUNPLUS_SEQUENTIAL_C loops="+loops+" chars="+c.length()+
                    " unresolved="+c.contains("UNRECOVERED_JUMPTABLE"));
                check(loops==2 && !c.contains("UNRECOVERED_JUMPTABLE"),
                    "two sequential CE loops not representable in native C");
            } finally { d.dispose(); }
            commit=true;
            println("SUNPLUS_SEQUENTIAL_CE_ACCEPTANCE=PASS loops=2 static_edges=2 preserved_call=1");
        } finally {
            currentProgram.endTransaction(tx,commit);
        }
    }
}
