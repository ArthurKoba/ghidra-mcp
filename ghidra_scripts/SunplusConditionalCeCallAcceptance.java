// Isolated conditional CALL fixture under counted CE nesting. Validate
// both taken and skipped branches and preserve the active outer counter.
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;

public class SunplusConditionalCeCallAcceptance extends GhidraScript {
  private Address pm(long word) {
    return currentProgram.getAddressFactory().getAddress("PM:" + Long.toHexString(word));
  }
  @Override public void run() throws Exception {
    if (!"nested_ce_condcall_2x3.bin".equals(currentProgram.getName()))
      throw new IllegalStateException("Wrong fixture");
    int tx=currentProgram.startTransaction("Synthetic conditional CALL/CE acceptance");
    try {
      Register nested=currentProgram.getProgramContext().getRegister("codec_ce_nested_mode");
      Register ce=currentProgram.getProgramContext().getRegister("codec_ce_loop_end");
      if(nested==null || ce==null)throw new IllegalStateException("Missing SLEIGH context");
      for(long w:new long[]{0x301,0x302,0x305,0x309,0x30a,0x30b,0x30c})
        currentProgram.getProgramContext().setValue(nested,pm(w),pm(w),BigInteger.ONE);
      disassemble(pm(0x300));
      for(long w=0x300;w<=0x30c;w++)
        if(currentProgram.getListing().getInstructionAt(pm(w))==null)
          disassemble(pm(w));
      for(long w:new long[]{0x305,0x30b}){
        clearListing(pm(w),pm(w));
        currentProgram.getProgramContext().setValue(ce,pm(w),pm(w),BigInteger.ONE);
        if(!disassemble(pm(w)))throw new IllegalStateException("Missing CE at "+pm(w));
      }
      Instruction conditional=currentProgram.getListing().getInstructionAt(pm(0x302));
      if(conditional==null || !conditional.toString().contains("IF NE CALL 0x0309"))
        throw new IllegalStateException("Wrong conditional native CALL: "+conditional);
      int branch=0,call=0;
      for(PcodeOp op:conditional.getPcode()){
        if(op.getOpcode()==PcodeOp.CBRANCH)branch++;
        if(op.getOpcode()==PcodeOp.CALL)call++;
      }
      if(branch==0||call==0)throw new IllegalStateException("Conditional CALL P-code malformed");

      for(int azf:new int[]{0,1}){
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        try {
          e.writeRegister("PC",0x300);
          e.writeRegister("PCSTACKTOP",0);
          e.writeRegister("AZF",azf);
          e.writeRegister("CNTR",0);
          e.writeRegister("DSP_LOOP_DEPTH",0);
          e.writeRegister("DSP_COUNT_DEPTH",0);
          e.writeRegister("DSP_CALL_DEPTH",0);
          e.writeRegister("DSP_LOOP_START",0);
          int entered=0,inner=0,outer=0,returns=0,steps=0;
          while(steps<80){
            Address pc=e.getExecutionAddress();
            if(pc==null)throw new IllegalStateException("No PC");
            if(pc.equals(pm(0x309)))entered++;
            if(pc.equals(pm(0x30b)))inner++;
            if(pc.equals(pm(0x305)))outer++;
            if(pc.equals(pm(0x303)))returns++;
            if(pc.equals(pm(0x306)))break;
            e.setContextRegister(nested,BigInteger.ONE);
            if(!e.step(monitor))
              throw new IllegalStateException("Emulation failed: "+e.getLastError());
            steps++;
          }
          int expected=azf==0?6:0;
          int expectedEntered=azf==0?2:0;
          int callDepth=e.readRegister("DSP_CALL_DEPTH").intValue();
          int loopDepth=e.readRegister("DSP_LOOP_DEPTH").intValue();
          int countDepth=e.readRegister("DSP_COUNT_DEPTH").intValue();
          println("CONDITIONAL_CE_CALL azf="+azf+" entered="+entered+" returns="+returns+
            " inner="+inner+" outer="+outer+" steps="+steps+" callDepth="+callDepth+
            " loopDepth="+loopDepth+" countDepth="+countDepth);
          if(entered!=expectedEntered||inner!=expected||returns!=2||outer!=2||
             callDepth!=0||loopDepth!=0||countDepth!=0||steps>=80)
             throw new IllegalStateException("Conditional CE/CALL gate not preserved");
        }finally{e.dispose();}
      }
      println("CONDITIONAL_CE_CALL_ACCEPTANCE=PASS");
    }finally{currentProgram.endTransaction(tx,false);}
  }
}
