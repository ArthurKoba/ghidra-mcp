// Isolated 2x3 hardware CE fixture; does not mutate canonical firmware or Ghidra projects.
//@category Sunplus/Regression
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
public class SunplusNestedDirectCeAcceptance extends GhidraScript {
 private Address pm(int w){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",w));}
 private void need(boolean b,String s){if(!b)throw new IllegalStateException(s);}
 private int count(Instruction i,int op){int n=0;for(PcodeOp p:i.getPcode())if(p.getOpcode()==op)n++;return n;}
 private void ctx(Register r,int at,int value)throws Exception{currentProgram.getProgramContext().setValue(r,pm(at),pm(at),BigInteger.valueOf(value));}
 public void run()throws Exception{
  need(currentProgram!=null&&currentProgram.getName().equals("nested_ce_2x3.bin"),"Expected exact synthetic native fixture");
  need("SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()),"Wrong DSP ISA");
  var context=currentProgram.getProgramContext();
  Register nested=context.getRegister("codec_ce_nested_mode"),depth=context.getRegister("codec_ce_static_depth"),ce=context.getRegister("codec_ce_loop_end"),direct=context.getRegister("codec_ce_direct_backedge"),start=context.getRegister("codec_ce_direct_start");
  need(nested!=null&&depth!=null&&ce!=null&&direct!=null&&start!=null,"New SLEIGH contexts missing");
  int tx=currentProgram.startTransaction("Synthetic ADSP direct-depth2 nested CE execution");
  try{
   currentProgram.getListing().clearCodeUnits(pm(0x100),pm(0x109),true);
   for(int w:new int[]{0x101,0x108}){ctx(nested,w,1);ctx(depth,w,1);}
   for(int w:new int[]{0x102,0x103,0x105}){ctx(nested,w,1);ctx(depth,w,2);}
   for(int w:new int[]{0x105,0x108}){ctx(ce,w,1);ctx(direct,w,1);}
   ctx(start,0x105,0x104);ctx(start,0x108,0x102);
   for(int w=0x100;w<=0x109;w++){
    Address a=pm(w);
    DisassembleCommand cmd=new DisassembleCommand(new AddressSet(a,a.add(2)),null,true);cmd.enableCodeAnalysis(false);
    need(cmd.applyTo(currentProgram,monitor),"Unable to decode "+a+" "+cmd.getStatusMsg());
   }
   for(int w:new int[]{0x105,0x108}){
    Instruction i=currentProgram.getListing().getInstructionAt(pm(w));println("DIRECT2_DEBUG at="+pm(w)+" opcode="+i+" cb="+count(i,PcodeOp.CBRANCH)+" br="+count(i,PcodeOp.BRANCH)+" bi="+count(i,PcodeOp.BRANCHIND)+" nested="+context.getValue(nested,pm(w),false)+" depth="+context.getValue(depth,pm(w),false)+" end="+context.getValue(ce,pm(w),false)+" direct="+context.getValue(direct,pm(w),false)+" start="+context.getValue(start,pm(w),false));need(i!=null&&count(i,PcodeOp.CBRANCH)>0&&count(i,PcodeOp.BRANCH)>0&&count(i,PcodeOp.BRANCHIND)==0,"Direct nested CE missing "+pm(w));
    println("ADSP_DIRECT2_PCODE end="+pm(w)+" CBRANCH="+count(i,PcodeOp.CBRANCH)+" BRANCH="+count(i,PcodeOp.BRANCH));
   }
   Instruction save=currentProgram.getListing().getInstructionAt(pm(0x102));need(save!=null&&count(save,PcodeOp.COPY)>=2,"Native inner counter load did not save outer CNTR");
   EmulatorHelper e=new EmulatorHelper(currentProgram);
   try{
    e.writeRegister("PC",0x100);e.writeRegister("CNTR",0);e.writeRegister("DSP_STATIC_CNTR_OUTER",0);
    int inner=0,outer=0,steps=0;boolean stopped=false;
    while(steps<85){
     Address pc=e.getExecutionAddress();need(pc!=null,"Emulator PC null");int w=(int)pc.getAddressableWordOffset();
     if(w==0x109){stopped=true;break;}
     if(w==0x104)inner++;
     if(w==0x108){outer++;need(e.readRegister("CNTR").intValue()==(3-outer),"Outer CNTR incorrect at iteration="+outer);}
     int dp=(w==0x101||w==0x108)?1:(w==0x102||w==0x103||w==0x105)?2:0;
     boolean end=(w==0x105||w==0x108);
     e.setContextRegister(nested,BigInteger.valueOf(dp>0?1:0));
     e.setContextRegister(depth,BigInteger.valueOf(dp));
     e.setContextRegister(ce,BigInteger.valueOf(end?1:0));
     e.setContextRegister(direct,BigInteger.valueOf(end?1:0));
     e.setContextRegister(start,BigInteger.valueOf(w==0x105?0x104:w==0x108?0x102:0));
     need(e.step(monitor),"Emulator fault: "+e.getLastError()+" at "+pc);
     steps++;
    }
    println("ADSP_DIRECT2_EMU inner="+inner+" outer="+outer+" steps="+steps+" stopped="+stopped+" CNTR="+e.readRegister("CNTR"));
    need(stopped&&inner==6&&outer==2,"Direct nested CE failed 2x3 runtime fixture");
    println("SUNPLUS_NESTED_DIRECT_CE_RUNTIME_ACCEPTANCE=PASS");
   }finally{e.dispose();}
  }finally{currentProgram.endTransaction(tx,false);}
 }
}
