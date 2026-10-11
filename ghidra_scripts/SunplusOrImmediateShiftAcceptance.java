// Isolated native Type-15 OR-LSHIFT immediate regression. Does not edit firmware.
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
public class SunplusOrImmediateShiftAcceptance extends GhidraScript {
 private Address pm(int w){return currentProgram.getAddressFactory().getAddress("PM:"+Integer.toHexString(w));}
 @Override public void run() throws Exception {
   if(!"immediate_or_shift.bin".equals(currentProgram.getName())||
      !"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
      throw new IllegalStateException("Unexpected fixture or DSP language");
   int tx=currentProgram.startTransaction("Isolated OR-shift sign regression");
   try {
     disassemble(pm(0x500));
     int[] src={0x56,0x56,0x1234,0x1234};
     int[] low={0,0x5600,0x4000,0x0123};
     int[] high={0x5600,0,0x0123,0};
     for(int i=0;i<4;i++){
       int word=0x500+i;
       Instruction ins=currentProgram.getListing().getInstructionAt(pm(word));
       if(ins==null){disassemble(pm(word));ins=currentProgram.getListing().getInstructionAt(pm(word));}
       if(ins==null||!ins.toString().contains("SR OR LSHIFT"))
         throw new IllegalStateException("Native OR shift did not decode "+pm(word)+" "+ins);
       int cond=0,left=0,right=0;
       for(PcodeOp op:ins.getPcode()){
         if(op.getOpcode()==PcodeOp.CBRANCH||op.getOpcode()==PcodeOp.BRANCH)cond++;
         if(op.getOpcode()==PcodeOp.INT_LEFT)left++;
         if(op.getOpcode()==PcodeOp.INT_RIGHT)right++;
       }
       int expectedLeft=i==0?3:i==2?2:i==1?2:1;
       int expectedRight=(i==1||i==3)?1:0;
       println("SUNPLUS_OR_SHIFT_PCODE "+pm(word)+" "+ins+" branch="+cond+" left="+left+" right="+right);
       if(cond!=0||left!=expectedLeft||right!=expectedRight)
         throw new IllegalStateException("OR immediate shift has dead branch / bad P-code "+pm(word));
       EmulatorHelper emu=new EmulatorHelper(currentProgram);
       try {
         emu.writeRegister("PC",word);
         emu.writeRegister("AR",src[i]);
         emu.writeRegister("SR0",0);
         emu.writeRegister("SR1",0);
         if(!emu.step(monitor))throw new IllegalStateException("Emulator failure "+emu.getLastError());
         int resultLow=emu.readRegister("SR0").intValue();
         int resultHigh=emu.readRegister("SR1").intValue();
         println("SUNPLUS_OR_SHIFT_NUMERIC "+pm(word)+" SR0="+Integer.toHexString(resultLow)+" SR1="+Integer.toHexString(resultHigh));
         if(resultLow!=low[i]||resultHigh!=high[i])
           throw new IllegalStateException("OR shift numeric mismatch "+pm(word));
       } finally {emu.dispose();}
     }
     Function f=createFunction(pm(0x500),"OrShiftRegression");
     if(f==null)throw new IllegalStateException("Cannot create fixture function");
     DecompInterface d=new DecompInterface();
     try{
       if(!d.openProgram(currentProgram))throw new IllegalStateException("Decompiler unavailable");
       DecompileResults dr=d.decompileFunction(f,25,monitor);
       String c=dr.getDecompiledFunction()==null?"":dr.getDecompiledFunction().getC();
       int dead=c.split("Removing unreachable block",-1).length-1;
       println("SUNPLUS_OR_SHIFT_C completed="+dr.decompileCompleted()+" dead="+dead);
       if(!dr.decompileCompleted()||dead!=0)
          throw new IllegalStateException("OR shift C still has unreachable blocks");
     }finally{d.dispose();}
     println("SUNPLUS_OR_SHIFT_ACCEPTANCE=PASS");
   }finally{currentProgram.endTransaction(tx,false);}
 }
}
