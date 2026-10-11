// Isolated signed immediate shift regression; PM word addresses 0x400..0x404.
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.PcodeOp;
public class SunplusSignedImmediateShiftAcceptance extends GhidraScript {
 private Address pm(int n){return currentProgram.getAddressFactory().getAddress("PM:"+Integer.toHexString(n));}
 @Override public void run() throws Exception {
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Wrong DSP language");
  if(!"immediate_signed_shift.bin".equals(currentProgram.getName()))
   throw new IllegalStateException("Wrong fixture name");
  int transaction=currentProgram.startTransaction("Isolated signed immediate shifter test");
  try{
   if(!disassemble(pm(0x400)))throw new IllegalStateException("Disassemble failed");
   for(int addr=0x400;addr<=0x403;addr++)
    if(currentProgram.getListing().getInstructionAt(pm(addr))==null)disassemble(pm(addr));
   for(int addr:new int[]{0x401,0x403}){
    Instruction inst=currentProgram.getListing().getInstructionAt(pm(addr));
    if(inst==null)throw new IllegalStateException("Missing shift "+pm(addr));
    int branches=0,left=0,right=0;
    for(PcodeOp op:inst.getPcode()){
     if(op.getOpcode()==PcodeOp.CBRANCH||op.getOpcode()==PcodeOp.BRANCH)branches++;
     if(op.getOpcode()==PcodeOp.INT_LEFT)left++;
     if(op.getOpcode()==PcodeOp.INT_RIGHT)right++;
    }
    println("SIGNED_SHIFT_PCODE "+pm(addr)+" "+inst+" branches="+branches+" left="+left+" right="+right);
    if(branches!=0||left!=(addr==0x401?1:0)||right!=(addr==0x403?1:0))
     throw new IllegalStateException("Invalid signed immediate shift P-code "+pm(addr));
   }
   // All Type-15 ASHIFT/LSHIFT HI/LO sign pairs must decode without
   // an impossible conditional branch inside an immediate shifter.
   int[][] extraCases={{0x405,PcodeOp.INT_LEFT},{0x406,PcodeOp.INT_SRIGHT},
     {0x407,PcodeOp.INT_LEFT},{0x408,PcodeOp.INT_SRIGHT},
     {0x409,PcodeOp.INT_LEFT},{0x40a,PcodeOp.INT_RIGHT}};
   for(int[] test:extraCases){
    int addr=test[0];
    if(currentProgram.getListing().getInstructionAt(pm(addr))==null)disassemble(pm(addr));
    Instruction inst=currentProgram.getListing().getInstructionAt(pm(addr));
    if(inst==null)throw new IllegalStateException("Failed signed shift decode "+pm(addr));
    int branches=0,expectedOp=0;
    for(PcodeOp op:inst.getPcode()){
     if(op.getOpcode()==PcodeOp.CBRANCH||op.getOpcode()==PcodeOp.BRANCH)branches++;
     if(op.getOpcode()==test[1])expectedOp++;
    }
    println("SIGNED_SHIFT_VARIANT "+pm(addr)+" "+inst+" branches="+branches+" targetOp="+expectedOp);
    int expectedShifts=(addr==0x405||addr==0x409)?2:1; // HI source alignment also shifts left
    if(branches!=0||expectedOp!=expectedShifts)
     throw new IllegalStateException("Signed HI/LO shift is not branchless "+pm(addr));
   }
   EmulatorHelper emulator=new EmulatorHelper(currentProgram);
   try{
    emulator.writeRegister("PC",0x400);
    for(int count=0;count<4;count++){
      Address pc=emulator.getExecutionAddress();
      if(!emulator.step(monitor))throw new IllegalStateException("Execution failed "+pc+" "+emulator.getLastError());
      if(count==1){
       int sr0=emulator.readRegister("SR0").intValue(), sr1=emulator.readRegister("SR1").intValue();
       println("SIGNED_SHIFT_POSITIVE SR0="+Integer.toHexString(sr0)+" SR1="+Integer.toHexString(sr1));
       if(sr0!=0x8000||sr1!=0x14)throw new IllegalStateException("Positive LSHIFT incorrect");
      }
      if(count==3){
       int sr0=emulator.readRegister("SR0").intValue(), sr1=emulator.readRegister("SR1").intValue();
       println("SIGNED_SHIFT_NEGATIVE SR0="+Integer.toHexString(sr0)+" SR1="+Integer.toHexString(sr1));
       if(sr0!=0x14||sr1!=0)throw new IllegalStateException("Negative LSHIFT incorrect");
      }
    }
    Function function=createFunction(pm(0x400), "SignedImmediateShiftRegression");
    if(function==null)
      throw new IllegalStateException("Cannot establish synthetic shift function");
    DecompInterface decomp=new DecompInterface();
    try{
     if(!decomp.openProgram(currentProgram))
      throw new IllegalStateException("Decompiler open failed");
     DecompileResults result=decomp.decompileFunction(function, 30, monitor);
     String c=result.getDecompiledFunction()==null?"":result.getDecompiledFunction().getC();
     int deadBlocks=c.split("Removing unreachable block",-1).length-1;
     println("SIGNED_SHIFT_C completed="+result.decompileCompleted()+" deadBlocks="+deadBlocks+" length="+c.length());
     if(!result.decompileCompleted()||deadBlocks!=0)
      throw new IllegalStateException("Signed immediate shift produced unreachable P-code");
    }finally{decomp.dispose();}
    println("SUNPLUS_SIGNED_IMMEDIATE_SHIFT_ACCEPTANCE=PASS");
   } finally { emulator.dispose(); }
  } finally { currentProgram.endTransaction(transaction,false); }
 }
}
