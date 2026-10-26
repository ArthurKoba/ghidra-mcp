//@category Sunplus/Verification
// REAL original DTS CALL-as-last-DO instruction, executed with opt-in stack P-code.
// Explicitly observe flow and frame status; silicon equivalence remains UNKNOWN.
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.math.BigInteger;
import java.util.*;
public class SunplusDSPOriginalDtsCeCallExecutionQA extends GhidraScript {
 private SleighLanguage isa;private int operations=0;
 private Address pm(int site){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",site));}
 private static byte[] bytes(long x,int size){byte[] v=new byte[size];for(int j=size-1;j>=0;j--){v[j]=(byte)x;x>>>=8;}return v;}
 private static long num(byte[] bytes){long n=0;for(byte b:bytes)n=(n<<8)|(b&255);return n;}
 public class Faults extends AnnotatedPcodeUseropLibrary<byte[]> {
  @PcodeUserop(hasSideEffects=true)
  public void dsp_model_stack_fault(byte[] code){throw new IllegalStateException("ORIGINAL_SOURCE_STACK_FAULT="+num(code));}
 }
 private final class CPU {
  final Faults faults=new Faults();
  final PcodeEmulator emulator=new PcodeEmulator(isa){@Override protected PcodeUseropLibrary<byte[]> createUseropLibrary(){return CPU.this.faults;}};
  final PcodeThread<byte[]> thr=emulator.newThread();
  CPU(){
   thr.getState().setVar(isa.getAddressFactory().getRegisterSpace(),0L,0x200,false,new byte[0x200]);
   emulator.getSharedState().setVar(isa.getAddressFactory().getAddressSpace("DSPSTACK"),0L,0x200,false,new byte[0x200]);
   emulator.getSharedState().setVar(isa.getAddressFactory().getAddressSpace("DM"),0L,0x8000,true,new byte[0x8000]);
   reg("SSTAT",0x55);reg("DSP_IRQ_ENABLED",1);
   thr.setCounter(pm(0x0069));
  }
  void reg(String name,long data){Register r=isa.getRegister(name);if(r==null)throw new IllegalStateException(name);thr.getState().setVar(r,bytes(data,r.getNumBytes()));}
  long get(String name){return num(thr.getState().getVar(isa.getRegister(name),Reason.INSPECT));}
  int pc(){return (int)thr.getCounter().getAddressableWordOffset();}
  void step(int word)throws Exception {
   monitor.checkCancelled();Instruction nativeInsn=currentProgram.getListing().getInstructionAt(pm(word));
   if(nativeInsn==null||nativeInsn.getLength()!=3)throw new IllegalStateException("Original native instruction absent "+pm(word));
   var memory=new ByteMemBufferImpl(pm(word),nativeInsn.getBytes(),true);
   var ctx=new ProcessorContextImpl(isa);
   ctx.setValue(isa.getRegister("DSPCTX"),BigInteger.ZERO);
   ctx.setValue(isa.getRegister("codec_arch_stack_mode"),BigInteger.ONE);
   ctx.setValue(isa.getRegister("codec_ce_phase"),BigInteger.ZERO);
   PseudoInstruction executable=new PseudoInstruction(currentProgram.getAddressFactory(),pm(word),isa.parse(memory,ctx,false),memory,ctx);
   if(!Arrays.equals(executable.getBytes(),nativeInsn.getBytes()))throw new IllegalStateException("Original native bytes changed");
   reg("PC",(word+1)&0x3fff);thr.setCounter(pm((word+1)&0x3fff));
   try{thr.getExecutor().execute(PcodeProgram.fromInstruction(executable),thr.getUseropLibrary());operations++;}
   catch(Exception e){throw new IllegalStateException("Native PC="+pm(word)+" "+nativeInsn+" source Pcode failed "+e,e);}
  }
 }
 public void run()throws Exception{
  String[] args=getScriptArgs();if(args.length!=2||!args[0].equals(currentProgram.getExecutableSHA256())||
    currentProgram.getFunctionManager().getFunctionCount()!=Integer.parseInt(args[1])||
    currentProgram.isChanged()||
    !currentProgram.getDomainFile().getPathname().startsWith("/RUSH28-architecture-import-validation/"))
   throw new IllegalStateException("Original exact DTS source image and immutable QA project required");
  long version=currentProgram.getDomainFile().getVersion();
  var listing=currentProgram.getListing();
  for(int[] x:new int[][]{{0x0069,0},{0x006a,0},{0x006b,0},{0x006c,0},{0x008b,0},{0x008c,0},{0x008d,0},{0x008e,0}})
   if(listing.getInstructionAt(pm(x[0]))==null)throw new IllegalStateException("Native expected PM missing");
  isa=(SleighLanguage)currentProgram.getLanguage();
  CPU m=new CPU();int loopBodies=0,called=0,returned=0,visitedEnd=0;String outcome="BOUNDED_NONEXIT";
  int[] earlyTrace=new int[24];int count=0;
  while(operations<650){
   monitor.checkCancelled();int pc=m.pc();
   if(pc==0x006d){outcome="CONTINUATION_AFTER_DO";break;}
   if(pc<0x0069||pc>0x006c && (pc<0x008b||pc>0x008e)){
    outcome="ESCAPED_BOUNDED_SOURCE_AT_PM_"+String.format("%04x",pc);break;
   }
   if(count<earlyTrace.length)earlyTrace[count++]=pc;
   if(pc==0x006b)loopBodies++;
   if(pc==0x006c)visitedEnd++;
   if(pc==0x008b)called++;
   if(pc==0x008e)returned++;
   if(operations<19||pc==0x006c&&visitedEnd<=3){
    println("SOURCE_CE_CALL_PCODE_TRACE step="+operations+" pc="+pm(pc)+
      " native="+listing.getInstructionAt(pm(pc))+" pcStack="+m.get("DSP_PC_DEPTH")+
      " loopFrames="+m.get("DSP_ARCH_LOOP_DEPTH")+
      " cntr="+m.get("CNTR")+" savedCount="+m.get("DSP_ARCH_COUNT_DEPTH"));
   }
   m.step(pc);
  }
  if(currentProgram.isChanged()||currentProgram.getDomainFile().getVersion()!=version)
   throw new IllegalStateException("Source image changed after execution");
  println("SOURCE_CE_CALL_PCODE_RESULT outcome="+outcome+" steps="+operations+
    " loopBodyVisits="+loopBodies+" ceCallSites="+visitedEnd+
    " calleeEntries="+called+" calleeRTS="+returned+
    " finalPC="+pm(m.pc())+" finalCNTR="+m.get("CNTR")+
    " finalSharedPCDepth="+m.get("DSP_PC_DEPTH")+
    " finalLoopDepth="+m.get("DSP_ARCH_LOOP_DEPTH")+
    " finalCountDepth="+m.get("DSP_ARCH_COUNT_DEPTH")+
    " architectureADSP218x=REFERENCE_ONLY siliconProof=UNKNOWN sourceSHA="+args[0]);
 }
}
