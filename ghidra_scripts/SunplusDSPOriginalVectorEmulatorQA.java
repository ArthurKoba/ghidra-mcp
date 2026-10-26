//@category Sunplus/Verification
// Execute original PM interrupt-vector instructions in opted-in shared-stack P-code.
// ADSP-218x vector address analogy is reference evidence, not proven Sunplus IRQ wiring.
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import java.math.BigInteger;
import java.util.*;

public class SunplusDSPOriginalVectorEmulatorQA extends GhidraScript {
 private SleighLanguage lang;private int steps=0,checks=0,rtis=0;
 private static final int[] expectedRti={0x0004,0x0008,0x000c,0x0010,0x0014,0x0018,0x001c,0x0020};
 private Address pm(int x){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",x));}
 private static byte[] bytes(long v,int n){byte[] b=new byte[n];for(int i=n-1;i>=0;i--){b[i]=(byte)v;v>>>=8;}return b;}
 private static long num(byte[] b){long v=0;for(byte x:b)v=(v<<8)|(x&255);return v;}
 private void need(boolean ok,String name){checks++;if(!ok)throw new IllegalStateException(name);}
 private PseudoInstruction decode(int site,byte[] raw)throws Exception{
  var mem=new ByteMemBufferImpl(pm(site),raw,true);
  var ctx=new ProcessorContextImpl(lang);
  ctx.setValue(lang.getRegister("DSPCTX"),BigInteger.ZERO);
  ctx.setValue(lang.getRegister("codec_arch_stack_mode"),BigInteger.ONE);
  ctx.setValue(lang.getRegister("codec_ce_phase"),BigInteger.ZERO);
  var ins=new PseudoInstruction(currentProgram.getAddressFactory(),pm(site),lang.parse(mem,ctx,false),mem,ctx);
  need(ins.getLength()==3&&Arrays.equals(ins.getBytes(),raw),"Original PM byte identity "+site);
  return ins;
 }
 public final class Faults extends AnnotatedPcodeUseropLibrary<byte[]> {
  @PcodeUserop(hasSideEffects=true)
  public void dsp_model_stack_fault(byte[] reason){throw new IllegalStateException("Native stack fault="+num(reason));}
 }
 private final class CPU {
  final Faults faults=new Faults();
  final PcodeEmulator emu=new PcodeEmulator(lang){@Override protected PcodeUseropLibrary<byte[]> createUseropLibrary(){return CPU.this.faults;}};
  final PcodeThread<byte[]> thread=emu.newThread();
  CPU(){thread.getState().setVar(lang.getAddressFactory().getRegisterSpace(),0L,0x200,false,new byte[0x200]);
       emu.getSharedState().setVar(lang.getAddressFactory().getAddressSpace("DSPSTACK"),0L,0x200,false,new byte[0x200]);
       put("SSTAT",0x55);put("DSP_IRQ_ENABLED",1);}
  void put(String name,long v){Register r=lang.getRegister(name);if(r==null)throw new IllegalStateException("Missing register "+name);thread.getState().setVar(r,bytes(v,r.getNumBytes()));}
  long get(String name){return num(thread.getState().getVar(lang.getRegister(name),Reason.INSPECT));}
  int pc(){return (int)thread.getCounter().getAddressableWordOffset();}
  void exec(int address,byte[] raw)throws Exception{
   monitor.checkCancelled();PseudoInstruction ins=decode(address,raw);
   put("PC",(address+1)&0x3fff);thread.setCounter(ins.getAddress().add(3));
   try{thread.getExecutor().execute(PcodeProgram.fromInstruction(ins),thread.getUseropLibrary());steps++;}
   catch(Exception e){throw new IllegalStateException("Source P-code runtime at "+pm(address)+" "+ins,e);}
  }
  void op(int site,int word)throws Exception{exec(site,bytes(word,3));}
  void nativeWord(int site)throws Exception{
   Instruction ins=currentProgram.getListing().getInstructionAt(pm(site));
   if(ins==null||ins.getLength()!=3)throw new IllegalStateException("Missing native PM vector "+pm(site));
   exec(site,ins.getBytes());
  }
 }
 public void run()throws Exception {
  String[] args=getScriptArgs();if(args.length!=2||!args[0].equals(currentProgram.getExecutableSHA256())||
       currentProgram.getFunctionManager().getFunctionCount()!=Integer.parseInt(args[1])||currentProgram.isChanged()||
       !currentProgram.getDomainFile().getPathname().startsWith("/RUSH28-architecture-import-validation/"))
    throw new IllegalStateException("Original saved source and bounded execution profile required");
  long version=currentProgram.getDomainFile().getVersion();lang=(SleighLanguage)currentProgram.getLanguage();
  var listing=currentProgram.getListing();
  String[] refNames={"RESET","IRQ2","IRQL1","IRQL0","SPORT0_TX","SPORT0_RX","IRQE","BDMA","SPORT1_TX_OR_IRQ1","SPORT1_RX_OR_IRQ0","TIMER","POWERDOWN"};
  int rtiStarts=0,jumpStarts=0,vectorNop=0;
  for(int index=0;index<12;index++){
   int start=index*4;StringBuilder symbols=new StringBuilder();
   for(int w=start;w<start+4;w++){
    Instruction i=listing.getInstructionAt(pm(w));
    if(i==null||i.getLength()!=3){symbols.append("UNDECODED;");continue;}
    symbols.append(i.toString().trim()).append(';');
    if(i.toString().trim().equals("NOP"))vectorNop++;
   }
   Instruction head=listing.getInstructionAt(pm(start));
   if(head!=null){if(head.toString().trim().equals("RTI"))rtiStarts++;if(head.toString().trim().startsWith("JUMP "))jumpStarts++;}
   println("SOURCE_VECTOR_REFERENCE_COMPARE at="+pm(start)+" ADSP218x_reference="+refNames[index]+
     " saved_native="+symbols+" Sunplus_IRQ_mapping=UNKNOWN");
  }
  // Execute the original reset-vector instructions up to their own JUMP.
  // Never assume that the ADSP interrupt vector map beyond PM:0023 is
  // identical to Sunplus: all current profiles jump into PM:0024 as main.
  int resetSteps=0;CPU reset=new CPU();
  int resetAt=0;
  for(;resetAt<4;resetAt++){
   Instruction resetIns=listing.getInstructionAt(pm(resetAt));
   need(resetIns!=null&&resetIns.getLength()==3,"Original reset vector instruction absent");
   boolean transfer=resetIns.toString().trim().startsWith("JUMP ");
   if(transfer)need(resetIns.getFlows().length==1,"Original reset requires single concrete jump");
   reset.nativeWord(resetAt);resetSteps++;
   if(transfer){
    need(reset.pc()==resetIns.getFlows()[0].getAddressableWordOffset(),
      "Original reset branch must take encoded PM target");
    println("SOURCE_RESET_EXECUTION_PASS nativeSourceSteps="+resetSteps+
      " originalResetBranch="+resetIns+" reached="+resetIns.getFlows()[0]);
    break;
   }
   need(reset.pc()==resetAt+1,"Original reset PM sequential control flow");
  }
  need(resetAt<4,"Original reset vector has no native direct JUMP");
  int executedVectorJumps=0,unknownHeads=0;
  // The codec profiles legitimately use different native IRQ handlers.
  // Validate and execute what each original source PM vector really encodes.
  for(int entry:expectedRti){
   Instruction nativeHead=listing.getInstructionAt(pm(entry));
   need(nativeHead!=null&&nativeHead.getLength()==3,"Source vector missing native PM word "+pm(entry));
   if(nativeHead.toString().trim().equals("RTI")){
    CPU cpu=new CPU();long ret=(0x350+entry)&0x3fff;
    // LDI ASTAT is required: ASTAT is packed from hardware flag registers.
    cpu.op(0x2fe,0x3c0000|((0xa5&0x3fff)<<4));cpu.put("IMASK",0x2ab);
    cpu.op(0x300,0x040002); // native PUSH STS
    cpu.put("AX0",ret);cpu.op(0x301,0x0d0cf0); // native PUSH PC from AX0
    need(cpu.get("DSP_STATUS_DEPTH")==1&&cpu.get("DSP_PC_DEPTH")==1,
      "Native interrupt frame fixture missing "+pm(entry));
    cpu.op(0x2ff,0x3c0000|((0x5a&0x3fff)<<4));cpu.put("IMASK",0);
    cpu.nativeWord(entry);
    need(cpu.pc()==ret,"Native RTI return PC "+pm(entry));
    need(cpu.get("ASTAT")==0xa5&&cpu.get("IMASK")==0x2ab,"Native RTI restores flags "+pm(entry));
    need(cpu.get("DSP_STATUS_DEPTH")==0&&cpu.get("DSP_PC_DEPTH")==0,"Native RTI stack cleaned "+pm(entry));
    rtis++;
    println("SOURCE_VECTOR_EXECUTION_PASS at="+pm(entry)+" originalOpcode="+nativeHead+
      " returnedPM="+pm((int)ret)+" restoredStatus=true stackDepths=0");
   }else if(nativeHead.toString().trim().startsWith("JUMP ")&&nativeHead.getFlows().length==1){
    CPU cpu=new CPU();cpu.nativeWord(entry);
    need(cpu.pc()==nativeHead.getFlows()[0].getAddressableWordOffset(),
      "Original native IRQ vector must jump to its encoded address "+pm(entry));
    executedVectorJumps++;
    println("SOURCE_VECTOR_EXECUTION_PASS at="+pm(entry)+" originalOpcode="+nativeHead+
      " nativeTarget="+nativeHead.getFlows()[0]+" Sunplus_IRQ_mapping=UNKNOWN");
   }else{
    unknownHeads++;
    println("SOURCE_VECTOR_EXECUTION_UNSUPPORTED at="+pm(entry)+" native="+nativeHead+
      " reason=no_source_proven_standalone_RTI_or_direct_JUMP");
   }
  }
  need(executedVectorJumps>=1&&unknownHeads==0,"Native vector heads have unresolved execution coverage");
  need(currentProgram.getDomainFile().getVersion()==version&&!currentProgram.isChanged(),"Original project not modified");
  println("SOURCE_VECTOR_EMULATOR_SUMMARY program="+currentProgram.getName()+
    " sourceSHA="+args[0]+" checkedADIvectorSlots=12 rtiStarts="+rtiStarts+
    " directJumpStarts="+jumpStarts+" vectorNOPs="+vectorNop+
    " realSourceRTIExecuted="+rtis+" nativeIRQlikeJUMPExecuted="+executedVectorJumps+
    " unsupportedVectorHeads="+unknownHeads+
    " originalPMinstructionsExecuted="+(rtis+executedVectorJumps+resetSteps)+
    " syntheticFrameSetupInstructions="+(steps-rtis-executedVectorJumps-resetSteps)+
    " allPcodeInstructionsExecuted="+steps+" checks="+checks+
    " SunplusVectorMapping=LIKELY_NOT_CONFIRMED siliconExecution=UNKNOWN");
 }
}
