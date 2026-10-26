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

public class SunplusDSPOriginalVectorContinuationQA extends GhidraScript {
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
       emu.getSharedState().setVar(lang.getAddressFactory().getAddressSpace("DM"),0L,0x8000,true,new byte[0x8000]);
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
    // A second path follows real handler code, not merely the vector JUMP.
    // A synthetic native interrupt frame is a software fixture, NOT a silicon IRQ.
    CPU irq=new CPU(); long ret=(0x350+entry)&0x3fff;
    irq.op(0x2fe,0x3c0000|((0x25&0x3fff)<<4));
    irq.put("IMASK",0x2ab);
    irq.op(0x300,0x040002); // native PUSH STS
    irq.put("AX0",ret);
    irq.op(0x301,0x0d0cf0); // native PUSH PC
    need(irq.get("DSP_STATUS_DEPTH")==1&&irq.get("DSP_PC_DEPTH")==1,
      "Vector handler synthetic IRQ frame "+pm(entry));
    irq.nativeWord(entry);
    int entryTarget=irq.pc(), walked=0;String stop="STEP_BOUND";
    Set<Integer> distinct=new LinkedHashSet<>();
    Map<Integer,Integer> visits=new LinkedHashMap<>();
    Deque<String> recent=new ArrayDeque<>();
    Map<Integer,Integer> eventAtPM=new LinkedHashMap<>();
    Set<Integer> acknowledged=new LinkedHashSet<>();
    Map<Integer,Boolean> waitForZero=new LinkedHashMap<>();
    int callHits=0,rtsHits=0,rtiHits=0;
    while(walked<12000){
      int before=irq.pc();
      if(before==ret){stop="RETURN_TO_FRAME_PC";break;}
      if(before<0||before>=0x4000){stop="OUT_OF_PM_RANGE";break;}
      Instruction ins=listing.getInstructionAt(pm(before));
      if(ins==null||ins.getLength()!=3){stop="UNDECODED_PM";break;}
      distinct.add(before);
      int hit=visits.getOrDefault(before,0)+1;
      visits.put(before,hit);
      // A 32-iteration CE loop may legitimately recur at this PC across
      // successive subroutine calls. Preserve it to the global step cap.
      if(hit>3000){stop="EXTREME_REPEAT_LIMIT";break;}
      recent.addLast(String.format("%04x",before)+" "+ins+" PCDEPTH="+irq.get("DSP_PC_DEPTH")+
        " AZF="+irq.get("AZF")+" ANF="+irq.get("ANF")+" CNTR="+irq.get("CNTR"));
      if(recent.size()>24)recent.removeFirst();
      String opname=ins.toString().trim();
      // Only introduce a synthetic external input for a source-proven
      // three-instruction hardware status polling loop. Do not patch opcodes.
      if(hit==3 && eventAtPM.size()<12 && !eventAtPM.containsKey(before)
          && opname.startsWith("DMREAD AR,0x")){
        Instruction arTest=listing.getInstructionAt(pm(before+1));
        Instruction eqBranch=listing.getInstructionAt(pm(before+2));
        if(arTest!=null && eqBranch!=null &&
           arTest.toString().trim().equals("AR = AR + 0") &&
           (eqBranch.toString().trim().startsWith("IF EQ JUMP ") ||
            eqBranch.toString().trim().startsWith("IF NE JUMP ")) &&
           eqBranch.getFlows().length==1 && eqBranch.getFlows()[0].equals(pm(before))){
          int dmword=Integer.parseInt(opname.substring("DMREAD AR,0x".length()),16);
          boolean clearForNE=eqBranch.toString().trim().startsWith("IF NE JUMP ");
          irq.emu.getSharedState().setVar(lang.getAddressFactory().getAddressSpace("DM"),
            dmword,2,true,bytes(clearForNE?0:1,2));
          eventAtPM.put(before,dmword);waitForZero.put(before,clearForNE);
          println("SOURCE_VECTOR_STATUS_INPUT vector="+pm(entry)+
            " nativePoll="+pm(before)+" DM="+String.format("DM:%04x",dmword)+
            " eventIndex="+eventAtPM.size()+" modeledValue="+(clearForNE?0:1)+
            " waitCondition="+(clearForNE?"NE":"EQ"));
        }
      }
      if(opname.contains("CALL "))callHits++;
      if(opname.equals("RTS"))rtsHits++;
      if(opname.equals("RTI"))rtiHits++;
      // Real P-code, real source bytes; deterministic zeroed DM fixture.
      // Do not silently skip faults or unsupported opcodes.
      try{irq.nativeWord(before);}
      catch(Exception failure){stop="EXECUTION_FAILED";println(
        "SOURCE_VECTOR_HANDLER_FAILURE vector="+pm(entry)+" at="+pm(before)+
        " native="+ins+" error="+failure.getMessage());break;}
      walked++;
      for(Map.Entry<Integer,Integer> event:eventAtPM.entrySet()){
        int poll=event.getKey();
        if(before==poll+2 && irq.pc()==poll+3 && acknowledged.add(poll)){
          need(irq.get("AZF")==(waitForZero.get(poll)?1:0),
            "Modeled event did not set expected comparison flags");
          println("SOURCE_VECTOR_STATUS_RELEASE vector="+pm(entry)+
            " nativePoll="+pm(poll)+" DM="+String.format("DM:%04x",event.getValue())+
            " reached="+pm(irq.pc())+" steps="+walked);
        }
      }
    }
    if(walked>=12000 && !stop.equals("RETURN_TO_FRAME_PC"))
      stop="BOUNDED_12000_INSTRUCTIONS";
    println("SOURCE_VECTOR_CONTINUATION_SUMMARY vector="+pm(entry)+
      " sourceTarget="+pm(entryTarget)+" steps="+walked+
      " uniquePC="+distinct.size()+" call="+callHits+" rts="+rtsHits+
      " rti="+rtiHits+" stop="+stop+" finalPC="+pm(irq.pc())+
      " finalCNTR="+irq.get("CNTR")+
      " finalLoopDepth="+irq.get("DSP_ARCH_LOOP_DEPTH")+
      " events="+eventAtPM.size()+" releasedEvents="+acknowledged.size()+
      " originalBytesPreserved=true siliconMapping=UNKNOWN");
    println("SOURCE_VECTOR_STATUS_SEQUENCE vector="+pm(entry)+
      " events="+eventAtPM.size()+" released="+acknowledged.size()+
      " executedNative="+walked+" stop="+stop+" finalPM="+pm(irq.pc())+
      " pcDepth="+irq.get("DSP_PC_DEPTH")+" statusDepth="+irq.get("DSP_STATUS_DEPTH")+
      " syntheticOnly=true originalMachineBytesUnchanged=true");
    println("SOURCE_VECTOR_HANDLER_TRACE vector="+pm(entry)+
      " sourceTarget="+pm(entryTarget)+" executedNativeInstructions="+walked+
      " uniqueInstructionSites="+distinct.size()+" stop="+stop+
      " finalPM="+pm(irq.pc())+" PC_depth="+irq.get("DSP_PC_DEPTH")+
      " statusDepth="+irq.get("DSP_STATUS_DEPTH")+
      " calls="+callHits+" rts="+rtsHits+" rti="+rtiHits+
      " repeatedSite="+(stop.equals("REPEATED_PC_LIMIT")?pm(irq.pc()).toString():"none")+
      " syntheticDM=true hardwareIRQ=UNKNOWN");
    if(stop.equals("REPEATED_PC_LIMIT")){
      println("SOURCE_VECTOR_WAIT_RECENT vector="+pm(entry)+
        " recent="+String.join(" | ",recent));
      int cur=irq.pc();
      for(int off=-8;off<=4;off++){
        int loc=cur+off;
        if(loc<0||loc>=0x4000)continue;
        Instruction where=listing.getInstructionAt(pm(loc));
        if(where==null)continue;
        StringBuilder pcode=new StringBuilder();
        for(var op:where.getPcode()){
          if(pcode.length()>0)pcode.append(" ; ");
          pcode.append(op.toString());
        }
        println("SOURCE_VECTOR_WAIT_INSTRUCTION vector="+pm(entry)+" at="+pm(loc)+
          " seen="+visits.getOrDefault(loc,0)+" ins="+where+
          " flows="+Arrays.toString(where.getFlows())+
          " pcode="+pcode);
      }
    }
    if(stop.equals("RETURN_TO_FRAME_PC")){
      need(irq.get("DSP_PC_DEPTH")==0&&irq.get("DSP_STATUS_DEPTH")==0,
        "Source handler returned without unwinding injected interrupt frame at "+pm(entry));
      need(irq.get("ASTAT")==0x25&&irq.get("IMASK")==0x2ab,
        "Source handler failed to restore modeled interrupt status at "+pm(entry));
      println("SOURCE_VECTOR_HANDLER_RETURN_PROOF vector="+pm(entry)+
        " at="+pm(entryTarget)+" returned="+pm((int)ret)+
        " savedASTAT=0x25 savedIMASK=0x2ab returnedViaRTI="+(rtiHits>0)+
        " softwareStackAndStatusRestored=true hardwareIRQ=UNKNOWN");
    }
    if(walked==0)throw new IllegalStateException(
      "No executable source handler instruction for vector "+pm(entry));
   }else{
    unknownHeads++;
    println("SOURCE_VECTOR_EXECUTION_UNSUPPORTED at="+pm(entry)+" native="+nativeHead+
      " reason=no_source_proven_standalone_RTI_or_direct_JUMP");
   }
  }
  need(executedVectorJumps>=1&&unknownHeads==0,"Native vector heads have unresolved execution coverage");
  need(currentProgram.getDomainFile().getVersion()==version&&!currentProgram.isChanged(),"Original project not modified");
  println("SOURCE_VECTOR_CONTINUATION_EMULATOR_SUMMARY program="+currentProgram.getName()+
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
