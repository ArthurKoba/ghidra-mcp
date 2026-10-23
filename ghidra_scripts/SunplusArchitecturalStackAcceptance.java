//@category Sunplus/Verification
// Execute actual native instruction P-code in the software sequencer view.
// Tests do not mutate executable bytes or invent stack contents via a substitute backend.
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
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.Gson;

public class SunplusArchitecturalStackAcceptance extends GhidraScript {
 private SleighLanguage language;
 private final Map<Long,PseudoInstruction> decoded=new HashMap<>();
 private final Map<String,Integer> groups=new LinkedHashMap<>();
 private int checks=0,executed=0,faults=0;
 private final List<String> failures=new ArrayList<>();
 private String active="";
 private void need(boolean v,String message){checks++;if(!v)throw new IllegalStateException(active+": "+message);}
 private long num(byte[] b){long n=0;for(byte x:b)n=(n<<8)|(x&255);return n;}
 private byte[] bytes(long n,int size){byte[] b=new byte[size];for(int i=size-1;i>=0;i--){b[i]=(byte)n;n>>>=8;}return b;}
 public class Faults extends AnnotatedPcodeUseropLibrary<byte[]> {
  long lastFault=0;
  @PcodeUserop(hasSideEffects=true)
  public void dsp_model_stack_fault(byte[] code){lastFault=num(code);throw new IllegalStateException("EXPLICIT_MODEL_STACK_FAULT="+lastFault);}
 }
 private PseudoInstruction decode(int pc,int word)throws Exception{
  long key=((long)pc<<24)|(word&0xffffffL);PseudoInstruction cached=decoded.get(key);if(cached!=null)return cached;
  Address at=currentProgram.getAddressFactory().getAddress("PM:"+Integer.toHexString(pc));
  var memory=new ByteMemBufferImpl(at,bytes(word,3),true);
  var ctx=new ProcessorContextImpl(language);
  ctx.setValue(language.getRegister("DSPCTX"),BigInteger.ZERO);
  ctx.setValue(language.getRegister("codec_arch_stack_mode"),BigInteger.ONE);
  ctx.setValue(language.getRegister("codec_ce_phase"),BigInteger.ZERO);
  var ins=new PseudoInstruction(currentProgram.getAddressFactory(),at,language.parse(memory,ctx,false),memory,ctx);
  if(ins.getLength()!=3)throw new IllegalStateException("Invalid native decode at "+at+" word="+Integer.toHexString(word));
  decoded.put(key,ins);return ins;
 }
 private class Machine {
  final Faults library=new Faults();
  final PcodeEmulator emulator=new PcodeEmulator(language){
   @Override protected PcodeUseropLibrary<byte[]> createUseropLibrary(){return Machine.this.library;}
  };
  final PcodeThread<byte[]> thread=emulator.newThread();
  Machine(){
   thread.getState().setVar(language.getAddressFactory().getRegisterSpace(),0L,0x200,false,new byte[0x200]);
   emulator.getSharedState().setVar(language.getAddressFactory().getAddressSpace("DSPSTACK"),0L,0x200,false,new byte[0x200]);
   put("SSTAT",0x55);put("DSP_IRQ_ENABLED",1);
   if(!library.getUserops().containsKey("dsp_model_stack_fault")||thread.getUseropLibrary().getUserops().get("dsp_model_stack_fault")!=library.getUserops().get("dsp_model_stack_fault"))throw new IllegalStateException("Fault userop binding mismatch");
  }
  void put(String name,long value){Register r=language.getRegister(name);if(r==null)throw new IllegalArgumentException(name);thread.getState().setVar(r,bytes(value,r.getNumBytes()));}
  long get(String name){return num(thread.getState().getVar(language.getRegister(name),Reason.INSPECT));}
  int pc(){return (int)thread.getCounter().getAddressableWordOffset();}
  void step(int pc,int word)throws Exception{
   monitor.checkCancelled();PseudoInstruction ins=decode(pc,word);
   put("PC",(pc+1)&0x3fff);thread.setCounter(ins.getAddress().add(3));
   try {thread.getExecutor().execute(PcodeProgram.fromInstruction(ins),thread.getUseropLibrary());executed++;}
   catch(Exception e){throw new IllegalStateException("pc="+Integer.toHexString(pc)+" word="+Integer.toHexString(word)+" "+ins+" "+e,e);}
  }
  void at(int word)throws Exception{step(0x100,word);}
  void astat(int bits)throws Exception{at(ldi(0,bits));}
  void count(int value)throws Exception{at(ldi(5,value));}
  void pushPc(int address)throws Exception{put("AX0",address);at(0x0d0cf0);}
  void expectFault(int word,int kind)throws Exception{
   boolean saw=false;library.lastFault=0;put("DSP_STACK_FAULT",0);
   try{at(word);}catch(Exception e){saw=library.lastFault==kind;if(!saw){println("FAULT_EXCEPTION "+e);for(Throwable t=e.getCause();t!=null;t=t.getCause())println("FAULT_CAUSE "+t);}}
   if(!saw)println("FAULT_LIBRARY bound="+thread.getUseropLibrary().getUserops().keySet()+" custom="+library.getUserops().keySet()+" recorded="+library.lastFault);
   need(saw&&get("DSP_STACK_FAULT")==kind,"Expected specific fail-closed stack fault "+kind+" actual="+get("DSP_STACK_FAULT"));faults++;
  }
 }
 private int ldi(int reg,int value){return 0x3c0000|((value&0x3fff)<<4)|reg;}
 private int call(int target,int cond){return 0x1c0000|((target&0x3fff)<<4)|cond;}
 private int doloop(int target,int term){return 0x140000|((target&0x3fff)<<4)|term;}
 private void group(String name,Task t)throws Exception{
  active=name;int start=checks;
  try{t.run();groups.put(name,checks-start);println("STACK_GROUP_PASS "+name+" checks="+(checks-start));}
  catch(Exception e){if(monitor.isCancelled())throw e;failures.add(name+": "+e);println("STACK_GROUP_FAIL "+name+" "+e);}
 }
 @FunctionalInterface private interface Task{void run()throws Exception;}
 private boolean predicate(int c,int a,int counter){
  boolean z=(a&1)!=0,n=(a&2)!=0,v=(a&4)!=0,carry=(a&8)!=0,sign=(a&16)!=0,mv=(a&64)!=0;
  return switch(c){case 0->z;case 1->!z;case 2->!z&&n==v;case 3->z||n!=v;case 4->n!=v;case 5->n==v;case 6->v;case 7->!v;case 8->carry;case 9->!carry;case 10->sign;case 11->!sign;case 12->mv;case 13->!mv;case 14->counter!=1;default->true;};
 }
 private void pc16()throws Exception{
  Machine m=new Machine();
  for(int i=0;i<16;i++){m.step(0x100+i,call(0x500,15));need(m.pc()==0x500&&m.get("DSP_PC_DEPTH")==i+1&&m.get("PCSTACKTOP")==0x101+i,"CALL push "+i+" PC="+m.pc()+" depth="+m.get("DSP_PC_DEPTH")+" TOP="+m.get("PCSTACKTOP"));}
  m.expectFault(call(0x500,15),1);need(m.get("DSP_PC_DEPTH")==16&&(m.get("SSTAT")&2)!=0,"Shared PC overflow not retained");
  for(int i=15;i>=0;i--){m.step(0x500,0x0a000f);need(m.pc()==0x101+i&&m.get("DSP_PC_DEPTH")==i,"LIFO RTS "+i);}
  need((m.get("SSTAT")&3)==3,"PC sticky overflow/empty");m.at(ldi(2,0));need((m.get("SSTAT")&3)==3,"Read-only SSTAT overwrite cleared sticky bits");m.expectFault(0x0a000f,2);
  m=new Machine();for(int i=0;i<4;i++)m.step(0x100+i,doloop(0x700+i,15));
  for(int i=0;i<12;i++)m.step(0x200+i,call(0x500,15));
  need(m.get("DSP_PC_DEPTH")==16&&m.get("DSP_ARCH_LOOP_DEPTH")==4,"DO/CALL did not share one PC stack");
  m.expectFault(call(0x500,15),1);
  for(int i=11;i>=0;i--){m.step(0x500,0x0a000f);need(m.pc()==0x201+i,"Shared call unwind");}
  for(int i=3;i>=0;i--){need(m.get("PCSTACKTOP")==0x101+i,"Preserved loop start below call frames");m.at(0x040018);}
  need(m.get("DSP_PC_DEPTH")==0&&m.get("DSP_ARCH_LOOP_DEPTH")==0,"Shared frames failed unwind");
 }
 private void counters()throws Exception{
  Machine m=new Machine();for(int i=0;i<5;i++){m.count(10+i);need(m.get("CNTR")==10+i&&m.get("DSP_ARCH_COUNT_DEPTH")==i,"CNTR push on write independent of loop");}
  m.expectFault(ldi(5,77),3);need(m.get("CNTR")==14&&m.get("DSP_ARCH_COUNT_DEPTH")==4&&(m.get("SSTAT")&8)!=0,"Count overflow damage");
  m.at(ldi(13,33));need(m.get("CNTR")==33&&m.get("DSP_ARCH_COUNT_DEPTH")==4,"OWRCNTR must not push");
  for(int i=3;i>=0;i--){m.at(0x040004);need(m.get("CNTR")==10+i&&m.get("DSP_ARCH_COUNT_DEPTH")==i,"CNTR pop "+i);}
  m.at(0x040004);need(m.get("DSP_CNTR_VALID")==0,"Empty counter pop must invalidate active CNTR");
  m.put("AR",0xffff);m.at(0x0d0c5a);need(m.get("CNTR")==0x3fff&&m.get("DSP_ARCH_COUNT_DEPTH")==0,"Register CNTR load width");
  m.emulator.getSharedState().setVar(language.getAddressFactory().getAddressSpace("DM"),0x100L,2,true,bytes(123,2));
  m.at(0x8c1005);need(m.get("CNTR")==123&&m.get("DSP_ARCH_COUNT_DEPTH")==1,"Direct DM CNTR push");
 }
 private int emitNested(TreeMap<Integer,Integer> code,int[] counts,int level,int at,int[] inner){
  code.put(at,ldi(5,counts[level]));int setup=at+1;int next=at+2;
  if(level+1<counts.length)next=emitNested(code,counts,level+1,next,inner);
  else {inner[0]=next;code.put(next++,0);}
  int end=next;code.put(end,0);code.put(setup,doloop(end,14));return end+1;
 }
 private void loops()throws Exception{
  for(int[] counts:new int[][]{{2},{2,3},{2,3,2,2}}){
   Machine m=new Machine();TreeMap<Integer,Integer> code=new TreeMap<>();int[] inner={0};int end=emitNested(code,counts,0,0x100,inner);int pc=0x100,visits=0,steps=0;
   while(pc!=end&&steps<500){if(pc==inner[0])visits++;Integer word=code.get(pc);need(word!=null,"Unknown nested-loop PC "+Integer.toHexString(pc));m.step(pc,word);pc=m.pc();steps++;}
   int expected=1;for(int x:counts)expected*=x;
   need(pc==end&&visits==expected,"Nested count "+Arrays.toString(counts)+" visits="+visits+" pc="+pc);
   need(m.get("DSP_PC_DEPTH")==0&&m.get("DSP_ARCH_LOOP_DEPTH")==0&&m.get("DSP_ARCH_COUNT_DEPTH")==0&&m.get("DSP_CNTR_VALID")==0,"Nested stacks leaked");
  }
  Machine m=new Machine();m.count(0);m.step(0x100,doloop(0x101,14));
  for(int i=0;i<16384;i++){m.step(0x101,0);if(i<16383)need(m.pc()==0x101,"Zero CNTR iteration truncated");}
  need(m.pc()==0x102&&m.get("DSP_CNTR_VALID")==0&&m.get("DSP_PC_DEPTH")==0,"CNTR zero wrap length");
  m=new Machine();for(int i=0;i<4;i++)m.step(0x100+i,doloop(0x700+i,15));
  m.expectFault(doloop(0x780,15),5);need((m.get("SSTAT")&0x80)!=0&&m.get("DSP_ARCH_LOOP_DEPTH")==4,"Loop overflow");
  m=new Machine();m.step(0x100,doloop(0x101,15));for(int i=0;i<5;i++){m.step(0x101,0);need(m.pc()==0x101,"Forever loop exited");}
  m.at(0x040018);need(m.get("DSP_PC_DEPTH")==0&&m.get("DSP_ARCH_LOOP_DEPTH")==0,"Manual break unwind");
 }
 private void mixedCalls()throws Exception{
  for(boolean secondStage:new boolean[]{false,true}){
   Machine m=new Machine();Map<Integer,Integer> program=new HashMap<>();
   program.put(0x300,ldi(5,2));program.put(0x301,doloop(0x305,14));program.put(0x302,call(0x309,15));
   program.put(0x303,0);program.put(0x304,0);program.put(0x305,0);
   int innerStart=secondStage?0x30d:0x309;
   if(secondStage){program.put(0x309,call(0x30d,15));program.put(0x30a,0x0a000f);}
   program.put(innerStart,ldi(5,3));program.put(innerStart+1,doloop(innerStart+2,14));
   program.put(innerStart+2,0);program.put(innerStart+3,0x0a000f);
   int pc=0x300,visits=0,returned=0,steps=0;
   while(pc!=0x306&&steps<100){
    if(pc==innerStart+2)visits++;
    if(pc==0x303){returned++;need(m.get("DSP_ARCH_LOOP_DEPTH")==1&&m.get("DSP_PC_DEPTH")==1&&m.get("DSP_ARCH_COUNT_DEPTH")==0&&m.get("CNTR")==3-returned,"Interprocedural loop/counter restoration");}
    Integer word=program.get(pc);need(word!=null,"Escaped native mixed CALL/DO program");m.step(pc,word);pc=m.pc();steps++;
   }
   need(pc==0x306&&visits==6&&returned==2&&m.get("DSP_PC_DEPTH")==0&&m.get("DSP_ARCH_LOOP_DEPTH")==0,"Mixed native CALL/DO failed");
  }
  // Create an interrupt-style PC/status frame using documented native pushes.
  // This checks the return frame, not asynchronous interrupt delivery.
  Machine m=new Machine();m.count(3);m.step(0x100,doloop(0x150,14));m.step(0x101,call(0x200,15));
  m.astat(0xa5);m.put("IMASK",0x2ab);m.at(0x040002);m.pushPc(0x200);
  m.astat(0x5a);m.put("IMASK",0);m.step(0x300,0x0a001f);
  need(m.pc()==0x200&&m.get("DSP_PC_DEPTH")==2&&m.get("DSP_ARCH_LOOP_DEPTH")==1&&m.get("CNTR")==3&&m.get("ASTAT")==0xa5&&m.get("IMASK")==0x2ab,"RTI nested above DO/CALL corrupts frame");
  m.step(0x210,0x0a000f);need(m.pc()==0x102&&m.get("DSP_PC_DEPTH")==1,"RTI displaced caller return");
  m.step(0x150,0);need(m.pc()==0x101&&m.get("CNTR")==2,"CE after returned status frame");
 }
 private void loopConditionMatrix()throws Exception{
  for(int term=0;term<16;term++)for(int flags=0;flags<256;flags++){
   Machine m=new Machine();m.count(2);m.astat(flags);m.step(0x100,doloop(0x101,term));m.step(0x101,0);
   boolean again=predicate(term,flags,2);
   need(m.pc()==(again?0x101:0x102)&&m.get("DSP_ARCH_LOOP_DEPTH")== (again?1:0)&&m.get("DSP_PC_DEPTH")== (again?1:0),"DO termination predicate term="+term+" flags="+flags);
  }
  Machine m=new Machine();m.count(9);m.count(1);m.step(0x100,call(0x300,14));
  need(m.pc()==0x101&&m.get("DSP_PC_DEPTH")==0&&m.get("CNTR")==9&&m.get("DSP_ARCH_COUNT_DEPTH")==0,"Conditional NOT CE exit restores count stack");
 }
 private void status()throws Exception{
  Machine m=new Machine();
  for(int i=0;i<12;i++){m.astat((i*19)&255);m.at(ldi(1,i&0x7f));m.put("IMASK",(i*83)&0x3ff);m.at(0x040002);need(m.get("DSP_STATUS_DEPTH")==i+1,"Status stack push");}
  m.expectFault(0x040002,6);need((m.get("SSTAT")&0x20)!=0&&m.get("DSP_STATUS_DEPTH")==12,"Status overflow");
  for(int i=11;i>=0;i--){m.at(0x040003);need(m.get("DSP_STATUS_DEPTH")==i&&m.get("ASTAT")==((i*19)&255)&&m.get("MSTAT")==i&&m.get("IMASK")==((i*83)&1023),"Status triplet pop "+i);}
  need((m.get("SSTAT")&0x30)==0x30,"Status sticky overflow/empty");m.expectFault(0x040003,7);
  m=new Machine();String[] regs={"AX0","AX1","MX0","MX1","AY0","AY1","MY0","MY1","SI","SE","AR","MR0","MR1","MR2","SR0","SR1","AF","MF","SB"};
  for(int i=0;i<regs.length;i++){m.put(regs[i],100+i);m.put("DSP_ALT_"+regs[i],200+i);}
  m.at(0x0c0030);for(int i=0;i<regs.length;i++)need(m.get(regs[i])==200+i&&m.get("DSP_ALT_"+regs[i])==100+i,"Secondary bank "+regs[i]);
  m.at(0x0c0020);for(int i=0;i<regs.length;i++)need(m.get(regs[i])==100+i&&m.get("DSP_ALT_"+regs[i])==200+i,"Primary bank "+regs[i]);
 }
 private void returnsMatrix()throws Exception{
  for(int condition=0;condition<16;condition++)for(int flags=0;flags<256;flags++){
   Machine m=new Machine();int saved=(flags^0xa5)&255;m.astat(saved);m.put("IMASK",0x2ab);m.at(0x040002);m.pushPc(0x1234);
   m.astat(flags);m.put("IMASK",0);m.count(2);boolean take=predicate(condition,flags,2);
   m.step(0x100,0x0a0010|condition);
   need(m.pc()==(take?0x1234:0x101),"Conditional RTI PC c="+condition+" flags="+flags);
   need(m.get("DSP_PC_DEPTH")== (take?0:1)&&m.get("DSP_STATUS_DEPTH")== (take?0:1),"Conditional RTI stack change");
   need(m.get("ASTAT")== (take?saved:flags)&&m.get("IMASK")== (take?0x2ab:0),"RTI status restoration");
  }
  Machine m=new Machine();m.pushPc(0x333);m.expectFault(0x0a001f,7);need(m.get("DSP_PC_DEPTH")==1,"RTI status-underflow changed PC stack");
  m=new Machine();m.at(0x040002);m.expectFault(0x0a001f,2);need(m.get("DSP_STATUS_DEPTH")==1,"RTI PC-underflow changed status");
 }
 private void callsMatrix()throws Exception{
  for(int condition=0;condition<16;condition++)for(int flags=0;flags<256;flags++){
   Machine m=new Machine();m.astat(flags);m.count(2);boolean take=predicate(condition,flags,2);m.step(0x100,call(0x345,condition));
   need(m.pc()==(take?0x345:0x101)&&m.get("DSP_PC_DEPTH")==(take?1:0),"Conditional CALL c="+condition+" flags="+flags);
   if(take){m.step(0x345,0x0a000f);need(m.pc()==0x101&&m.get("DSP_PC_DEPTH")==0,"CALL/RTS roundtrip");}
  }
  Machine m=new Machine();m.put("I6",0x500);m.step(0x100,0x0b009f);need(m.pc()==0x500&&m.get("PCSTACKTOP")==0x101,"Indirect CALL I6");m.step(0x500,0x0a000f);need(m.pc()==0x101,"Indirect CALL/RTS");
 }
 private void conditionEnd()throws Exception{
  for(int word:new int[]{call(0x500,0),0x185000,0x238610}){
   Machine m=new Machine();m.count(2);m.astat(0);m.step(0x100,doloop(0x101,14));m.step(0x101,word);
   need(m.pc()==0x101&&m.get("CNTR")==1&&m.get("DSP_PC_DEPTH")==1,"False conditional skipped CE for "+Integer.toHexString(word));
   m.step(0x101,word);need(m.pc()==0x102&&m.get("DSP_PC_DEPTH")==0,"False conditional failed loop exit");
  }
  Machine m=new Machine();m.count(2);m.astat(1);m.step(0x100,doloop(0x101,14));m.step(0x101,call(0x500,0));
  need(m.pc()==0x500&&m.get("CNTR")==2&&m.get("DSP_PC_DEPTH")==2,"Taken CALL must override CE endpoint");
 }
 private void manualAndDelay()throws Exception{
  for(int status=0;status<4;status++)for(int pops=0;pops<8;pops++)for(int irq:new int[]{0,2,3}){
   Machine m=new Machine();m.count(5);m.count(3);m.step(0x100,doloop(0x700,15));m.at(0x040002);
   int word=0x040000|(irq<<5)|(pops<<2)|status;m.at(word);
   need(m.get("DSP_STATUS_DEPTH")== (status==2?2:status==3?0:1),"Combined status operation");
   need(m.get("DSP_ARCH_COUNT_DEPTH")== ((pops&1)!=0?0:1),"Combined count operation");
   need(m.get("DSP_ARCH_LOOP_DEPTH")== ((pops&2)!=0?0:1),"Combined loop operation");
   need(m.get("DSP_PC_DEPTH")== ((pops&4)!=0?0:1),"Combined PC operation");
   need(m.get("DSP_IRQ_ENABLED")== (irq==2?0:1),"Combined interrupt enable bit");
  }
  Machine m=new Machine();m.pushPc(0xf234);need(m.get("PCSTACKTOP")==0x3234,"TopPC width mask");
  m.at(0x0d030f);need(m.get("AX0")==0x3234&&m.get("DSP_PC_DEPTH")==1&&m.get("DSP_PC_POP_PENDING")==1,"TOPPCSTACK read must delay pop");
  m.at(0);need(m.get("DSP_PC_DEPTH")==0&&m.get("DSP_PC_POP_PENDING")==0,"Delayed pop after NOP");
  m=new Machine();m.pushPc(0x234);m.at(0x0d030f);m.at(call(0x500,15));
  need(m.pc()==0x500&&m.get("DSP_PC_DEPTH")==1&&m.get("PCSTACKTOP")==0x234,"Delayed pop must commit after a taken CALL too");
  m=new Machine();m.pushPc(0x123);m.pushPc(0x234);m.at(0x0d030f);m.at(0x0d031f);
  need(m.get("AX0")==0x234&&m.get("AX1")==0x234&&m.get("DSP_PC_DEPTH")==1,"Consecutive delayed TOPPC reads");m.at(0);need(m.get("DSP_PC_DEPTH")==0,"Second delayed pop lost");
  m=new Machine();m.step(0x3fff,0);need(m.pc()==0,"14-bit PC fallthrough wrap");
  m.step(0x3fff,call(0x500,15));need(m.pc()==0x500&&m.get("PCSTACKTOP")==0,"14-bit CALL return wrap");m.step(0x500,0x0a000f);need(m.pc()==0,"Wrapped PC return");
 }
 private String nativeHash()throws Exception{MessageDigest md=MessageDigest.getInstance("SHA-256");byte[] b=new byte[8192];for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){Address a=block.getStart();long n=block.getSize();while(n>0){int take=(int)Math.min(n,b.length);if(currentProgram.getMemory().getBytes(a,b,0,take)!=take)throw new IllegalStateException("Short native read");md.update(b,0,take);a=a.add(take);n-=take;}}return HexFormat.of().formatHex(md.digest());}
 public void run()throws Exception{
  String[] args=getScriptArgs();if(args.length>1)throw new IllegalArgumentException("Optional audit/persist/readback");String mode=args.length==0?"audit":args[0];
  if(!Set.of("audit","persist","readback").contains(mode))throw new IllegalArgumentException(mode);
  String root=System.getenv("GHIDRA_MCP_PROJECT_ROOT");if(root==null||!root.endsWith("/rush26-stack-model-20261023/projects"))throw new IllegalStateException("Isolated local project only");
  if(currentProgram==null||currentProgram.isChanged())throw new IllegalStateException("Clean saved program required");
  language=(SleighLanguage)currentProgram.getLanguage();if(language.getRegister("codec_arch_stack_mode")==null)throw new IllegalStateException("Stack execution mode absent");
  String original=nativeHash();int functions=currentProgram.getFunctionManager().getFunctionCount();
  group("shared-PC16-CALL-DO",this::pc16);group("counter-stack-OWRCNTR",this::counters);group("nested-DO-CE",this::loops);
  group("mixed-CALL-DO-RTI",this::mixedCalls);group("all-DO-termination-flags",this::loopConditionMatrix);
  group("status12-and-register-banks",this::status);group("RTI-all-condition-flags",this::returnsMatrix);
  group("CALL-all-condition-flags",this::callsMatrix);group("conditional-loop-end",this::conditionEnd);group("combined-POP-and-delayed-TOPPC",this::manualAndDelay);
  need(failures.isEmpty(),"Test group failures: "+failures);
  need(original.equals(nativeHash())&&functions==currentProgram.getFunctionManager().getFunctionCount()&&!currentProgram.isChanged(),"Executable bytes or saved model mutated by tests");
  Map<String,Object> result=new LinkedHashMap<>();result.put("state","SOFTWARE_SEQUENCER_TESTS_PASSED");result.put("checks",checks);result.put("native_instructions_executed",executed);result.put("expected_stack_faults",faults);result.put("groups",groups);result.put("original_initialized_sha256",original);result.put("program",currentProgram.getName());result.put("function_count",functions);result.put("scope","Executable SLEIGH stack view; documented control state and explicit invalid-state faults");
  String json=new Gson().toJson(result);String group="RUSH26 software sequencer",key="stack-model-tests-v1";
  if(mode.equals("persist")){int tx=currentProgram.startTransaction("Save software sequencer model test evidence");boolean done=false;try{currentProgram.getOptions(group).setString(key,json);done=true;}finally{currentProgram.endTransaction(tx,done);}}
  if(mode.equals("readback"))need(json.equals(currentProgram.getOptions(group).getString(key,"")),"Saved test result mismatch");
  println("SOFTWARE_STACK_MODEL_RESULT "+json);println("SOFTWARE_STACK_MODEL_PASS mode="+mode);
 }
}
