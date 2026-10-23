//@category Sunplus/Verification
// Prove the destination of existing native DO/CE BRANCHIND edges; do not
// replace them with direct branches. Only evidence options may be written.
// Scope: saved program/model, active DO entry, no asynchronous register clobber
// or self-modifying executable memory. This is not a silicon/interrupt proof.
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
import com.google.gson.Gson;

public class SunplusCeIndirectTargetProof extends GhidraScript {
 private static final Pattern DO=Pattern.compile("^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
 private static final String GROUP="RUSH26 CE indirect target proof",KEY="saved-model-proof-v1";
 private static final Set<String> TARGETS=Set.of("DSP_LOOP_START","DSP_STATIC_START_OUTER","DSP_STATIC_START_INNER");
 private static final Set<String> FORBIDDEN_USEROPS=Set.of("dsp_pop_loop_stack","dsp_pop_pc_stack","dsp_rti_restore_status");
 private record Loop(Instruction start,Instruction end,Address expected,Function owner,Register target,int branchIndex) {}
 private void need(boolean yes,String message){if(!yes)throw new IllegalStateException(message);}
 private boolean overlap(Varnode out,Register r){
  if(out==null||!out.getAddress().getAddressSpace().equals(r.getAddress().getAddressSpace()))return false;
  long a=out.getOffset(),b=r.getOffset();return a<b+r.getNumBytes() && b<a+out.getSize();
 }
 private boolean same(Varnode a,Varnode b){return a.getSize()==b.getSize()&&a.getAddress().equals(b.getAddress());}
 private boolean isreg(Varnode v,Register r){return v!=null&&v.getAddress().equals(r.getAddress())&&v.getSize()==r.getNumBytes();}
 private boolean constant(Varnode v,long n){return v.isConstant()&&v.getOffset()==n;}
 private Address pm(String raw){return currentProgram.getAddressFactory().getAddress("PM:"+raw);}
 private String pcode(Instruction ins){return Arrays.toString(ins.getPcode());}
 private String sha(String text)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}
 private String nativeHash()throws Exception{
  MessageDigest md=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   Address a=block.getStart();long left=block.getSize();while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,buffer.length);
    need(currentProgram.getMemory().getBytes(a,buffer,0,n)==n,"Incomplete native image read");md.update(buffer,0,n);a=a.add(n);left-=n;}
  }return HexFormat.of().formatHex(md.digest());
 }
 private String functionHash()throws Exception{
  StringBuilder s=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))s.append(f.getEntryPoint()).append('/').append(f.getName()).append('/').append(f.getBody()).append('/').append(f.getCallingConventionName()).append('\n');return sha(s.toString());
 }
 private String userop(PcodeOp op){return currentProgram.getLanguage().getUserDefinedOpName((int)op.getInput(0).getOffset());}
 private List<Loop> discover(int expectedDo,int expectedIndirect)throws Exception{
  List<Loop> result=new ArrayList<>();int all=0;
  for(Instruction start:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();if(!start.getAddress().getAddressSpace().getName().equals("PM"))continue;
   var m=DO.matcher(start.toString().trim());if(!m.matches())continue;all++;
   Instruction end=currentProgram.getListing().getInstructionAt(pm(m.group(1)));need(end!=null,"Missing CE instruction");
   Address expected=start.getFallThrough();int cb=0,ind=0,match=0,branchIndex=-1;PcodeOp[] ops=end.getPcode();
   for(int i=0;i<ops.length;i++){PcodeOp op=ops[i];
    if(op.getOpcode()==PcodeOp.CBRANCH)cb++;
    if(op.getOpcode()==PcodeOp.BRANCHIND){ind++;branchIndex=i;}
    if((op.getOpcode()==PcodeOp.BRANCH||op.getOpcode()==PcodeOp.CBRANCH)&&op.getInput(0).getAddress().equals(expected))match++;
   }
   if(cb==0||ind==0||match>0)continue;
   need(ind==1,"Ambiguous computed CE target at "+end.getAddress());
   Varnode t=ops[branchIndex].getInput(0);Register reg=currentProgram.getLanguage().getRegister(t.getAddress(),t.getSize());
   need(reg!=null&&reg.getNumBytes()==2&&TARGETS.contains(reg.getName()),"Unsupported target expression "+t);
   Function owner=currentProgram.getFunctionManager().getFunctionContaining(start.getAddress());
   need(owner!=null&&owner.getBody().contains(end.getAddress())&&owner.getBody().contains(expected),"DO/end ownership mismatch");
   need(start.getLength()==3&&expected.equals(start.getAddress().add(3)),"DO successor not the next PM word");
   byte[] bytes=start.getBytes();int word=(bytes[0]&255)<<16|(bytes[1]&255)<<8|(bytes[2]&255);
   need((word>>>18)==5&&(word&15)==14&&((word>>>4)&0x3fff)==end.getAddress().getAddressableWordOffset(),"Native DO encoding mismatch");
   result.add(new Loop(start,end,expected,owner,reg,branchIndex));
  }
  need(all==expectedDo&&result.size()==expectedIndirect,"Scoped CE inventory mismatch: "+all+"/"+result.size());return result;
 }
 private Map<String,Object> calleeProof(Function f,Register target,Set<Address> visiting,int depth)throws Exception{
  need(f!=null&&!f.isExternal()&&!f.isThunk()&&depth<=5,"Unresolved or excessive callee scope");
  need(visiting.add(f.getEntryPoint()),"Recursive call requires a separate proof");
  need("__sunplus_loop_safe".equals(f.getCallingConventionName()),"No previously accepted loop-preserving ABI at "+f.getEntryPoint());
  int count=0,returns=0;Set<String> userops=new TreeSet<>();List<Map<String,Object>> children=new ArrayList<>();StringBuilder evidence=new StringBuilder();
  for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true)){
   monitor.checkCancelled();need(++count<=5000,"Callee scan bound");String text=ins.toString().trim();
   need(!text.startsWith("DO ")&&!text.startsWith("RTI"),"Callee touches loop/interrupt return stack");
   if(ins.getFlowType().isCall()){
    Address[] flows=ins.getFlows();need(flows.length==1,"Computed callee call");
    children.add(calleeProof(currentProgram.getFunctionManager().getFunctionAt(flows[0]),target,visiting,depth+1));
   }
   for(PcodeOp op:ins.getPcode()){
    need(!overlap(op.getOutput(),target),"Callee writes target register "+ins.getAddress());
    if(op.getOpcode()==PcodeOp.BRANCHIND||op.getOpcode()==PcodeOp.CALLIND)throw new IllegalStateException("Callee leaves proven flow "+ins.getAddress());
    if(op.getOpcode()==PcodeOp.RETURN)returns++;
    if((op.getOpcode()==PcodeOp.BRANCH||op.getOpcode()==PcodeOp.CBRANCH)&&!op.getInput(0).isConstant())need(f.getBody().contains(op.getInput(0).getAddress()),"Callee branch escapes body");
    if(op.getOpcode()==PcodeOp.CALLOTHER){String name=userop(op);need(Set.of("dsp_interrupt_disable","dsp_interrupt_enable").contains(name),"Unproved callee userop "+name);userops.add(name);}
   }
   evidence.append(ins.getAddress()).append('/').append(HexFormat.of().formatHex(ins.getBytes())).append('/').append(pcode(ins)).append('\n');
  }
  visiting.remove(f.getEntryPoint());need(count>0&&returns>0,"No modeled returning path in callee");
  Map<String,Object> proof=new LinkedHashMap<>();proof.put("entry",f.getEntryPoint().toString());proof.put("ABI",f.getCallingConventionName());proof.put("native_instructions",count);proof.put("returns",returns);proof.put("native_pcode_sha256",sha(evidence.toString()));proof.put("userops",userops);proof.put("nested_callees",children);proof.put("contract","Every modeled returning path preserves "+target.getName()+"; interrupt/hardware interference excluded");return proof;
 }
 private Map<String,Object> prove(Loop loop)throws Exception{
  PcodeOp[] startOps=loop.start().getPcode();long dest=loop.expected().getAddressableWordOffset();int definitions=0;
  for(PcodeOp op:startOps)if(overlap(op.getOutput(),loop.target())){
   need(isreg(op.getOutput(),loop.target()),"Partial loop target write");definitions++;
   need(op.getOpcode()==PcodeOp.INT_DIV&&op.getNumInputs()==2&&constant(op.getInput(1),3)&&op.getInput(0).isConstant(),"Unexpected DO target value expression");
   need(op.getInput(0).getOffset()==loop.expected().getOffset()&&op.getInput(0).getOffset()/3==dest,"DO PM byte/word conversion differs from expected target");
  }
  need(definitions==1,"No unique constant reaching definition in native DO");
  Register cntr=currentProgram.getRegister("CNTR");PcodeOp[] tail=loop.end().getPcode();int k=loop.branchIndex();need(k>=3,"Missing CE condition suffix");
  PcodeOp dec=tail[k-3],equal=tail[k-2],branch=tail[k-1];
  need(dec.getOpcode()==PcodeOp.INT_SUB&&isreg(dec.getOutput(),cntr)&&isreg(dec.getInput(0),cntr)&&constant(dec.getInput(1),1),"Missing native CE decrement");
  need(equal.getOpcode()==PcodeOp.INT_EQUAL&&isreg(equal.getInput(0),cntr)&&constant(equal.getInput(1),0),"Missing zero test");
  need(branch.getOpcode()==PcodeOp.CBRANCH&&constant(branch.getInput(0),2)&&same(branch.getInput(1),equal.getOutput()),"Exit branch does not skip exactly the backedge");
  int count=0;List<Map<String,Object>> calls=new ArrayList<>();Set<String> userops=new TreeSet<>();StringBuilder signature=new StringBuilder();
  for(Address a=loop.expected();a.compareTo(loop.end().getAddress())<=0;a=a.add(3)){
   monitor.checkCancelled();Instruction body=currentProgram.getListing().getInstructionAt(a);need(body!=null&&body.getLength()==3,"Native loop gap "+a);count++;
   Function owner=currentProgram.getFunctionManager().getFunctionContaining(a);need(owner!=null&&owner.getEntryPoint().equals(loop.owner().getEntryPoint()),"Loop instruction belongs to a different function");
   var references=currentProgram.getReferenceManager().getReferencesTo(a);
   while(references.hasNext()){
    var ref=references.next();if(ref.getReferenceType().isFlow())need(ref.getFromAddress().compareTo(loop.start().getAddress())>=0&&ref.getFromAddress().compareTo(loop.end().getAddress())<=0,"Known entry bypasses defining DO "+ref);
   }
   if(body.getFlowType().isCall()){
    Address[] flows=body.getFlows();need(flows.length==1,"Unresolved call inside loop");
    Map<String,Object> entry=new LinkedHashMap<>();entry.put("site",a.toString());entry.put("proof",calleeProof(currentProgram.getFunctionManager().getFunctionAt(flows[0]),loop.target(),new HashSet<>(),0));calls.add(entry);
   }
   for(PcodeOp op:body.getPcode()){
    if(a.equals(loop.end().getAddress())&&op.getOpcode()==PcodeOp.BRANCHIND)break; // exit-only restoration follows this op
    need(!overlap(op.getOutput(),loop.target()),"Reaching target definition clobbered at "+a);
    if(op.getOpcode()==PcodeOp.STORE){var space=currentProgram.getAddressFactory().getAddressSpace((int)op.getInput(0).getOffset());need(space!=null&&!space.isRegisterSpace(),"Potential alias to loop register");}
    if(op.getOpcode()==PcodeOp.CALLOTHER){String name=userop(op);need(!FORBIDDEN_USEROPS.contains(name),"Opaque stack mutation "+name);userops.add(name);}
   }
   signature.append(a).append('/').append(HexFormat.of().formatHex(body.getBytes())).append('/').append(pcode(body)).append('\n');
  }
  // Static invariant: constant DO definition + absence of any register write
  // in all body instructions/returning callees implies equality at every CE.
  // Execute the unmodified DO and the unmodified control suffix as independent
  // PC/PM-unit and taken/exit checks; these are not full audio-body executions.
  int cases=0;for(int countValue:new int[]{0,1,2,0x8000,0xffff}){executeSuffix(loop,countValue,false);cases++;}
  executeSuffix(loop,2,true); // negative control: a corrupted target must be observed
  Map<String,Object> proof=new LinkedHashMap<>();proof.put("do",loop.start().getAddress().toString());proof.put("end",loop.end().getAddress().toString());proof.put("owner",loop.owner().getEntryPoint().toString());proof.put("target",loop.expected().toString());proof.put("target_register",loop.target().getName());proof.put("status","CONFIRMED_STATIC_MODEL");proof.put("body_instructions",count);proof.put("start_pcode",pcode(loop.start()));proof.put("body_pcode_sha256",sha(signature.toString()));proof.put("callee_proofs",calls);proof.put("userops",userops);proof.put("control_execution_cases",cases);proof.put("corrupted_target_negative_control",true);return proof;
 }
 private byte[] be(long value,int size){byte[] b=new byte[size];for(int i=size-1;i>=0;i--){b[i]=(byte)value;value>>>=8;}return b;}
 private void set(PcodeThread<byte[]> thread,String name,long value){Register r=currentProgram.getRegister(name);need(r!=null,"Missing register "+name);thread.getState().setVar(r,be(value,r.getNumBytes()));}
 private long get(PcodeThread<byte[]> thread,String name){Register r=currentProgram.getRegister(name);byte[] b=thread.getState().getVar(r,Reason.INSPECT);long value=0;for(byte x:b)value=(value<<8)|(x&255);return value;}
 private void executeSuffix(Loop loop,int count,boolean corrupt)throws Exception{
  SleighLanguage lang=(SleighLanguage)currentProgram.getLanguage();PcodeEmulator emulator=new PcodeEmulator(lang);PcodeThread<byte[]> thread=emulator.newThread();
  var regs=lang.getAddressFactory().getRegisterSpace();thread.getState().setVar(regs,0L,512,false,new byte[512]);
  set(thread,"DSP_LOOP_START",0x600);set(thread,"DSP_LOOP_START_SHADOW",0x650);set(thread,"DSP_LOOP_COUNT_SHADOW",0x700);
  set(thread,"DSP_STATIC_START_OUTER",0x750);set(thread,"DSP_STATIC_START_INNER",0x800);set(thread,"DSP_STATIC_CNTR_OUTER",0x1234);set(thread,"CNTR",count);
  set(thread,"PC",loop.expected().getAddressableWordOffset());thread.setCounter(loop.expected());
  thread.getExecutor().execute(PcodeProgram.fromInstruction(loop.start()),thread.getUseropLibrary());
  need(get(thread,loop.target().getName())==loop.expected().getAddressableWordOffset(),"Native DO execution gives wrong target");
  if(corrupt)set(thread,loop.target().getName(),loop.expected().getAddressableWordOffset()+1);
  Address next=loop.end().getAddress().add(3);set(thread,"PC",next.getAddressableWordOffset());thread.setCounter(next);
  PcodeProgram whole=PcodeProgram.fromInstruction(loop.end());List<PcodeOp> suffix=Arrays.asList(loop.end().getPcode()).subList(loop.branchIndex()-3,loop.end().getPcode().length);
  var frame=thread.getExecutor().execute(new PcodeProgram(whole,suffix),thread.getUseropLibrary());
  Address expected=(count==1)?next:(corrupt?loop.expected().add(3):loop.expected());
  need(thread.getCounter().equals(expected),"CE execution target mismatch: "+loop.end().getAddress()+" CNTR="+count+" actual="+thread.getCounter()+" expected="+expected);
  need(frame.isBranch()==(count!=1),"CE taken/exit branch condition mismatch");
  if(corrupt)need(!thread.getCounter().equals(loop.expected()),"Negative control failed to reveal a corrupted target");
 }
 public void run()throws Exception{
  String[] args=getScriptArgs();need(args.length==4&&Set.of("audit","persist","readback").contains(args[0]),"mode sourceSHA expectedDO expectedIndirect");
  String root=System.getenv("GHIDRA_MCP_PROJECT_ROOT");need(root!=null&&root.endsWith("/native-branchind-candidate/projects"),"Only isolated local Analyzer");
  need(currentProgram!=null&&currentProgram.getLanguageID().getIdAsString().equals("SunplusSPHEAudioDSP:BE:16:default"),"Wrong ISA");
  need(currentProgram.getExecutableSHA256().equals(args[1]),"Native source identity changed");need(!currentProgram.isChanged(),"Existing unsaved work");
  String original=nativeHash(),functions=functionHash();List<Loop> loops=discover(Integer.parseInt(args[2]),Integer.parseInt(args[3]));List<Map<String,Object>> rows=new ArrayList<>();
  for(Loop loop:loops){monitor.checkCancelled();Map<String,Object> proof=prove(loop);rows.add(proof);println("CE_TARGET_CONFIRMED "+loop.start().getAddress()+"->"+loop.end().getAddress()+" target="+loop.expected()+" register="+loop.target().getName());}
  need(original.equals(nativeHash())&&functions.equals(functionHash())&&!currentProgram.isChanged(),"Read-only proof changed native program");
  Map<String,Object> result=new LinkedHashMap<>();result.put("status","CONFIRMED_STATIC_MODEL");result.put("program",currentProgram.getName());result.put("source_sha256",args[1]);result.put("initialized_image_sha256",original);result.put("function_identity_sha256",functions);result.put("native_DO",Integer.parseInt(args[2]));result.put("indirect_targets",loops.size());result.put("confirmed",rows.size());result.put("unresolved",0);result.put("control_execution_cases",loops.size()*5);result.put("negative_controls",loops.size());result.put("scope","Active modeled DO-to-CE path; current P-code and validated returning callees; no asynchronous interrupt clobber or self-modifying PM; hardware equivalence NOT_CLAIMED");result.put("loops",rows);
  String json=new Gson().toJson(result);
  if(args[0].equals("persist")){
   int tx=currentProgram.startTransaction("Save verified indirect CE target contracts only");boolean commit=false;
   try{currentProgram.getOptions(GROUP).setString(KEY,json);need(original.equals(nativeHash())&&functions.equals(functionHash()),"Native state changed during evidence write");commit=true;}
   finally{currentProgram.endTransaction(tx,commit);}
  }
  if(args[0].equals("readback"))need(json.equals(currentProgram.getOptions(GROUP).getString(KEY,"")),"Saved CE proof differs from independently recomputed evidence");
  println("CE_TARGET_PROOF_JSON "+json);println("CE_TARGET_PROOF_PASS program="+currentProgram.getName()+" confirmed="+rows.size()+" unresolved=0 raw_BRANCHIND_unchanged=true mode="+args[0]);
 }
}
