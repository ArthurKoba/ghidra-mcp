//@category Sunplus/Architecture
// Recover depth-two native DSP DO..CE loop pairs from intervals, not PM offsets.
// audit (default); apply-safe only on a backed-up, isolated Ghidra GZF.
// Ambiguous graphs/calls/stack writers are reported, not guessed.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class SunplusDSPNestedLoopRecovery extends GhidraScript {
 private static final Pattern DO=Pattern.compile("^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
 private record L(int start,int end,Function owner){}
 private record P(L outer,L inner,Instruction writer){}
 private Address pm(int x){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",x));}
 private int word(Address x){return (int)(x.getOffset()/x.getAddressSpace().getAddressableUnitSize());}
 private boolean sameOwner(L a,L b){return a.owner()!=null&&b.owner()!=null&&a.owner().getEntryPoint().equals(b.owner().getEntryPoint());}
 private boolean contains(L a,L b){return a.start()<b.start()&&b.end()<a.end();}
 private boolean overlap(L a,L b){return a.start()<=b.end()&&b.start()<=a.end();}
 private boolean countLoad(Instruction i){
  if(i==null)return false;
  String s=i.toString().trim().toUpperCase(Locale.ROOT);
  return s.startsWith("LDI CNTR,")||s.startsWith("DMREAD CNTR,");
 }
 private List<L> discover(){
  List<L> all=new ArrayList<>();
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   if(!"PM".equals(i.getAddress().getAddressSpace().getName()))continue;
   Matcher m=DO.matcher(i.toString().trim());
   if(m.matches())all.add(new L(word(i.getAddress()),Integer.parseInt(m.group(1),16),
       currentProgram.getFunctionManager().getFunctionContaining(i.getAddress())));
  }return all;
 }
 private boolean exact(L l){
  Instruction tail=currentProgram.getListing().getInstructionAt(pm(l.end()));
  if(tail==null)return false;
  boolean cb=false,br=false;
  for(PcodeOp op:tail.getPcode()){
   if(op.getOpcode()==PcodeOp.CBRANCH)cb=true;
   if(op.getOpcode()==PcodeOp.BRANCH&&pm(l.start()+1).equals(op.getInput(0).getAddress()))br=true;
  }return cb&&br;
 }
 private boolean valid(L l){
  if(l.owner()==null||l.start()>=l.end()||l.end()-l.start()>=0x4000)return false;
  Instruction start=currentProgram.getListing().getInstructionAt(pm(l.start()));
  Instruction end=currentProgram.getListing().getInstructionAt(pm(l.end()));
  return start!=null&&end!=null&&end.getLength()==3&&
    pm(l.start()+1).equals(start.getFallThrough())&&
    l.owner().getBody().contains(pm(l.start()+1))&&l.owner().getBody().contains(pm(l.end()));
 }
 // Calls inside DO are only eligible if the target is an entirely
 // resolved finite leaf with a balanced RTS, no further calls, no hardware
 // DO or CNTR writes and no synthetic loop-stack register mutations.
 // This is a bounded static proof; hardware PC-stack depth is still not
 // claimed fully modeled by this two-level analyzer.
 private boolean verifiedLeafCall(Instruction call){
  if(!call.getFlowType().isCall())return false;
  Address[] flows=call.getFlows();
  if(flows.length!=1)return false;
  Function callee=currentProgram.getFunctionManager().getFunctionAt(flows[0]);
  if(callee==null || !callee.getBody().contains(flows[0]))return false;
  int instructionCount=0,returns=0;
  String[] hazardNames={"CNTR","DSP_LOOP_START","DSP_LOOP_START_SHADOW",
    "DSP_STATIC_START_OUTER","DSP_STATIC_START_INNER","DSP_STATIC_CNTR_OUTER",
    "DSP_LOOP_COUNT_SHADOW","DSP_LOOP_DEPTH"};
  Set<Address> hazards=new HashSet<>();
  for(String name:hazardNames){
   Register r=currentProgram.getRegister(name);
   if(r!=null)hazards.add(r.getAddress());
  }
  for(Instruction inst:currentProgram.getListing().getInstructions(callee.getBody(),true)){
   instructionCount++;
   if(instructionCount>1000 || inst.toString().startsWith("DO ") ||
      countLoad(inst) || inst.getFlowType().isCall() ||
      inst.getFlowType().isComputed())return false;
   if(inst.toString().trim().equals("RTS"))returns++;
   for(PcodeOp op:inst.getPcode()){
    if(op.getOutput()!=null && hazards.contains(op.getOutput().getAddress()))
     return false;
   }
  }
  if(instructionCount==0||returns!=1)return false;
  println("DSP_NESTED_PRESERVING_LEAF_CALL at="+call.getAddress()+
    " target="+flows[0]+" body_instructions="+instructionCount+
    " returns="+returns+" stack_upper_bound=3/16");
  return true;
 }
 private String disqualifier(L outer,L inner,List<L> all){
  if(!valid(outer)||!valid(inner)||!sameOwner(outer,inner)||!contains(outer,inner))
    return "invalid native owner or DO intervals";
  for(L l:all)if(l!=outer&&l!=inner&&sameOwner(l,outer)&&overlap(l,outer))
    return "crossing or deeper-than-two hardware DO";
  Instruction writer=currentProgram.getListing().getInstructionAt(pm(inner.start()-1));
  if(!countLoad(writer)||!outer.owner().getBody().contains(writer.getAddress()))
    return "no single counter load before inner DO";
  for(int w=outer.start()+1;w<outer.end();w++){
   Instruction inst=currentProgram.getListing().getInstructionAt(pm(w));
   if(inst==null)return "missing native instruction";
   if(inst.getFlowType().isCall()&&!verifiedLeafCall(inst))
     return "callee may clobber loop/counter state";
   if(countLoad(inst)&&w!=inner.start()-1)return "additional counter writer";
  }
  if(exact(outer)&&exact(inner))return "already modeled";
  if(exact(outer)!=exact(inner))return "inconsistent partial nested context";
  return null;
 }
 private Register context(String n){
  Register r=currentProgram.getProgramContext().getRegister(n);
  if(r==null)throw new IllegalStateException("Missing DSP context "+n);
  return r;
 }
 private void recode(Address at)throws Exception{
  DisassembleCommand cmd=new DisassembleCommand(new AddressSet(at,at.add(2)),null,true);
  cmd.enableCodeAnalysis(false);
  if(!cmd.applyTo(currentProgram,monitor)||currentProgram.getListing().getInstructionAt(at)==null)
    throw new IllegalStateException("Cannot disassemble nested instruction "+at+" "+cmd.getStatusMsg());
 }
 private void mark(Address at,int depth,Register nested,Register level)throws Exception{
  currentProgram.getListing().clearCodeUnits(at,at,true);
  currentProgram.getProgramContext().setValue(nested,at,at,BigInteger.ONE);
  currentProgram.getProgramContext().setValue(level,at,at,BigInteger.valueOf(depth));
  recode(at);
 }
 private void markEnd(L l,int depth,Register nested,Register level,Register ce,Register direct,Register target)throws Exception{
  Address at=pm(l.end());
  currentProgram.getListing().clearCodeUnits(at,at,true);
  currentProgram.getProgramContext().setValue(nested,at,at,BigInteger.ONE);
  currentProgram.getProgramContext().setValue(level,at,at,BigInteger.valueOf(depth));
  currentProgram.getProgramContext().setValue(ce,at,at,BigInteger.ONE);
  currentProgram.getProgramContext().setValue(direct,at,at,BigInteger.ONE);
  currentProgram.getProgramContext().setValue(target,at,at,BigInteger.valueOf(l.start()+1));
  recode(at);
  if(!exact(l))throw new IllegalStateException("Expected nested PM backedge absent "+at);
 }
 private String c(DecompInterface d,Function f)throws Exception{
  DecompileResults x=d.decompileFunction(f,38,monitor);
  if(!x.decompileCompleted()||x.getDecompiledFunction()==null)
    throw new IllegalStateException("C failed "+f.getEntryPoint()+" "+x.getErrorMessage());
  return x.getDecompiledFunction().getC();
 }
 private int n(String s,String p){return s.split(p,-1).length-1;}
 private String inventory(){
  StringBuilder s=new StringBuilder();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
    s.append(f.getEntryPoint()).append(':').append(f.getName()).append(':').append(f.getBody()).append('\n');
  return s.toString();
 }
 private byte[] hash()throws Exception{
  MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
   if(!b.isInitialized())continue;
   Address p=b.getStart();long left=b.getSize();
   while(left>0){
    int take=(int)Math.min(left,buf.length);
    if(currentProgram.getMemory().getBytes(p,buf,0,take)!=take)throw new IllegalStateException("Source read");
    d.update(buf,0,take);p=p.add(take);left-=take;
   }
  }return d.digest();
 }
 public void run() throws Exception{
  if(currentProgram==null||!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
    throw new IllegalStateException("Not Sunplus DSP");
  if("srvdsp.bin".equals(currentProgram.getName()))
    throw new IllegalStateException("Resident wrapper has a different loop contract");
  String[] a=getScriptArgs();String mode=a.length==0?"audit":a[0];
  if(a.length>1||(!mode.equals("audit")&&!mode.equals("apply-safe")))
    throw new IllegalArgumentException("audit or apply-safe");
  List<L> all=discover();LinkedHashSet<P> ready=new LinkedHashSet<>();
  int skip=0,already=0;
  for(L outer:all){
   if(outer.owner()==null)continue;
   List<L> children=new ArrayList<>();
   for(L inner:all)if(sameOwner(inner,outer)&&inner!=outer&&contains(outer,inner))
     children.add(inner);
   if(children.isEmpty())continue;
   if(children.size()!=1){skip++;println("DSP_NESTED_SKIPPED outer="+pm(outer.start())+" reason=depth/crossing");continue;}
   L inner=children.get(0);
   String error=disqualifier(outer,inner,all);
   if(error!=null){
    if(error.equals("already modeled"))already++;else skip++;
    println("DSP_NESTED_SKIPPED outer="+pm(outer.start())+" inner="+pm(inner.start())+" reason="+error);
    continue;
   }
   Instruction writer=currentProgram.getListing().getInstructionAt(pm(inner.start()-1));
   ready.add(new P(outer,inner,writer));
   println("DSP_NESTED_READY owner="+outer.owner().getEntryPoint()+
     " outer="+pm(outer.start())+".."+pm(outer.end())+
     " inner="+pm(inner.start())+".."+pm(inner.end())+
     " saved_counter_at="+writer.getAddress());
  }
  println("DSP_NESTED_PLAN program="+currentProgram.getName()+" loops="+all.size()+
    " eligible_pairs="+ready.size()+" already="+already+" unresolved="+skip+" mode="+mode);
  if(mode.equals("audit")){println("DSP_NESTED_AUDIT_PASS");return;}
  if(ready.isEmpty()){println("DSP_NESTED_APPLY_PASS pairs=0");return;}
  Register nested=context("codec_ce_nested_mode"),level=context("codec_ce_static_depth"),
    ce=context("codec_ce_loop_end"),direct=context("codec_ce_direct_backedge"),
    target=context("codec_ce_direct_start");
  Register saved=currentProgram.getRegister("DSP_STATIC_CNTR_OUTER");
  if(saved==null)throw new IllegalStateException("Missing saved outer CNTR");
  Map<Function,Integer> needed=new LinkedHashMap<>();
  for(P p:ready)needed.merge(p.outer().owner(),2,Integer::sum);
  byte[] old=hash();String oldFns=inventory();
  DecompInterface before=new DecompInterface();
  if(!before.openProgram(currentProgram))throw new IllegalStateException("C unavailable");
  Map<Function,String> prior=new LinkedHashMap<>();
  try{for(Function f:needed.keySet())prior.put(f,c(before,f));}finally{before.dispose();}
  int tx=currentProgram.startTransaction("Generic static depth-two DSP loops");
  boolean commit=false;
  try{
   for(P p:ready){
    monitor.checkCancelled();
    mark(p.writer().getAddress(),2,nested,level);
    Instruction stored=currentProgram.getListing().getInstructionAt(p.writer().getAddress());
    boolean preserves=false;
    for(PcodeOp op:stored.getPcode())if(op.getOutput()!=null&&
      op.getOutput().getAddress().equals(saved.getAddress())&&
      op.getOutput().getSize()==saved.getMinimumByteSize())preserves=true;
    if(!preserves)throw new IllegalStateException("Inner counter load did not save outer counter "+stored.getAddress());
    mark(pm(p.outer().start()),1,nested,level);
    mark(pm(p.inner().start()),2,nested,level);
    markEnd(p.inner(),2,nested,level,ce,direct,target);
    markEnd(p.outer(),1,nested,level,ce,direct,target);
   }
   if(!Arrays.equals(old,hash())||!oldFns.equals(inventory()))
    throw new IllegalStateException("Native bytes/function inventory changed");
   DecompInterface after=new DecompInterface();
   if(!after.openProgram(currentProgram))throw new IllegalStateException("C reinit failed");
   try{
    for(var e:prior.entrySet()){
     String now=c(after,e.getKey());
     int c0=n(e.getValue(),"do \\{"),c1=n(now,"do \\{");
     int w0=n(e.getValue(),"WARNING:"),w1=n(now,"WARNING:");
     println("DSP_NESTED_OWNER_DIFF owner="+e.getKey().getEntryPoint()+
       " expected_new="+needed.get(e.getKey())+" C_do="+c0+"->"+c1+" warnings="+w0+"->"+w1);
     if(c1<c0+needed.get(e.getKey())||w1>w0||now.contains("halt_baddata()"))
      throw new IllegalStateException("Nested loop C/CFG regression "+e.getKey().getEntryPoint());
    }
   }finally{after.dispose();}
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);}
  if(!commit)throw new IllegalStateException("Nested CE transaction rolled back");
  println("DSP_NESTED_APPLY_PASS pairs="+ready.size()+" recovered_ends="+(ready.size()*2));
 }
}
