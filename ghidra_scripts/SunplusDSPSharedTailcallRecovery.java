//@category Sunplus/Architecture
// Generic, bounded multi-owner native JUMP -> common handler C/CFG recovery.
// No named module, codec address or expected source count is hardcoded.
// audit by default; apply-safe requires an exact native image SHA, an isolated
// saved GZF and global C improvement. Unproven program relations remain UNKNOWN.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import java.security.MessageDigest;
import java.util.*;

public class SunplusDSPSharedTailcallRecovery extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private record Incoming(Instruction instruction,boolean conditional,List<String> predicatePcode) {}
 private record Candidate(Address start,Address end,Function parent,
   List<Incoming> incoming,int owners,int conditional) {}
 private boolean in(Address a,Address first,Address end){return a!=null && a.compareTo(first)>=0 && a.compareTo(end)<=0;}
 private List<String> conditions(Instruction i){
  var output=new ArrayList<String>();
  for(PcodeOp op:i.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)output.add(op.toString());
  return output;
 }
 private Map<Address,List<Instruction>> crossOwnerJumpEntries() throws Exception {
  var grouped=new TreeMap<Address,List<Instruction>>();
  var listing=currentProgram.getListing();var fm=currentProgram.getFunctionManager();
  for(Instruction i:listing.getInstructions(true)){
   monitor.checkCancelled();
   if(!i.getAddress().getAddressSpace().getName().equals("PM") || !i.getFlowType().isJump() ||
      i.getFlowOverride()!=FlowOverride.NONE)continue;
   Function source=fm.getFunctionContaining(i.getAddress());
   if(source==null)continue;
   for(Address target:i.getFlows()){
    if(!target.getAddressSpace().getName().equals("PM"))continue;
    Function owning=fm.getFunctionContaining(target);
    if(owning==null||owning.getEntryPoint().equals(target))continue;
    // Include the current owning function's native jumps as well. Once a
    // cross-owner target is proven, all entrants require the same CFG split.
    grouped.computeIfAbsent(target,key->new ArrayList<>()).add(i);
   }
  }
  return grouped;
 }
 private Candidate analyze(Address start,List<Instruction> inbound)throws Exception{
  var fm=currentProgram.getFunctionManager();var listing=currentProgram.getListing();
  Function parent=fm.getFunctionContaining(start);
  if(parent==null||parent.getEntryPoint().equals(start)||fm.getFunctionAt(start)!=null)return null;
  var owners=new HashSet<Address>();int conditional=0;
  int foreignOwners=0;
  for(Instruction i:inbound){
   Function owner=fm.getFunctionContaining(i.getAddress());
   if(owner==null||i.getFlowOverride()!=FlowOverride.NONE)return null;
   owners.add(owner.getEntryPoint());
   if(!owner.equals(parent))foreignOwners++;
   if(i.getFlowType().isConditional())conditional++;
  }
  // Multi-owner incoming native flow is the discriminant; other same-function
  // loops/branches are NOT shared error-handler evidence.
  if(inbound.size()<6||owners.size()<3||foreignOwners<3)return null;
  Address end=null;int instructions=0;
  for(int w=0;w<256;w++){
   Address a=start.addNoWrap(w*3L);
   Instruction i=listing.getInstructionAt(a);
   if(i==null||i.getLength()!=3||fm.getFunctionContaining(a)!=parent)break;
   instructions++;
   // Only an unconditional *exit* to an already owned instruction qualifies
   // as a natural handler boundary. A self-loop is not an exit.
   if(i.getFlowType().isJump()&&!i.getFlowType().isConditional()){
    Address[] edges=i.getFlows();
    if(edges.length!=1)return null;
    Address dst=edges[0];
    if(dst.equals(a))continue;
    if(dst.compareTo(start)<0){
     if(fm.getFunctionContaining(dst)!=parent)return null;
     end=i.getAddress();break;
    }
   }
  }
  if(end==null||instructions<4||instructions>256)return null;
  // The handler must have a unique entry from other code, with all interior
  // native branch destinations reached within the handler itself.
  for(Instruction i:listing.getInstructions(true)){
   if(i.getAddress().getAddressSpace().getName().equals("PM") && !in(i.getAddress(),start,end)){
    if(!i.getFlowType().isJump()){
     for(Address dest:i.getFlows())if(dest.equals(start))return null; // native CALL to same handler
    }
    for(Address dest:i.getFlows())if(in(dest,start,end)&&!dest.equals(start))return null;
   }
   if(in(i.getAddress(),start,end)&&i.getFlowType().isJump()){
    for(Address dest:i.getFlows())if(!in(dest,start,end) && !(i.getAddress().equals(end) &&
       fm.getFunctionContaining(dest)==parent))return null;
   }
  }
  var evidence=new ArrayList<Incoming>();
  for(Instruction i:inbound){
   if(i.getFlows().length!=1||!i.getFlows()[0].equals(start))return null;
   List<String> predicate=conditions(i);
   boolean cond=i.getFlowType().isConditional();
   if((cond && predicate.isEmpty())||(!cond && !predicate.isEmpty()))return null;
   evidence.add(new Incoming(i,cond,predicate));
  }
  return new Candidate(start,end,parent,evidence,owners.size(),conditional);
 }
 private String cpp(DecompInterface d,Function f)throws Exception {
  var r=d.decompileFunction(f,30,monitor);
  if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
   throw new IllegalStateException("Native C failed "+f.getEntryPoint()+": "+r.getErrorMessage());
  return r.getDecompiledFunction().getC();
 }
 private int warnings(String s){return s.split("WARNING:",-1).length-1;}
 private byte[] nativeDigest()throws Exception{
  var hash=MessageDigest.getInstance("SHA-256");var buffer=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address at=b.getStart();long left=b.getSize();
   while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,buffer.length);
    if(currentProgram.getMemory().getBytes(at,buffer,0,n)!=n)throw new IllegalStateException("Memory changed at "+at);
    hash.update(buffer,0,n);at=at.add(n);left-=n;
   }
  }
  return hash.digest();
 }
 private Map<Address,String> immutableFunctionIdentity(){
  var ids=new TreeMap<Address,String>();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   ids.put(f.getEntryPoint(),f.getName());
  return ids;
 }
 public void run()throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Wrong Sunplus native processor model");
  String[] a=getScriptArgs();String mode=a.length==0?"audit":a[0];
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit / apply-safe");
  if(mode.equals("apply-safe") && (a.length!=2||!a[1].equals(currentProgram.getExecutableSHA256())))
   throw new IllegalArgumentException("Exact executable SHA required before annotation");
  if(currentProgram.getName().equals("srvdsp.bin"))throw new IllegalStateException("Resident bootstrap wrapper not in this scope");
  List<Candidate> eligible=new ArrayList<>();
  var graph=crossOwnerJumpEntries();
  for(var group:graph.entrySet()){
   Candidate proof=analyze(group.getKey(),group.getValue());
   if(proof!=null){eligible.add(proof);println("DSP_SHARED_TAILCALL_PROVEN handler="+proof.start()+
    " end="+proof.end()+" parent="+proof.parent().getEntryPoint()+
    " incoming="+proof.incoming().size()+" source_owners="+proof.owners()+
    " conditional="+proof.conditional()+" analysis=LIKELY");}
  }
  println("DSP_SHARED_TAILCALL_PLAN program="+currentProgram.getName()+
    " native_functions="+currentProgram.getFunctionManager().getFunctionCount()+
    " candidate_crossowner_jump_targets="+graph.size()+" eligible="+eligible.size()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_SHARED_TAILCALL_AUDIT_PASS");return;}
  if(eligible.isEmpty()){println("DSP_SHARED_TAILCALL_APPLY_PASS changed=0");return;}
  if(eligible.size()!=1)throw new IllegalStateException("Ambiguous multi-owner shared handlers; resolve independently");
  Candidate target=eligible.get(0);
  var fm=currentProgram.getFunctionManager();
  DecompInterface before=new DecompInterface();
  if(!before.openProgram(currentProgram))throw new IllegalStateException("Native C backend unavailable");
  Map<Function,Integer> prior=new LinkedHashMap<>();
  try{for(Function f:fm.getFunctions(true))if(!f.isExternal())prior.put(f,warnings(cpp(before,f)));}finally{before.dispose();}
  int priorAffected=(int)prior.values().stream().filter(x->x>0).count();
  if(priorAffected==0){println("DSP_SHARED_TAILCALL_APPLY_PASS changed=0 baseline_C_clean");return;}
  byte[] bytes=nativeDigest();Map<Address,String> identities=immutableFunctionIdentity();
  int tx=currentProgram.startTransaction("Native multi-owner shared error-handler tailcall recovery");
  boolean commit=false;
  try{
   AddressSet handlerBody=new AddressSet(target.start(),target.end().add(2));
   AddressSet remainder=new AddressSet(target.parent().getBody());
   if(!remainder.contains(handlerBody))throw new IllegalStateException("Handler body not owned by parent");
   remainder.delete(handlerBody);
   target.parent().setBody(remainder);
   String name=String.format("FUN_PM_%04x",target.start().getAddressableWordOffset());
   Function handler=fm.createFunction(name,target.start(),handlerBody,SourceType.ANALYSIS);
   if(handler==null||handler.getBody().getNumAddresses()!=handlerBody.getNumAddresses())
    throw new IllegalStateException("Cannot define isolated native handler");
   handler.setComment("LIKELY: native multi-owner shared exception/control handler. Split is supported by native multi-owner direct JUMP entries and natural outgoing native JUMP. Behavior/stack hardware effects UNKNOWN.");
   for(Incoming site:target.incoming()){
    Instruction i=site.instruction();
    if(i.getFlowOverride()!=FlowOverride.NONE)throw new IllegalStateException("Another flow override owns "+i.getAddress());
    i.setFlowOverride(FlowOverride.CALL_RETURN);
    if(i.getFlowOverride()!=FlowOverride.CALL_RETURN||!conditions(i).equals(site.predicatePcode()))
     throw new IllegalStateException("Native conditional predicate lost at "+i.getAddress());
   }
   if(!Arrays.equals(bytes,nativeDigest()))throw new IllegalStateException("Executable bytes modified");
   Map<Address,String> actual=immutableFunctionIdentity();
   if(actual.size()!=identities.size()+1||!name.equals(actual.remove(target.start()))||!actual.equals(identities))
    throw new IllegalStateException("Unrelated native function identities changed");
   DecompInterface after=new DecompInterface();
   if(!after.openProgram(currentProgram))throw new IllegalStateException("Post-C backend unavailable");
   int improved=0,regressed=0,owners=0,warningLines=0;
   try{
    for(var row:prior.entrySet()){
     monitor.checkCancelled();String output=cpp(after,row.getKey());int n=warnings(output);
     if(n>row.getValue()||output.contains("halt_baddata()"))regressed++;
     if(n<row.getValue()){improved++;println("DSP_SHARED_TAILCALL_C_DIFF owner="+row.getKey().getEntryPoint()+
          " warnings="+row.getValue()+"->"+n);}
     if(n>0)owners++;warningLines+=n;
    }
    String output=cpp(after,handler);int handlerWarnings=warnings(output);
    if(output.contains("halt_baddata()"))throw new IllegalStateException("New native handler not C-covered");
    if(handlerWarnings>0)owners++;warningLines+=handlerWarnings;
    println("DSP_SHARED_TAILCALL_C_SUMMARY native_total="+(prior.size()+1)+
     " warning_owners="+priorAffected+"->"+owners+
     " existing_improved="+improved+" regressions="+regressed+
     " handler_warnings="+handlerWarnings+" warning_lines="+warningLines);
    if(regressed!=0||improved==0||owners>=priorAffected)
     throw new IllegalStateException("No scoped semantically valid full C improvement");
   }finally{after.dispose();}
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);
   println("DSP_SHARED_TAILCALL_TRANSACTION="+(commit?"COMMITTED_ISOLATED":"ROLLED_BACK"));}
  if(!commit)throw new IllegalStateException("Full shared-tailcall repair was rolled back");
  println("DSP_SHARED_TAILCALL_APPLY_PASS native_added=1 new_tailcalls="+target.incoming().size());
 }
}
