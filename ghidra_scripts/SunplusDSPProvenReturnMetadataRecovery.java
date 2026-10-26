//@category Sunplus/Architecture
// Correct false Ghidra no-return annotations from native-reachable RETURN
// paths of CALL providers. No invented flow edges or firmware-specific sites.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.mem.MemoryBlock;
import java.security.MessageDigest;
import java.util.*;
public class SunplusDSPProvenReturnMetadataRecovery extends GhidraScript {
 private boolean reachesReturn(Function fn){
  Listing listing=currentProgram.getListing();Set<Address> seen=new HashSet<>();Deque<Address> queue=new ArrayDeque<>();
  queue.add(fn.getEntryPoint());int scanned=0;
  while(!queue.isEmpty()&&scanned<2000){
   Address a=queue.remove();if(!seen.add(a)||!fn.getBody().contains(a))continue;
   Instruction ins=listing.getInstructionAt(a);if(ins==null)continue;scanned++;
   if(ins.toString().equals("RTS")||ins.toString().endsWith(" RTS"))return true;
   for(PcodeOp op:ins.getPcode())if(op.getOpcode()==PcodeOp.RETURN)return true;
   // Calls return to the next local instruction unless flow metadata itself
   // proves a nonreturning branch. The return in THIS function is independently
   // required; visiting a callee entry never counts as a local return.
   Address fall=ins.getFallThrough();if(fall!=null&&fn.getBody().contains(fall))queue.add(fall);
   if(ins.getFlowType().isJump())for(Address target:ins.getFlows())
     if(fn.getBody().contains(target))queue.add(target);
  }return false;
 }
 private boolean loopPreservingNativeProvider(Function f){
  // Native ABI proof: the callee does not manipulate hardware DO/CNTR state,
  // call through an unknown function, or use computed flow. The native RTS
  // reachability is independently established by reachesReturn().
  Set<Address> protectedRegisters=new HashSet<>();
  for(String name:new String[]{"CNTR","DSP_LOOP_START","DSP_LOOP_START_SHADOW",
      "DSP_LOOP_COUNT_SHADOW","DSP_LOOP_DEPTH","DSP_STATIC_CNTR_OUTER",
      "DSP_STATIC_START_INNER","DSP_STATIC_START_OUTER"}){
    var reg=currentProgram.getRegister(name);if(reg!=null)protectedRegisters.add(reg.getAddress());
  }
  int n=0;
  for(Instruction i:currentProgram.getListing().getInstructions(f.getBody(),true)){
    if(++n>4000)return false;
    if(i.toString().trim().startsWith("DO ")||i.getFlowType().isCall()||
       (i.getFlowType().isComputed()&&!i.getFlowType().isTerminal()))return false;
    for(PcodeOp op:i.getPcode()){
      var output=op.getOutput();
      if(output!=null&&output.isRegister()&&protectedRegisters.contains(output.getAddress()))return false;
    }
  }return n>0;
 }
 private String c(DecompInterface d,Function f)throws Exception{
  var r=d.decompileFunction(f,28,monitor);
  if(!r.decompileCompleted()||r.getDecompiledFunction()==null||r.getDecompiledFunction().getC().isBlank())
   throw new IllegalStateException("Native C failed "+f.getEntryPoint()+" "+r.getErrorMessage());
  return r.getDecompiledFunction().getC();}
 private int warningCount(String s){return s.split("WARNING:",-1).length-1;}
 private byte[] bytes()throws Exception{
  MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address at=b.getStart();long n=b.getSize();while(n>0){int z=(int)Math.min(n,buf.length);monitor.checkCancelled();
    if(currentProgram.getMemory().getBytes(at,buf,0,z)!=z)throw new IllegalStateException("Native image read failed");
    d.update(buf,0,z);at=at.add(z);n-=z;
   }
  }return d.digest();}
 private String functionBodies(){StringBuilder s=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  s.append(f.getEntryPoint()).append('|').append(f.getName()).append('|').append(f.getBody()).append('\n');return s.toString();}
 public void run()throws Exception{
  if(currentProgram==null||!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("DSP image required");
  String[] args=getScriptArgs();String mode=args.length==0?"audit":args[0];
  boolean loopAbi=mode.equals("apply-safe-loop-abi");
  if(!mode.equals("audit")&&!mode.equals("apply-safe")&&!loopAbi)
   throw new IllegalArgumentException("audit|apply-safe|apply-safe-loop-abi sha");
  if(!mode.equals("audit")&&(args.length!=2||!currentProgram.getExecutableSHA256().equals(args[1])))
   throw new IllegalArgumentException("Exact original DSP executable SHA required");
  var fm=currentProgram.getFunctionManager();Map<Function,String> baseline=new LinkedHashMap<>();
  DecompInterface d=new DecompInterface();if(!d.openProgram(currentProgram))throw new IllegalStateException("C unavailable");
  try{for(Function f:fm.getFunctions(true))if(!f.isExternal())baseline.put(f,c(d,f));}finally{d.dispose();}
  Map<Function,Set<Function>> targets=new LinkedHashMap<>();
  for(var row:baseline.entrySet()){
   Function caller=row.getKey();if(!row.getValue().contains("WARNING: Subroutine does not return"))continue;
   for(Instruction ins:currentProgram.getListing().getInstructions(caller.getBody(),true))if(ins.getFlowType().isCall()){
    for(Address to:ins.getFlows()){
     Function callee=fm.getFunctionAt(to);
     if(callee!=null&&!callee.isExternal()&&callee.hasNoReturn()&&reachesReturn(callee))
      targets.computeIfAbsent(callee,k->new LinkedHashSet<>()).add(caller);
    }
   }
  }
  for(var t:targets.entrySet())println("DSP_NATIVE_RETURN_PROOF callee="+t.getKey().getEntryPoint()+
    " native_RTS_reachable=true currently_noReturn="+t.getKey().hasNoReturn()+
    " callers="+t.getValue().stream().map(f->f.getEntryPoint().toString()).toList());
  println("DSP_RETURN_PLAN program="+currentProgram.getName()+" C_ok="+baseline.size()+
    " incorrect_noReturn_providers="+targets.size()+" affected_callers="+
    targets.values().stream().flatMap(Collection::stream).distinct().count()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_RETURN_AUDIT_PASS");return;}
  if(targets.isEmpty()){println("DSP_RETURN_APPLY_PASS providers=0");return;}
  if(loopAbi){
    if(currentProgram.getCompilerSpec().getCallingConvention("__sunplus_loop_safe")==null)
      throw new IllegalStateException("Processor lacks loop-preserving DSP calling convention");
    for(Function f:targets.keySet()){
      if(!loopPreservingNativeProvider(f))
        throw new IllegalStateException("Callee may mutate hardware-loop state: "+f.getEntryPoint());
      println("DSP_RETURN_ABI_PROOF callee="+f.getEntryPoint()+
        " no_HardwareDO_CNTR_mutation=true convention="+f.getCallingConventionName()+
        " proposed=__sunplus_loop_safe");
    }
  }
  byte[] source=bytes();String bodies=functionBodies();int initialWarn=baseline.values().stream().mapToInt(this::warningCount).sum();
  int tx=currentProgram.startTransaction("Native reachable RTS disproves no-return DSP function attribute");boolean commit=false;
  try{
   for(Function provider:targets.keySet()){
    if(!provider.hasNoReturn()||!reachesReturn(provider))throw new IllegalStateException("Invalid return evidence "+provider.getEntryPoint());
    provider.setNoReturn(false);
    if(loopAbi)provider.setCallingConvention("__sunplus_loop_safe");
   }
   if(!Arrays.equals(source,bytes())||!bodies.equals(functionBodies()))throw new IllegalStateException("Native source or function bodies mutated");
   DecompInterface verify=new DecompInterface();if(!verify.openProgram(currentProgram))throw new IllegalStateException("Post C unavailable");
   int afterWarnings=0,regressions=0,improved=0;try{
    for(var row:baseline.entrySet()){
     monitor.checkCancelled();String after=c(verify,row.getKey());int w0=warningCount(row.getValue()),w1=warningCount(after);
     afterWarnings+=w1;
     if(w1>w0||after.contains("halt_baddata")){
      regressions++;
      println("DSP_RETURN_REGRESSION owner="+row.getKey().getEntryPoint()+
         " warnings="+w0+"->"+w1+" original_C="+row.getValue().length()+" next_C="+after.length());
      int shown=0;for(String line:after.split("\n"))if(line.contains("WARNING:")&&shown++<8)
        println("DSP_RETURN_WARNING_DETAIL owner="+row.getKey().getEntryPoint()+" "+line.trim());
     }
     if(w1<w0){improved++;println("DSP_RETURN_C_DIFF owner="+row.getKey().getEntryPoint()+
       " warnings="+w0+"->"+w1+" C_chars="+row.getValue().length()+"->"+after.length());}
    }
   }finally{verify.dispose();}
   println("DSP_RETURN_C_GATE native="+baseline.size()+" warning_lines="+initialWarn+"->"+afterWarnings+
     " improved_owners="+improved+" regressions="+regressions);
   if(regressions!=0||afterWarnings>=initialWarn||improved==0)throw new IllegalStateException("No proven no-return C warning reduction");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("DSP_RETURN_TRANSACTION="+(commit?"COMMIT":"ROLLBACK"));}
  if(!commit)throw new IllegalStateException("Return metadata recovery not accepted");
  println("DSP_RETURN_APPLY_PASS providers="+targets.size());
 }
}
