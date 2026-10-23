//@category Sunplus/Architecture
// Native-evidenced opt-in call ABI for calls inside single-level DO/CE.
// No module, PM offset, function-name assumptions. Read-only audit is default.
// Mutation requires apply-safe and an explicit native-image SHA, on an isolated copy.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import java.util.*;
import java.util.regex.*;
import java.security.MessageDigest;

public class SunplusLoopSafeCallModel extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private static final String ABI="__sunplus_loop_safe";
 private static final Pattern DO=Pattern.compile("^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
 private record Loop(int begin,int end,Function owner) {}
 private Address pm(int w){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",w));}
 private int addrWord(Address a){return (int)a.getAddressableWordOffset();}
 private boolean writesHardwareLoop(Instruction i){
  Set<Address> protectedRegs=new HashSet<>();
  for(String n:new String[]{"CNTR","DSP_LOOP_START","DSP_LOOP_START_SHADOW","DSP_LOOP_START_SHADOW2",
     "DSP_LOOP_START_SHADOW3","DSP_LOOP_COUNT_SHADOW","DSP_LOOP_DEPTH","DSP_COUNT_DEPTH",
     "DSP_COUNT0","DSP_COUNT1","DSP_COUNT2","DSP_COUNT3",
     "DSP_STATIC_START_OUTER","DSP_STATIC_START_INNER","DSP_STATIC_CNTR_OUTER"}){
   var r=currentProgram.getRegister(n);if(r!=null)protectedRegs.add(r.getAddress());
  }
  for(PcodeOp op:i.getPcode()){
   Varnode out=op.getOutput();
   if(out!=null&&out.isRegister()&&protectedRegs.contains(out.getAddress()))return true;
  }
  return false;
 }
 private boolean nativeSafe(Function f,Set<Address> seen,int depth)throws Exception{
  if(f==null||f.isExternal()||f.isThunk()||depth>5||seen.size()>24||!seen.add(f.getEntryPoint()))return false;
  int n=0;
  for(Instruction i:currentProgram.getListing().getInstructions(f.getBody(),true)){
   monitor.checkCancelled();if(++n>5000)return false;
   String op=i.toString().trim().toUpperCase(Locale.ROOT);
   if(writesHardwareLoop(i)||op.startsWith("DO ")||op.startsWith("RTI")||
      op.contains("POP LOOP")||op.contains("PUSH LOOP")||op.contains("POP PC"))return false;
   if(i.getFlowType().isComputed()&&!i.getFlowType().isTerminal())return false;
   if(i.getFlowType().isCall()){
    Address[] flows=i.getFlows();
    if(flows.length!=1||!nativeSafe(currentProgram.getFunctionManager().getFunctionAt(flows[0]),seen,depth+1))return false;
   }
  }
  seen.remove(f.getEntryPoint());return n>0;
 }
 private boolean singleLoop(Loop l,List<Loop> all)throws Exception{
  if(l.owner()==null||l.begin()>=l.end()||l.end()-l.begin()>0x300)return false;
  var first=currentProgram.getListing().getInstructionAt(pm(l.begin()));
  var end=currentProgram.getListing().getInstructionAt(pm(l.end()));
  if(first==null||end==null||first.getFallThrough()==null||
      !first.getFallThrough().equals(pm(l.begin()+1))||
      !l.owner().getBody().contains(first.getAddress())||!l.owner().getBody().contains(end.getAddress()))return false;
  for(Loop other:all){
   if(other==l||other.owner()!=l.owner())continue;
   if(other.begin()<=l.end()&&l.begin()<=other.end())return false;
  }
  int cb=0,ind=0,direct=0;
  var nativeReg=currentProgram.getRegister("DSP_LOOP_START");if(nativeReg==null)return false;
  for(PcodeOp op:end.getPcode()){
   if(op.getOpcode()==PcodeOp.CBRANCH)cb++;
   if(op.getOpcode()==PcodeOp.BRANCH)direct++;
   if(op.getOpcode()==PcodeOp.BRANCHIND){
    ind++;
    if(op.getNumInputs()!=1||!op.getInput(0).getAddress().equals(nativeReg.getAddress()))return false;
   }
  }
  if(cb!=1||ind!=1||direct!=0)return false;
  for(int w=l.begin()+1;w<l.end();w++){
   var i=currentProgram.getListing().getInstructionAt(pm(w));
   if(i==null||i.getLength()!=3||i.toString().trim().toUpperCase(Locale.ROOT).startsWith("DO ")||
      writesHardwareLoop(i))return false;
  }
  return true;
 }
 private String decompile(DecompInterface d,Function f)throws Exception{
  var res=d.decompileFunction(f,25,monitor);
  if(!res.decompileCompleted()||res.getDecompiledFunction()==null)
   throw new IllegalStateException("C generator failed for "+f.getEntryPoint()+": "+res.getErrorMessage());
  return res.getDecompiledFunction().getC();
 }
 private int warnings(String c){return c.split("WARNING:",-1).length-1;}
 private byte[] nativeHash()throws Exception{
  var d=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address a=b.getStart();long left=b.getSize();
   while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,buffer.length);
    if(currentProgram.getMemory().getBytes(a,buffer,0,n)!=n)throw new IllegalStateException("Memory read failed");
    d.update(buffer,0,n);a=a.add(n);left-=n;
   }
  }
  return d.digest();
 }
 private String inventory(){
  var s=new StringBuilder();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   s.append(f.getEntryPoint()).append('/').append(f.getName()).append('/').append(f.getBody()).append('\n');
  return s.toString();
 }
 public void run()throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong processor language");
  String[] args=getScriptArgs();String mode=args.length>0?args[0]:"audit";
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit or apply-safe");
  if(mode.equals("apply-safe")&&(args.length!=2||!currentProgram.getExecutableSHA256().equals(args[1])))
   throw new IllegalArgumentException("Mutation requires exact caller-supplied native SHA");
  if(currentProgram.getCompilerSpec().getCallingConvention(ABI)==null)
   throw new IllegalStateException("Special compiler prototype is not installed");
  if(currentProgram.getName().equals("srvdsp.bin"))throw new IllegalStateException("Resident DSP wrapper uses separate contract");
  List<Loop> loops=new ArrayList<>();
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   if(!i.getAddress().getAddressSpace().getName().equals("PM"))continue;
   Matcher m=DO.matcher(i.toString().trim());
   if(m.matches())loops.add(new Loop(addrWord(i.getAddress()),Integer.parseInt(m.group(1),16),currentProgram.getFunctionManager().getFunctionContaining(i.getAddress())));
  }
  DecompInterface current=new DecompInterface();
  if(!current.openProgram(currentProgram))throw new IllegalStateException("Decompiler unavailable");
  Map<Function,String> before=new LinkedHashMap<>();
  Map<Function,Integer> beforeWarn=new LinkedHashMap<>();
  try{
   for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
    if(f.isExternal())continue;
    String c=decompile(current,f);before.put(f,c);beforeWarn.put(f,warnings(c));
   }
  }finally{current.dispose();}
  Map<Function,Set<Function>> safeProviders=new LinkedHashMap<>();
  int eligibleLoops=0;
  for(Loop loop:loops){
   if(!singleLoop(loop,loops)||beforeWarn.getOrDefault(loop.owner(),0)==0)continue;
   eligibleLoops++;
   for(int word=loop.begin()+1;word<loop.end();word++){
    var i=currentProgram.getListing().getInstructionAt(pm(word));
    if(!i.getFlowType().isCall())continue;
    Address[] flows=i.getFlows();
    if(flows.length!=1)continue;
    Function provider=currentProgram.getFunctionManager().getFunctionAt(flows[0]);
    if(nativeSafe(provider,new HashSet<>(),0))safeProviders.computeIfAbsent(provider,f->new LinkedHashSet<>()).add(loop.owner());
   }
  }
  int warningOwners=(int)beforeWarn.values().stream().filter(n->n>0).count();
  for(var row:safeProviders.entrySet())
   println("DSP_SAFE_ABI_PROOF provider="+row.getKey().getEntryPoint()+" callers="+
      row.getValue().stream().map(f->f.getEntryPoint().toString()).toList()+
      " native_proven_no_hardware_loop_write=true current_convention="+row.getKey().getCallingConventionName());
  println("DSP_SAFE_ABI_PLAN program="+currentProgram.getName()+" native_functions="+before.size()+
     " C_warning_owners="+warningOwners+" eligible_loops="+eligibleLoops+
     " safe_native_callees="+safeProviders.size()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_SAFE_ABI_AUDIT_PASS");return;}
  if(safeProviders.isEmpty()){println("DSP_SAFE_ABI_APPLY_PASS changed=0");return;}
  byte[] raw=nativeHash();String originalInventory=inventory();
  int tx=currentProgram.startTransaction("Scoped native loop-preserving DSP call convention");
  boolean commit=false;int improved=0;
  try{
   for(Function callee:safeProviders.keySet()){
    monitor.checkCancelled();
    if(callee.getCallingConventionName().equals(ABI))continue;
    callee.setCallingConvention(ABI);
   }
   if(!Arrays.equals(nativeHash(),raw)||!inventory().equals(originalInventory))
    throw new IllegalStateException("Native executable or function inventory altered");
   DecompInterface after=new DecompInterface();
   if(!after.openProgram(currentProgram))throw new IllegalStateException("Post ABI C unavailable");
   try{
    for(var e:before.entrySet()){
     monitor.checkCancelled();Function function=e.getKey();
     String updated=decompile(after,function);int w0=beforeWarn.get(function),w1=warnings(updated);
     if(w1>w0||updated.contains("halt_baddata()"))
      throw new IllegalStateException("C regression at "+function.getEntryPoint()+" warnings="+w0+"->"+w1);
     if(w1<w0){
      improved++;println("DSP_SAFE_ABI_C_DIFF owner="+function.getEntryPoint()+
        " warnings="+w0+"->"+w1);
     }
    }
   }finally{after.dispose();}
   if(improved==0)throw new IllegalStateException("No observed C warnings improved");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("DSP_SAFE_ABI_TRANSACTION="+(commit?"COMMITTED":"ROLLED_BACK"));}
  if(!commit)throw new IllegalStateException("Native safe callee ABI transaction rolled back");
  println("DSP_SAFE_ABI_APPLY_PASS native_callees="+safeProviders.size()+" C_owners_improved="+improved);
 }
}
