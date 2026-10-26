//@category Sunplus/Architecture
// Scoped correction of DSP callee ABI when original native machine instructions
// prove hardware CNTR/DO registers untouched. Audit by default; apply requires
// exact source SHA and native address. No hand-written C or invented edges.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Register;
import java.security.MessageDigest;
import java.util.*;
public class SunplusDSPReturnLoopAbiRecovery extends GhidraScript {
 private static final String ABI="__sunplus_loop_safe";
 private byte[] bytes()throws Exception{
  MessageDigest h=MessageDigest.getInstance("SHA-256");byte[] block=new byte[8192];
  for(MemoryBlock m:currentProgram.getMemory().getBlocks())if(m.isInitialized()){
   Address addr=m.getStart();long left=m.getSize();while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,block.length);
    if(currentProgram.getMemory().getBytes(addr,block,0,n)!=n)throw new IllegalStateException("Source byte gap");
    h.update(block,0,n);left-=n;addr=addr.add(n);
   }
  }return h.digest();}
 private String identity(){StringBuilder x=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  x.append(f.getEntryPoint()).append('|').append(f.getName()).append('|').append(f.getBody()).append('|').append(f.hasNoReturn()).append('\n');return x.toString();}
 private String code(DecompInterface d,Function f)throws Exception{
  var r=d.decompileFunction(f,30,monitor);if(!r.decompileCompleted()||r.getDecompiledFunction()==null||r.getDecompiledFunction().getC().isBlank())
   throw new IllegalStateException("Native C failure "+f.getEntryPoint());return r.getDecompiledFunction().getC();}
 private int warns(String s){return s.split("WARNING:",-1).length-1;}
 private int loops(String s){return s.split("do \\{",-1).length-1;}
 private boolean preservesLoop(Function f) throws Exception {
  if(f.isExternal()||f.isThunk()||f.hasNoReturn())return false;
  var protectedRegs=new ArrayList<Register>();
  for(String name:new String[]{"CNTR","DSP_LOOP_START","DSP_LOOP_START_SHADOW","DSP_LOOP_START_SHADOW2","DSP_LOOP_START_SHADOW3",
    "DSP_LOOP_COUNT_SHADOW","DSP_LOOP_DEPTH","DSP_COUNT_DEPTH","DSP_COUNT0","DSP_COUNT1","DSP_COUNT2","DSP_COUNT3",
    "DSP_STATIC_START_OUTER","DSP_STATIC_START_INNER","DSP_STATIC_CNTR_OUTER"}){
   Register r=currentProgram.getRegister(name);if(r!=null)protectedRegs.add(r);
  }
  int n=0,returns=0;
  for(Instruction i:currentProgram.getListing().getInstructions(f.getBody(),true)){
   monitor.checkCancelled();if(++n>5000)return false;
   String text=i.toString().trim().toUpperCase(Locale.ROOT);
   if(text.startsWith("DO ")||text.startsWith("RTI")||text.contains("POP LOOP")||
      text.contains("PUSH LOOP")||text.contains("POP CNTR")||text.startsWith("LDI CNTR,")||
      text.startsWith("DMREAD CNTR,")||i.getFlowType().isCall()||
      (i.getFlowType().isComputed()&&!i.getFlowType().isTerminal()))return false;
   for(PcodeOp op:i.getPcode()){
    if(op.getOpcode()==PcodeOp.RETURN)returns++;
    Varnode out=op.getOutput();if(out==null||!out.isRegister())continue;
    for(Register reg:protectedRegs){
     if(!reg.getAddress().getAddressSpace().equals(out.getAddress().getAddressSpace()))continue;
     long a=reg.getAddress().getOffset(),b=out.getOffset();
     if(a<b+out.getSize()&&b<a+reg.getMinimumByteSize())return false;
    }
   }
  }
  return n>0&&returns>0;
 }
 public void run()throws Exception{
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong ISA");
  String[] args=getScriptArgs();String mode=args.length>0?args[0]:"audit";
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit|apply-safe PM:word [SHA]");
  if(args.length<(mode.equals("audit")?2:3)||args.length>3)throw new IllegalArgumentException("Exact provider PM address mandatory");
  if(mode.equals("apply-safe")&&!args[2].equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong image SHA");
  Address target=toAddr(args[1]);if(target==null||!"PM".equals(target.getAddressSpace().getName()))throw new IllegalArgumentException("Wrong provider address");
  Function callee=currentProgram.getFunctionManager().getFunctionAt(target);
  if(callee==null||!preservesLoop(callee))throw new IllegalStateException("Native provider is not proven loop safe");
  if(currentProgram.getCompilerSpec().getCallingConvention(ABI)==null)throw new IllegalStateException("Processor ABI missing");
  Map<Function,String> baseline=new LinkedHashMap<>();DecompInterface before=new DecompInterface();
  if(!before.openProgram(currentProgram))throw new IllegalStateException("C backend unavailable");
  try{for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal())baseline.put(f,code(before,f));}finally{before.dispose();}
  Map<Function,String> impacted=new LinkedHashMap<>();
  for(var e:baseline.entrySet())if(e.getValue().contains("WARNING: Could not recover jumptable")&&
    e.getValue().contains(callee.getName()+"();"))impacted.put(e.getKey(),e.getValue());
  println("DSP_CALL_ABI_PLAN program="+currentProgram.getName()+" provider="+target+" nativeLoopWrites=0 nativeRTS=1 C_ok="+baseline.size()+
   " affected_warning_functions="+impacted.size()+" priorConvention="+callee.getCallingConventionName()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_CALL_ABI_AUDIT_PASS");return;}
  if(impacted.isEmpty())throw new IllegalStateException("No native C caller evidence for ABI change");
  if(ABI.equals(callee.getCallingConventionName()))throw new IllegalStateException("Provider already has loop safe ABI");
  byte[] raw=bytes();String functions=identity();int initialWarnings=baseline.values().stream().mapToInt(this::warns).sum();
  int tx=currentProgram.startTransaction("Native-proof DSP loop-preserving caller ABI");boolean commit=false;
  try{
   callee.setCallingConvention(ABI);
   if(!Arrays.equals(raw,bytes())||!functions.equals(identity()))throw new IllegalStateException("Native source/functions changed");
   DecompInterface d=new DecompInterface();if(!d.openProgram(currentProgram))throw new IllegalStateException("Post C unavailable");
   int afterWarn=0,improved=0,regressed=0;try{
    for(var e:baseline.entrySet()){
     monitor.checkCancelled();String now=code(d,e.getKey());int w0=warns(e.getValue()),w1=warns(now);
     afterWarn+=w1;if(w1>w0||now.contains("halt_baddata"))regressed++;
     if(w1<w0){improved++;println("DSP_CALL_ABI_C_DIFF owner="+e.getKey().getEntryPoint()+" warnings="+w0+"->"+w1+
      " C_loops="+loops(e.getValue())+"->"+loops(now));}
     if(impacted.containsKey(e.getKey())&&(w1>=w0||loops(now)<loops(e.getValue())+1||now.contains("__ghidra_unresolved_indirect_jump")))
      throw new IllegalStateException("Native loop not actually recovered for "+e.getKey().getEntryPoint());
    }
   }finally{d.dispose();}
   println("DSP_CALL_ABI_C_GATE native="+baseline.size()+" warning_lines="+initialWarnings+"->"+afterWarn+
     " improved="+improved+" regressed="+regressed);
   if(regressed!=0||afterWarn>=initialWarnings||improved==0)throw new IllegalStateException("No proven C improvement");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("DSP_CALL_ABI_TRANSACTION="+(commit?"COMMIT":"ROLLBACK"));}
  if(!commit)throw new IllegalStateException("No verified ABI recovery");
  println("DSP_CALL_ABI_APPLY_PASS provider="+target);
 }
}
