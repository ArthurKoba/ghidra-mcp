//@category Sunplus/Architecture
// Recover stale saved CNTR register-move P-code only when a verified two-level
// DSP DO/CE nested-loop context selects the active counter shadow frame.
// Pure native semantics: no fabricated hardware executions or function names.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import java.security.MessageDigest;
import java.math.BigInteger;
import java.util.*;
public class SunplusDSPNestedCounterRefresh extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private record One(Address at,byte[] raw,String displayed,String oldPcode,String freshPcode,String owner) {}
 private String ops(Instruction i){StringBuilder b=new StringBuilder();for(PcodeOp p:i.getPcode())b.append(p).append(';');return b.toString();}
 private PseudoInstruction parsed(Instruction old)throws Exception {
  Language language=currentProgram.getLanguage();
  var bytes=new ByteMemBufferImpl(old.getAddress(),old.getBytes(),true);
  var context=new ProcessorContextImpl(language);
  for(Register reg:language.getContextRegisters()){
   BigInteger v=currentProgram.getProgramContext().getValue(reg,old.getAddress(),false);
   if(v!=null)context.setValue(reg,v);
  }
  return new PseudoInstruction(currentProgram.getAddressFactory(),old.getAddress(),language.parse(bytes,context,false),bytes,context);
 }
 private boolean copy(PcodeOp op,Address output,Address input){
  return op.getOpcode()==PcodeOp.COPY&&op.getOutput()!=null&&
    op.getOutput().isRegister()&&op.getOutput().getAddress().equals(output)&&
    op.getNumInputs()==1&&op.getInput(0).isRegister()&&op.getInput(0).getAddress().equals(input);
 }
 private List<One> stale()throws Exception{
  Register cntr=currentProgram.getRegister("CNTR"),shadow=currentProgram.getRegister("DSP_STATIC_CNTR_OUTER"),
    mode=currentProgram.getRegister("codec_ce_nested_mode"),depth=currentProgram.getRegister("codec_ce_static_depth");
  if(cntr==null||shadow==null||mode==null||depth==null)throw new IllegalStateException("Static native loop state unavailable");
  List<One> result=new ArrayList<>();
  for(Instruction ins:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();if(!ins.getAddress().getAddressSpace().getName().equals("PM")||ins.getLength()!=3)continue;
   if(!ins.toString().trim().startsWith("CNTR = "))continue;
   var newCode=parsed(ins);
   if(!ins.toString().equals(newCode.toString())||!Arrays.equals(ins.getBytes(),newCode.getBytes()))
    throw new IllegalStateException("Native register move rendering/bytes changed "+ins.getAddress());
   String before=ops(ins),after=ops(newCode);if(before.equals(after))continue;
   var old=ins.getPcode();var updated=newCode.getPcode();
   if(old.length!=1||updated.length!=2||!copy(updated[0],shadow.getAddress(),cntr.getAddress())||
      old[0].getOpcode()!=PcodeOp.COPY||updated[1].getOpcode()!=PcodeOp.COPY||
      !old[0].getOutput().getAddress().equals(cntr.getAddress())||
      !updated[1].getOutput().getAddress().equals(cntr.getAddress())||
      !old[0].getInput(0).equals(updated[1].getInput(0)))
    throw new IllegalStateException("Contradictory native nested counter Pcode transformation "+ins.getAddress());
   BigInteger nested=currentProgram.getProgramContext().getValue(mode,ins.getAddress(),false);
   BigInteger staticDepth=currentProgram.getProgramContext().getValue(depth,ins.getAddress(),false);
   if(nested==null||!nested.equals(BigInteger.ONE)||staticDepth==null||!staticDepth.equals(BigInteger.valueOf(2)))
    throw new IllegalStateException("Counter move has no proven nested depth2 Ghidra context "+ins.getAddress());
   var owner=currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
   if(owner==null||owner.isExternal())throw new IllegalStateException("Unknown native counter register-move function");
   result.add(new One(ins.getAddress(),ins.getBytes(),ins.toString(),before,after,owner.getEntryPoint().toString()));
  }
  if(result.size()>100)throw new IllegalStateException("Unbounded nested counter stale semantics count");
  return result;
 }
 private byte[] sourceHash()throws Exception{
  var digest=MessageDigest.getInstance("SHA-256");byte[] b=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   Address a=block.getStart();long left=block.getSize();
   while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,b.length);
    if(currentProgram.getMemory().getBytes(a,b,0,n)!=n)throw new IllegalStateException("Source unreadable "+a);
    digest.update(b,0,n);a=a.add(n);left-=n;
   }
  }
  return digest.digest();
 }
 private String owners(){var b=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  b.append(f.getEntryPoint()).append('/').append(f.getBody()).append('/').append(f.getName()).append('\n');return b.toString();}
 private int instructions(){int n=0;for(Instruction i:currentProgram.getListing().getInstructions(true))if(i.getAddress().getAddressSpace().getName().equals("PM"))n++;return n;}
 private String c(DecompInterface decompiler,Function f)throws Exception{
  var r=decompiler.decompileFunction(f,27,monitor);if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
   throw new IllegalStateException("Native C failed "+f.getEntryPoint()+" "+r.getErrorMessage());
  String source=r.getDecompiledFunction().getC();if(source.isBlank())throw new IllegalStateException("Empty native C "+f.getEntryPoint());return source;
 }
 private int warnings(String s){return s.split("WARNING:",-1).length-1;}
 public void run()throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong native Sunplus processor");
  String[] args=getScriptArgs();String mode=args.length==0?"audit":args[0];
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("Use audit / apply-safe");
  if(mode.equals("apply-safe")&&(args.length!=2||!currentProgram.getExecutableSHA256().equals(args[1])))
   throw new IllegalArgumentException("Exact original executable SHA required");
  int version=currentProgram.getDomainFile().getVersion();boolean dirty=currentProgram.isChanged();
  var unresolved=stale();Set<String> affected=new TreeSet<>();
  for(One o:unresolved){affected.add(o.owner());println("DSP_NESTED_CNTR_PROOF native="+o.at()+
    " opcode="+HexFormat.of().formatHex(o.raw())+" owner="+o.owner()+" mode=1 depth=2");}
  int nativeCount=0;for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal())nativeCount++;
  println("DSP_NESTED_CNTR_PLAN program="+currentProgram.getName()+" native_total="+nativeCount+
    " stale_native_counter_moves="+unresolved.size()+" affected_functions="+affected.size()+" mode="+mode);
  if(mode.equals("audit")){
   if(currentProgram.isChanged()!=dirty||currentProgram.getDomainFile().getVersion()!=version)
    throw new IllegalStateException("Native source changed during static audit");
   println("DSP_NESTED_CNTR_AUDIT_PASS");return;
  }
  if(unresolved.isEmpty()){println("DSP_NESTED_CNTR_APPLY_PASS changed=0");return;}
  byte[] nativeBytes=sourceHash();String identity=owners();int codeCount=instructions();
  Map<Function,Integer> before=new LinkedHashMap<>();int warned=0;
  DecompInterface decompiler=new DecompInterface();if(!decompiler.openProgram(currentProgram))throw new IllegalStateException("Native C backend failed");
  try{for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal()){
    int count=warnings(c(decompiler,f));before.put(f,count);if(count>0)warned++;
  }}finally{decompiler.dispose();}
  if(before.size()!=nativeCount)throw new IllegalStateException("Full native C baseline missing");
  int tx=currentProgram.startTransaction("Scoped ADSP nested DO/CE shadow-counter P-code refresh");boolean accepted=false;
  try{
   var listing=currentProgram.getListing();
   for(One change:unresolved){
    monitor.checkCancelled();Instruction old=listing.getInstructionAt(change.at());
    if(old==null||!change.displayed().equals(old.toString())||!change.oldPcode().equals(ops(old)))
     throw new IllegalStateException("Saved counter evidence changed "+change.at());
    // Preserve the proven per-instruction codec_ce_nested_mode/depth context.
    // clearCodeUnits(...,true) would erase those context values and silently
    // select the generic Type17 move instead of the native 2-level frame.
    listing.clearCodeUnits(change.at(),change.at().add(2),false);
    Register flag=currentProgram.getRegister("codec_ce_nested_mode");
    Register depth=currentProgram.getRegister("codec_ce_static_depth");
    if(!BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(flag,change.at(),false))||
       !BigInteger.valueOf(2).equals(currentProgram.getProgramContext().getValue(depth,change.at(),false)))
      throw new IllegalStateException("Scoped nested loop context unexpectedly lost "+change.at());
    var cmd=new DisassembleCommand(new AddressSet(change.at(),change.at().add(2)),null,true);cmd.enableCodeAnalysis(false);
    if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Native counter decoder failed "+change.at());
    Instruction after=listing.getInstructionAt(change.at());
    if(after==null||!Arrays.equals(after.getBytes(),change.raw())||
       !after.toString().equals(change.displayed())||!change.freshPcode().equals(ops(after)))
     throw new IllegalStateException("Native shadow-counter instruction not preserved "+change.at());
   }
   if(!Arrays.equals(nativeBytes,sourceHash())||!identity.equals(owners())||codeCount!=instructions())
    throw new IllegalStateException("Native executable, function identity or instruction inventory changed");
   var checked=new DecompInterface();if(!checked.openProgram(currentProgram))throw new IllegalStateException("Post-C engine failed");
   int remaining=0,improved=0,regressed=0,lines=0;
   try{
    for(var e:before.entrySet()){
     monitor.checkCancelled();String after=c(checked,e.getKey());int now=warnings(after);lines+=now;
     if(now>0)remaining++;
     if(now<e.getValue()){improved++;println("DSP_NESTED_CNTR_C_DIFF owner="+e.getKey().getEntryPoint()+" warnings="+e.getValue()+"->"+now);}
     if(now>e.getValue()||after.contains("halt_baddata()")){
      regressed++;println("DSP_NESTED_CNTR_REGRESSION owner="+e.getKey().getEntryPoint()+" warnings="+e.getValue()+"->"+now);
     }
    }
   }finally{checked.dispose();}
   println("DSP_NESTED_CNTR_C_SUMMARY native_total="+nativeCount+" C_ok="+before.size()+" C_failed=0"+
     " warning_owners="+warned+"->"+remaining+" improved="+improved+" regressed="+regressed+
     " remaining_warning_lines="+lines);
   if(regressed!=0||remaining>warned)throw new IllegalStateException("No-regression native C acceptance failed");
   currentProgram.getOptions("RUSH DSP Nested Counter Pcode").setString("Acceptance",
     "CONFIRMED-STATIC native="+currentProgram.getExecutableSHA256()+" restored_moves="+unresolved.size()+
     " mode=1 depth=2 C_ok="+nativeCount+" warning_owners="+warned+"->"+remaining+
     " hardware_execution=UNKNOWN");
   accepted=true;
  }finally{currentProgram.endTransaction(tx,accepted);
   println("DSP_NESTED_CNTR_TRANSACTION="+(accepted?"COMMITTED_ISOLATED":"ROLLED_BACK"));}
  if(!accepted)throw new IllegalStateException("Native counter P-code refresh rolled back");
  println("DSP_NESTED_CNTR_APPLY_PASS corrected="+unresolved.size()+" native_total="+nativeCount);
 }
}
