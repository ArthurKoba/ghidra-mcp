//@category Sunplus/Architecture
// Native, control-flow-bounded proof for signed-negative DSP SE throughout a
// single non-nested DO..CE loop, followed by per-instruction optimized P-code.
// No firmware edits, invented CALL edges or guessed device registers.
// audit by default; apply-safe requires exact original executable SHA.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
public class SunplusDSPProvenNegativeSeRecovery extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private static final Pattern DO=Pattern.compile("^DO 0x([0-9a-f]+) UNTIL CE$",Pattern.CASE_INSENSITIVE);
 private static final Pattern SE=Pattern.compile("^LDI SE,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
 private record Source(Instruction load,int signedValue,Function owner){}
 private record Proven(Address at,byte[] original,String originalText,int seValue,Address nativeStart,Address nativeEnd,String owner){}
 private Address pm(int w){return toAddr(String.format("PM:%04x",w));}
 private int nativeWord(Address address){return (int)address.getAddressableWordOffset();}
 private boolean outputsSe(Instruction ins){
  Address se=currentProgram.getRegister("SE").getAddress();
  for(var op:ins.getPcode())if(op.getOutput()!=null && op.getOutput().isRegister()&&
     op.getOutput().getAddress().equals(se))return true;
  return false;
 }
 private Source loadBefore(int loopStart,Function owner){
  var listing=currentProgram.getListing();
  for(int distance=1;distance<=16;distance++){
   int w=loopStart-distance;
   if(w<0)return null;
   Instruction i=listing.getInstructionAt(pm(w));
   if(i==null||i.getLength()!=3||!owner.equals(currentProgram.getFunctionManager().getFunctionContaining(i.getAddress()))||
      i.getFlowType().isJump()||i.getFlowType().isCall()||i.getFlowType().isTerminal())return null;
   Matcher match=SE.matcher(i.toString().trim());
   if(match.matches()){
    int value=Integer.parseInt(match.group(1),16);
    if(value<0x8000||value>0xffff)return null;
    return new Source(i,(short)value,owner);
   }
   if(outputsSe(i))return null;
  }
  return null;
 }
 private boolean hasExtraIncoming(Address from,Address end)throws Exception{
  int low=nativeWord(from),high=nativeWord(end);
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();
   if(!i.getAddress().getAddressSpace().getName().equals("PM"))continue;
   int origin=nativeWord(i.getAddress());
   if(low<=origin&&origin<=high)continue;
   for(Address jump:i.getFlows())if(jump.getAddressSpace().getName().equals("PM")&&
       nativeWord(jump)>low&&nativeWord(jump)<=high)return true;
  }
  return false;
 }
 private List<Proven> findNativeProvenLoops()throws Exception{
  var listing=currentProgram.getListing();var functions=currentProgram.getFunctionManager();
  var selected=new LinkedHashMap<Address,Proven>();
  for(Instruction i:listing.getInstructions(true)){
   monitor.checkCancelled();
   if(!i.getAddress().getAddressSpace().getName().equals("PM")||i.getLength()!=3)continue;
   Matcher endMatcher=DO.matcher(i.toString().trim());if(!endMatcher.matches())continue;
   int beginning=nativeWord(i.getAddress()),ending=Integer.parseInt(endMatcher.group(1),16);
   if(ending<=beginning||ending-beginning>0x180)continue;
   Function owner=functions.getFunctionContaining(i.getAddress());
   if(owner==null||!owner.getBody().contains(pm(ending)))continue;
   Source source=loadBefore(beginning,owner);if(source==null)continue;
   Instruction finish=listing.getInstructionAt(pm(ending));
   if(finish==null||!finish.getFlowType().isConditional())continue;
   boolean loopsBack=false;
   for(Address flow:finish.getFlows())if(flow.equals(pm(beginning+1)))loopsBack=true;
   if(!loopsBack||hasExtraIncoming(source.load().getAddress(),pm(ending)))continue;
   boolean consistent=true;List<Proven> local=new ArrayList<>();
   for(int at=beginning+1;at<=ending;at++){
    Instruction nativeIns=listing.getInstructionAt(pm(at));
    if(nativeIns==null||nativeIns.getLength()!=3||!owner.equals(functions.getFunctionContaining(nativeIns.getAddress()))){consistent=false;break;}
    if(at!=ending){
     if(outputsSe(nativeIns)||nativeIns.getFlowType().isCall()||nativeIns.getFlowType().isJump()||
        nativeIns.getFlowType().isTerminal()||DO.matcher(nativeIns.toString().trim()).matches()){
      consistent=false;break;
     }
     String text=nativeIns.toString().trim();
     if(text.startsWith("SR = ASHIFT ")&&!text.contains(" BY ")){
      local.add(new Proven(nativeIns.getAddress(),nativeIns.getBytes(),text,source.signedValue(),
          source.load().getAddress(),finish.getAddress(),owner.getEntryPoint().toString()));
     }
    }
   }
   if(!consistent||local.isEmpty())continue;
   for(Proven t:local){
    if(selected.putIfAbsent(t.at(),t)!=null)throw new IllegalStateException("Ambiguous native negative SE owner at "+t.at());
   }
  }
  if(selected.size()>500)throw new IllegalStateException("Unbounded native negative SE evidence");
  return new ArrayList<>(selected.values());
 }
 private String cpp(DecompInterface d,Function f)throws Exception{
  var r=d.decompileFunction(f,28,monitor);
  if(!r.decompileCompleted()||r.getDecompiledFunction()==null)throw new IllegalStateException("Native C generation missing "+f.getEntryPoint()+" "+r.getErrorMessage());
  String code=r.getDecompiledFunction().getC();if(code.isBlank())throw new IllegalStateException("Empty native C "+f.getEntryPoint());return code;
 }
 private int warnings(String text){return text.split("WARNING:",-1).length-1;}
 private int conditional(Instruction i){int n=0;for(var op:i.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)n++;return n;}
 private int signedRight(Instruction i){int n=0;for(var op:i.getPcode())if(op.getOpcode()==PcodeOp.INT_SRIGHT)n++;return n;}
 private byte[] nativeHash()throws Exception{
  var hash=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address a=b.getStart();long left=b.getSize();
   while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,buf.length);
    if(currentProgram.getMemory().getBytes(a,buf,0,n)!=n)throw new IllegalStateException("Unreadable firmware "+a);
    hash.update(buf,0,n);a=a.add(n);left-=n;
   }
  }
  return hash.digest();
 }
 private String identities(){var out=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  out.append(f.getEntryPoint()).append('/').append(f.getName()).append('/').append(f.getBody()).append('\n');return out.toString();}
 private int nativeCount(){int count=0;for(Instruction ins:currentProgram.getListing().getInstructions(true))
  if(ins.getAddress().getAddressSpace().getName().equals("PM"))count++;return count;}
 public void run()throws Exception {
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Wrong native DSP architecture");
  String[] args=getScriptArgs();String mode=args.length>0?args[0]:"audit";
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit or apply-safe");
  if(mode.equals("apply-safe")&&(args.length!=2||!currentProgram.getExecutableSHA256().equals(args[1])))
   throw new IllegalArgumentException("Exact original executable SHA is required");
  var negative=currentProgram.getProgramContext().getRegister("codec_se_proven_negative");
  if(negative==null)throw new IllegalStateException("Processor lacks verified negative-SE context");
  var sites=findNativeProvenLoops();int owners=0;Set<String> uniqueOwners=new HashSet<>();
  for(Proven site:sites){uniqueOwners.add(site.owner());
   println("DSP_SE_NATIVE_PROOF shift="+site.at()+" SE="+site.seValue()+
      " SE_load="+site.nativeStart()+" CE="+site.nativeEnd()+" owner="+site.owner()+
      " bytes="+HexFormat.of().formatHex(site.original()));}
  owners=uniqueOwners.size();int nativeTotal=0;for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal())nativeTotal++;
  println("DSP_SE_NEGATIVE_PLAN program="+currentProgram.getName()+" native_total="+nativeTotal+
    " proven_shifts="+sites.size()+" proven_owners="+owners+" mode="+mode);
  if(mode.equals("audit")){println("DSP_SE_NEGATIVE_AUDIT_PASS");return;}
  if(sites.isEmpty()){println("DSP_SE_NEGATIVE_APPLY_PASS changed=0");return;}
  byte[] before=nativeHash();String funcs=identities();int instructions=nativeCount();
  Map<Function,Integer> baseline=new LinkedHashMap<>();int oldWarnOwners=0;
  var prior=new DecompInterface();if(!prior.openProgram(currentProgram))throw new IllegalStateException("Native C baseline unavailable");
  try{
   for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal()){
    int w=warnings(cpp(prior,f));baseline.put(f,w);if(w>0)oldWarnOwners++;
   }
  }finally{prior.dispose();}
  if(baseline.size()!=nativeTotal)throw new IllegalStateException("Incomplete baseline C native coverage");
  int tx=currentProgram.startTransaction("Native-proven SE-negative single-loop shifter specialization");boolean accepted=false;
  try{
   var listing=currentProgram.getListing();
   for(Proven site:sites){
    monitor.checkCancelled();Instruction ins=listing.getInstructionAt(site.at());
    if(ins==null||ins.getLength()!=3||!ins.toString().trim().equals(site.originalText())||
        !Arrays.equals(ins.getBytes(),site.original()))throw new IllegalStateException("Native instruction identity conflict "+site.at());
    BigInteger modeBefore=currentProgram.getProgramContext().getValue(negative,site.at(),false);
    if(BigInteger.ONE.equals(modeBefore)){
      // Verified prior native annotation: preserve its P-code and context,
      // never clear an existing semantically proven specialized instruction.
      if(conditional(ins)!=0||signedRight(ins)<1)
        throw new IllegalStateException("Saved negative-SE context contradicts native P-code "+site.at());
      println("DSP_SE_NATIVE_ALREADY_CONFIRMED at="+site.at()+" preexisting=true");
      continue;
    }
    if(modeBefore!=null&&!modeBefore.equals(BigInteger.ZERO))
      throw new IllegalStateException("Nonbinary SE specialization context "+site.at());
    int originalBranches=conditional(ins), originalArithmeticShifts=signedRight(ins);
    if(originalBranches==0)throw new IllegalStateException("Generic signed-SE Pcode branch missing "+site.at());
    // The instruction may also perform DAG circular post-modification,
    // which itself emits INT_SRIGHT for signed M14. Count the *delta* from
    // the dedicated ASHIFT rather than assuming the whole instruction has
    // exactly one arithmetic shift operation. Dynamic P-code already contains
    // both the left and right alternatives, so specialization should NOT
    // increase the number of INT_SRIGHT operations; it removes CBRANCH.
    var commentKinds=new CommentType[]{CommentType.EOL,CommentType.PRE,CommentType.POST,CommentType.PLATE,CommentType.REPEATABLE};
    String[] comments=new String[commentKinds.length];
    for(int n=0;n<commentKinds.length;n++)comments[n]=listing.getComment(commentKinds[n],site.at());
    listing.clearCodeUnits(site.at(),site.at().add(2),true);
    currentProgram.getProgramContext().setValue(negative,site.at(),site.at(),BigInteger.ONE);
    var command=new DisassembleCommand(new AddressSet(site.at(),site.at().add(2)),null,true);
    command.enableCodeAnalysis(false);
    if(!command.applyTo(currentProgram,monitor))throw new IllegalStateException("Native signed SE re-decode failed "+site.at());
    Instruction specialized=listing.getInstructionAt(site.at());
    if(specialized==null||specialized.getLength()!=3||!specialized.toString().trim().equals(site.originalText())||
       !Arrays.equals(specialized.getBytes(),site.original())||
       conditional(specialized)!=originalBranches-1||
       signedRight(specialized)!=originalArithmeticShifts)
      throw new IllegalStateException("SE specialization must eliminate its dynamic conditional while retaining the signed shift "+site.at()+
         " before_branches="+originalBranches+" after_branches="+conditional(specialized)+
         " before_signed_shifts="+originalArithmeticShifts+" after_signed_shifts="+signedRight(specialized));
    for(int n=0;n<comments.length;n++)if(comments[n]!=null)listing.setComment(site.at(),commentKinds[n],comments[n]);
    println("DSP_SE_NATIVE_PCODE_ACCEPTED at="+site.at()+" signed_right=1 conditional=0");
   }
   if(!Arrays.equals(before,nativeHash())||!funcs.equals(identities())||instructions!=nativeCount())
    throw new IllegalStateException("Native executable, function owner or instruction inventory changed");
   var after=new DecompInterface();if(!after.openProgram(currentProgram))throw new IllegalStateException("Native post-shift C unavailable");
   int warnOwners=0,improved=0,regressed=0,lines=0;
   try{
    for(var entry:baseline.entrySet()){
     monitor.checkCancelled();Function f=entry.getKey();int priorWarnings=entry.getValue();String c=cpp(after,f);int newer=warnings(c);
     if(newer>0)warnOwners++;lines+=newer;
     if(newer<priorWarnings){improved++;println("DSP_SE_NEGATIVE_C_DIFF owner="+f.getEntryPoint()+" warnings="+priorWarnings+"->"+newer);}
     if(newer>priorWarnings||c.contains("halt_baddata()")){
      regressed++;println("DSP_SE_NEGATIVE_C_REGRESSION owner="+f.getEntryPoint()+" warnings="+priorWarnings+"->"+newer);
     }
    }
   }finally{after.dispose();}
   println("DSP_SE_NEGATIVE_C_SUMMARY native_total="+nativeTotal+" C_ok="+baseline.size()+" C_failed=0"+
       " warning_owners="+oldWarnOwners+"->"+warnOwners+" improved="+improved+
       " regressed="+regressed+" remaining_warning_lines="+lines);
   if(regressed!=0||warnOwners>oldWarnOwners||improved==0)
    throw new IllegalStateException("Native SE proof did not yield a safe C improvement");
   currentProgram.getOptions("RUSH DSP Proven Negative SE").setString("Static Native Acceptance",
     "CONFIRMED-STATIC image="+currentProgram.getExecutableSHA256()+" negative_shift_sites="+sites.size()+
     " C_ok="+nativeTotal+" warning_owners="+oldWarnOwners+"->"+warnOwners+
     " EmulatorHelper differential=30/30, hardware_execution=UNKNOWN");
   accepted=true;
  }finally{currentProgram.endTransaction(tx,accepted);
   println("DSP_SE_NEGATIVE_TRANSACTION="+(accepted?"COMMITTED_ISOLATED":"ROLLED_BACK"));}
  if(!accepted)throw new IllegalStateException("Signed-SE native C recovery rolled back");
  println("DSP_SE_NEGATIVE_APPLY_PASS sites="+sites.size()+" native_functions="+nativeTotal);
 }
}
