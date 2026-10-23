//@category Sunplus/Architecture
// Re-decode native shift-immediate instructions with stale saved SLEIGH Pcode.
// The original PM24 code bytes and all function identities MUST remain intact.
// audit by default; apply-safe requires an exact native program SHA. Never
// mutate the canonical Analyzer program during local architecture development.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class SunplusDSPStaleShifterRecovery extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private static final Pattern SHIFT=Pattern.compile("\\b(LSHIFT|ASHIFT)\\b[^\\n]*\\bBY\\s+-0x([0-9a-f]+)\\s+\\((HI|LO)\\)",Pattern.CASE_INSENSITIVE);
 private record Candidate(Address at,Function owner,String opcode,byte[] bytes,boolean arithmetic,String originalPcode) {}
 private boolean has(PcodeOp[] ops,int opcode){for(PcodeOp op:ops)if(op.getOpcode()==opcode)return true;return false;}
 private String textualPcode(Instruction i){StringBuilder b=new StringBuilder();for(PcodeOp p:i.getPcode())b.append(p.toString()).append(';');return b.toString();}
 private byte[] nativeHash()throws Exception {
  var digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   Address at=block.getStart();long size=block.getSize();
   while(size>0){monitor.checkCancelled();int n=(int)Math.min(buffer.length,size);
    if(currentProgram.getMemory().getBytes(at,buffer,0,n)!=n)throw new IllegalStateException("Source bytes unreadable "+at);
    digest.update(buffer,0,n);at=at.add(n);size-=n;
   }
  }
  return digest.digest();
 }
 private String functionInventory(){
  var result=new StringBuilder();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   result.append(f.getEntryPoint()).append('|').append(f.getName()).append('|').append(f.getBody()).append('|').append(f.isThunk()).append('\n');
  return result.toString();
 }
 private String c(DecompInterface backend,Function f)throws Exception{
  var result=backend.decompileFunction(f,25,monitor);
  if(!result.decompileCompleted()||result.getDecompiledFunction()==null)
   throw new IllegalStateException("C generator failed native "+f.getEntryPoint()+": "+result.getErrorMessage());
  String code=result.getDecompiledFunction().getC();
  if(code.isEmpty())throw new IllegalStateException("Empty native C "+f.getEntryPoint());
  return code;
 }
 private int warnings(String c){return c.split("WARNING:",-1).length-1;}
 private List<Candidate> candidates()throws Exception{
  var found=new ArrayList<Candidate>();
  for(Instruction ins:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();
   if(!ins.getAddress().getAddressSpace().getName().equals("PM")||ins.getLength()!=3)continue;
   String rendered=ins.toString();Matcher m=SHIFT.matcher(rendered);
   if(!m.find())continue;
   byte[] raw=ins.getBytes();int negativeByte=raw[2]&0xff;
   if(negativeByte<=0x80)continue; // excludes -128: signed 8-bit negation overflow
   int encodedShift=256-negativeByte;
   if(!Integer.toHexString(encodedShift).equalsIgnoreCase(m.group(2)))
    throw new IllegalStateException("Contradictory native shift immediate at "+ins.getAddress()+": "+rendered);
   PcodeOp[] ops=ins.getPcode();
   if(!has(ops,PcodeOp.INT_LEFT)||has(ops,PcodeOp.INT_RIGHT)||has(ops,PcodeOp.INT_SRIGHT))continue;
   Function owner=currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
   if(owner==null||owner.isExternal())continue;
   found.add(new Candidate(ins.getAddress(),owner,rendered,raw,m.group(1).equalsIgnoreCase("ASHIFT"),textualPcode(ins)));
  }
  if(found.size()>500)throw new IllegalStateException("Unbounded invalid shift-instruction inventory");
  return found;
 }
 public void run()throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Not Sunplus DSP ISA");
  String[] args=getScriptArgs();String mode=args.length==0?"audit":args[0];
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit or apply-safe");
  if(mode.equals("apply-safe") && (args.length!=2||!args[1].equals(currentProgram.getExecutableSHA256())))
   throw new IllegalArgumentException("Exact native executable SHA required");
  List<Candidate> stale=candidates();
  var functions=currentProgram.getFunctionManager();
  int nativeTotal=0,externalTotal=0;
  for(Function f:functions.getFunctions(true)){if(f.isExternal())externalTotal++;else nativeTotal++;}
  Map<Function,Integer> byOwner=new LinkedHashMap<>();
  for(Candidate one:stale)byOwner.merge(one.owner(),1,Integer::sum);
  for(Candidate one:stale)println("DSP_SHIFT_STALE_PROOF word="+one.at()+" native="+
      HexFormat.of().formatHex(one.bytes())+" owner="+one.owner().getEntryPoint()+
      " opcode="+one.opcode().replace(' ','_'));
  println("DSP_SHIFT_STALE_PLAN program="+currentProgram.getName()+
       " native_total="+nativeTotal+" external="+externalTotal+" malformed_negative_shift="+stale.size()+
       " affected_owner_functions="+byOwner.size()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_SHIFT_STALE_AUDIT_PASS");return;}
  if(stale.isEmpty()){println("DSP_SHIFT_STALE_APPLY_PASS changed=0");return;}
  byte[] sourceHash=nativeHash();String inventory=functionInventory();
  var listing=currentProgram.getListing();int instructionCount=0;
  for(Instruction i:listing.getInstructions(true))if(i.getAddress().getAddressSpace().getName().equals("PM"))instructionCount++;
  DecompInterface old=new DecompInterface();
  if(!old.openProgram(currentProgram))throw new IllegalStateException("C baseline unavailable");
  Map<Function,Integer> baseline=new LinkedHashMap<>();int baselineOwners=0;
  try{
   for(Function f:functions.getFunctions(true))if(!f.isExternal()){
    String code=c(old,f);int n=warnings(code);
    baseline.put(f,n);if(n>0)baselineOwners++;
   }
  }finally{old.dispose();}
  if(baseline.size()!=nativeTotal)throw new IllegalStateException("Incomplete baseline native C coverage");
  int tx=currentProgram.startTransaction("Native stale negative shift P-code re-decode");
  boolean accepted=false;int changed=0;
  try{
   for(Candidate candidate:stale){
    monitor.checkCancelled();Address at=candidate.at();
    var before=listing.getInstructionAt(at);
    if(before==null||!Arrays.equals(before.getBytes(),candidate.bytes())||
      !before.toString().equals(candidate.opcode()))throw new IllegalStateException("Changed native shift before application: "+at);
    listing.clearCodeUnits(at,at.add(2),true);
    var command=new DisassembleCommand(new AddressSet(at,at.add(2)),null,true);
    command.enableCodeAnalysis(false);
    if(!command.applyTo(currentProgram,monitor))throw new IllegalStateException("Native re-decode failed "+at+": "+command.getStatusMsg());
    Instruction newer=listing.getInstructionAt(at);
    if(newer==null||newer.getLength()!=3||!Arrays.equals(candidate.bytes(),newer.getBytes())||
       !newer.toString().equals(candidate.opcode()))throw new IllegalStateException("Native instruction identity altered by re-decode "+at);
    PcodeOp[] code=newer.getPcode();
    if(!has(code,candidate.arithmetic()?PcodeOp.INT_SRIGHT:PcodeOp.INT_RIGHT))
     throw new IllegalStateException("Current SLEIGH doesn't correct negative shift semantics "+at);
    String after=textualPcode(newer);
    if(after.equals(candidate.originalPcode()))throw new IllegalStateException("Stale P-code did not change "+at);
    changed++;
   }
   if(!Arrays.equals(sourceHash,nativeHash())||!inventory.equals(functionInventory()))
    throw new IllegalStateException("Original machine image or native function owners modified");
   int afterInstructions=0;
   for(Instruction i:listing.getInstructions(true))if(i.getAddress().getAddressSpace().getName().equals("PM"))afterInstructions++;
   if(afterInstructions!=instructionCount)throw new IllegalStateException("Instruction inventory changed unexpectedly");
   DecompInterface check=new DecompInterface();
   if(!check.openProgram(currentProgram))throw new IllegalStateException("Post C interface unavailable");
   int newWarnOwners=0,improved=0,regressed=0,lines=0;
   try{
    for(var entry:baseline.entrySet()){
     monitor.checkCancelled();Function f=entry.getKey();int w0=entry.getValue();String output=c(check,f);int w1=warnings(output);
     if(output.contains("halt_baddata()")||w1>w0){regressed++;println("DSP_SHIFT_STALE_REGRESSION owner="+f.getEntryPoint()+" warnings="+w0+"->"+w1);}
     if(w1<w0){improved++;println("DSP_SHIFT_STALE_C_DIFF owner="+f.getEntryPoint()+" warnings="+w0+"->"+w1);}
     if(w1>0)newWarnOwners++;
     lines+=w1;
    }
   }finally{check.dispose();}
   println("DSP_SHIFT_STALE_C_SUMMARY program="+currentProgram.getName()+" native_total="+nativeTotal+
     " C_ok="+baseline.size()+" C_failed=0 warnings_owners="+baselineOwners+"->"+newWarnOwners+
     " fixed_native_words="+changed+" owners_improved="+improved+" regressions="+regressed+
     " remaining_warning_lines="+lines);
   if(regressed!=0||newWarnOwners>baselineOwners||changed!=stale.size())
    throw new IllegalStateException("Stale-shift re-decode failed scoped native C/no-regression acceptance");
   if(baselineOwners>0&&improved==0)
    throw new IllegalStateException("Candidate did not improve any original native C warning owner");
   currentProgram.getOptions("RUSH DSP Stale Shift Recovery").setString("Native Pcode acceptance",
     "CONFIRMED-STATIC image="+currentProgram.getExecutableSHA256()+
     " corrected_negative_shift_words="+changed+" warnings_owners="+baselineOwners+"->"+newWarnOwners+
     " C_ok="+nativeTotal+"; hardware execution UNKNOWN");
   accepted=true;
  }finally{currentProgram.endTransaction(tx,accepted);
    println("DSP_SHIFT_STALE_TRANSACTION="+(accepted?"COMMITTED_ISOLATED":"ROLLED_BACK"));}
  if(!accepted)throw new IllegalStateException("Native stale-shift repair rolled back");
  println("DSP_SHIFT_STALE_APPLY_PASS changed="+changed+" functions="+nativeTotal);
 }
}
