//@category Sunplus/Architecture
// Restore proven distinct PM CALL target wrongly joined to a foreign function,
// plus one independently bounded native DO/CALL/RTS routine from accepted image.
// Both native functions are created by Ghidra, not handwritten; all C must pass.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
public class SunplusDSPProvenBoundaryCompletion extends GhidraScript {
 private record Region(Address start,Address finish,int n){}
 private Address pm(String word){return currentProgram.getAddressFactory().getAddress("PM:"+word);}
 private int pcode(Instruction i,int op){int n=0;for(var p:i.getPcode())if(p.getOpcode()==op)n++;return n;}
 private byte[] firmware()throws Exception{
  MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address a=b.getStart();long n=b.getSize();while(n>0){monitor.checkCancelled();int len=(int)Math.min(n,buf.length);
    if(currentProgram.getMemory().getBytes(a,buf,0,len)!=len)throw new IllegalStateException("Native image unreadable");
    d.update(buf,0,len);a=a.add(len);n-=len;
   }
  }return d.digest();
 }
 private String identity(Function f){return f.getName()+"|"+f.getBody()+"|"+f.isThunk()+"|"+f.hasNoReturn();}
 private Region throughRts(Address entry,int maxInstructions,Function expectedOwner)throws Exception{
  var listing=currentProgram.getListing();int n=0;Address last=null;
  for(int i=0;i<maxInstructions;i++){
   Address at=entry.add(i*3L);Instruction ins=listing.getInstructionAt(at);
   if(ins==null||ins.getLength()!=3)throw new IllegalStateException("Native instruction gap "+at);
   Function owner=currentProgram.getFunctionManager().getFunctionContaining(at);
   if(owner!=expectedOwner)throw new IllegalStateException("Unexpected native owner at "+at);
   n++;if(ins.toString().trim().equals("RTS")){last=ins.getMaxAddress();break;}
  }
  if(last==null)throw new IllegalStateException("Native contiguous routine without RTS");
  return new Region(entry,last,n);
 }
 private int inboundCalls(Address at){int calls=0;for(Reference r:currentProgram.getReferenceManager().getReferencesTo(at))if(r.getReferenceType().isCall())calls++;return calls;}
 private String c(DecompInterface d,Function f)throws Exception{
  var result=d.decompileFunction(f,38,monitor);
  if(!result.decompileCompleted()||result.getDecompiledFunction()==null)
   throw new IllegalStateException("Ghidra C failed "+f.getEntryPoint()+": "+result.getErrorMessage());
  String code=result.getDecompiledFunction().getC();if(code.isBlank())throw new IllegalStateException("Empty C "+f.getEntryPoint());return code;
 }
 public void run()throws Exception{
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("DSP ISA required");
  String[] args=getScriptArgs();if(args.length!=4||!Set.of("audit","apply-safe").contains(args[0])||
    !args[2].matches("(?i)[0-9a-f]{4}")||!args[3].matches("(?i)[0-9a-f]{4}"))
    throw new IllegalArgumentException("audit|apply-safe exactSHA splitCALLentry orphanDOentry");
  if(!currentProgram.getExecutableSHA256().equals(args[1]))throw new IllegalArgumentException("Executable SHA mismatch");
  Address split=pm(args[2]),standalone=pm(args[3]);
  var listing=currentProgram.getListing();var fm=currentProgram.getFunctionManager();
  Function parent=fm.getFunctionContaining(split);
  if(parent==null||parent.getEntryPoint().equals(split))throw new IllegalStateException("Split target does not belong to foreign function");
  if(inboundCalls(split)<1)throw new IllegalStateException("Split target lacks CALL provenance");
  if(fm.getFunctionContaining(standalone)!=null)throw new IllegalStateException("Native loop already belongs to a function");
  Region child=throughRts(split,96,parent),single=throughRts(standalone,16,null);
  if(child.n()<5||child.n()>90||single.n()!=7)throw new IllegalStateException("Unproven native routine bounds");
  Instruction prior=listing.getInstructionAt(split.subtract(3));
  if(prior==null||!prior.toString().trim().equals("RTS"))throw new IllegalStateException("Split target lacks separate preceding RTS");
  Address next=single.finish().add(1);Function nextOwner=fm.getFunctionContaining(next);
  if(nextOwner==null||!nextOwner.getEntryPoint().equals(next))throw new IllegalStateException("Standalone native routine overlaps next entry");
  Instruction setup=listing.getInstructionAt(standalone),doinst=listing.getInstructionAt(standalone.add(3)),
    providerCall=listing.getInstructionAt(standalone.add(6)),finish=listing.getInstructionAt(single.finish().subtract(2)),
    end=listing.getInstructionAt(standalone.add(15));
  if(!setup.toString().trim().startsWith("LDI CNTR,")||!doinst.toString().trim().startsWith("DO ")||
    !providerCall.getFlowType().isCall()||!finish.toString().trim().equals("RTS")||end==null)
    throw new IllegalStateException("Original native DO/CALL/RTS contract absent");
  int encodedEnd=Integer.parseInt(doinst.toString().trim().split(" ")[1].replace("0x",""),16);
  if(!end.getAddress().equals(pm(String.format("%04x",encodedEnd))))throw new IllegalStateException("DO endpoint mismatches native instruction");
  Function callee=providerCall.getFlows().length==1?fm.getFunctionAt(providerCall.getFlows()[0]):null;
  if(callee==null||callee.hasNoReturn())throw new IllegalStateException("Unresolved returning DSP loop callee");
  for(Instruction i:listing.getInstructions(callee.getBody(),true))if(i.toString().trim().startsWith("DO ")||
    i.toString().trim().startsWith("LDI CNTR,")||i.toString().trim().startsWith("DMREAD CNTR,"))
    throw new IllegalStateException("Native callee may reset hardware loop state");
  // Split body is exactly one disconnected region; preserve rest unchanged.
  AddressSet splitSegment=new AddressSet(child.start(),child.finish());
  if(!parent.getBody().contains(splitSegment)||parent.getBody().getNumAddressRanges()!=2)
    throw new IllegalStateException("Parent native disjoint body not cleanly separable");
  Instruction tailJump=null;
  for(Instruction i:listing.getInstructions(parent.getBody(),true)){
    if(i.getFlowType().isJump()&&!i.getFlowType().isConditional()&&
      i.getFlows().length==1&&i.getFlows()[0].equals(split)){
      if(tailJump!=null)throw new IllegalStateException("Multiple native tailjump candidates");
      tailJump=i;
    }
  }
  if(tailJump==null||tailJump.getFlowOverride()!=FlowOverride.NONE||
     tailJump.getFallThrough()!=null||splitSegment.contains(tailJump.getAddress()))
    throw new IllegalStateException("Unproven native tailjump-to-returning-entry ABI");
  println("LAST_TWO_TAILCALL_PROOF nativeJUMP="+tailJump.getAddress()+
    " target="+split+" callee_endRTS="+child.finish()+" source_is_current_parent=true");
  println("LAST_TWO_PROOF split="+split+" owner="+parent.getEntryPoint()+" segment="+splitSegment+
    " CALLs="+inboundCalls(split)+" standalone="+standalone+" DO_end="+end.getAddress()+
    " callee="+callee.getEntryPoint()+" postRTS_entry="+next);
  int oldCount=fm.getFunctionCount();println("LAST_TWO_PLAN existingNative="+oldCount+" recoveredNative="+(oldCount+2)+" mode="+args[0]);
  if(args[0].equals("audit")){println("LAST_TWO_AUDIT_PASS");return;}
  byte[] raw=firmware();Map<Address,String> names=new TreeMap<>();
  for(Function f:fm.getFunctions(true))names.put(f.getEntryPoint(),identity(f));
  int initialInstructions=0;for(Instruction i:listing.getInstructions(true))initialInstructions++;
  int tx=currentProgram.startTransaction("Bounded DSP CALL split and isolated native DO/RTS routine");boolean commit=false;
  try{
   AddressSet retained=new AddressSet(parent.getBody());retained.delete(splitSegment);
   parent.setBody(retained);
   var childCmd=new CreateFunctionCmd(split);
   if(!childCmd.applyTo(currentProgram,monitor))throw new IllegalStateException("CALL target function creation failed "+childCmd.getStatusMsg());
   Function newChild=fm.getFunctionAt(split);
   if(newChild==null||!newChild.getBody().equals(splitSegment))throw new IllegalStateException("Split child body differs from native routine");
   // Native JUMP to a returning function transfers execution without pushing
   // another PC frame: this is precisely a tail-call. The flow override changes
   // only the Analyzer call/return representation, not original PM bits.
   tailJump.setFlowOverride(FlowOverride.CALL_RETURN);
   if(tailJump.getFlowOverride()!=FlowOverride.CALL_RETURN)
     throw new IllegalStateException("Native tail-call flow override was not applied");
   Register ce=currentProgram.getProgramContext().getRegister("codec_ce_loop_end"),
     direct=currentProgram.getProgramContext().getRegister("codec_ce_direct_backedge"),
     target=currentProgram.getProgramContext().getRegister("codec_ce_direct_start");
   if(ce==null||direct==null||target==null)throw new IllegalStateException("Processor lacks CE model context");
   byte[] endBytes=end.getBytes();
   listing.clearCodeUnits(end.getAddress(),end.getMaxAddress(),false);
   currentProgram.getProgramContext().setValue(ce,end.getAddress(),end.getAddress(),BigInteger.ONE);
   currentProgram.getProgramContext().setValue(direct,end.getAddress(),end.getAddress(),BigInteger.ONE);
   currentProgram.getProgramContext().setValue(target,end.getAddress(),end.getAddress(),
     BigInteger.valueOf(standalone.getAddressableWordOffset()+2));
   var recode=new DisassembleCommand(new AddressSet(end.getAddress(),end.getMaxAddress()),null,true);
   recode.enableCodeAnalysis(false);
   if(!recode.applyTo(currentProgram,monitor))throw new IllegalStateException("DSP CE end decode failed "+recode.getStatusMsg());
   Instruction refreshed=listing.getInstructionAt(end.getAddress());
   if(refreshed==null||!Arrays.equals(endBytes,refreshed.getBytes()))throw new IllegalStateException("Native CE bytes changed");
   int cb=0,jumpBack=0;for(var op:refreshed.getPcode()){
    if(op.getOpcode()==PcodeOp.CBRANCH)cb++;
    if(op.getOpcode()==PcodeOp.BRANCH&&standalone.add(6).equals(op.getInput(0).getAddress()))jumpBack++;
   }
   if(cb<1||jumpBack!=1)throw new IllegalStateException("DSP CE did not create the proven backedge");
   var standaloneCmd=new CreateFunctionCmd(standalone);
   if(!standaloneCmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Standalone native function create failed "+standaloneCmd.getStatusMsg());
   Function newLoop=fm.getFunctionAt(standalone);
   if(newLoop==null||!newLoop.getBody().contains(new AddressSet(single.start(),single.finish())))
    throw new IllegalStateException("Standalone native DO region lost");
   if(fm.getFunctionCount()!=oldCount+2)throw new IllegalStateException("Incomplete function inventory");
   if(!Arrays.equals(raw,firmware()))throw new IllegalStateException("Native PM/DM source modified");
   for(var e:names.entrySet()){
    Function now=fm.getFunctionAt(e.getKey());if(now==null)throw new IllegalStateException("Preexisting function deleted "+e.getKey());
    if(!e.getKey().equals(parent.getEntryPoint())&&!e.getValue().equals(identity(now)))
     throw new IllegalStateException("Unrelated function altered "+e.getKey());
   }
   int afterInstructions=0;for(Instruction i:listing.getInstructions(true))afterInstructions++;
   if(afterInstructions!=initialInstructions)throw new IllegalStateException("Native decoder instruction inventory changed");
   DecompInterface d=new DecompInterface();if(!d.openProgram(currentProgram))throw new IllegalStateException("C backend unavailable");
   int ok=0,warnings=0;String tailC="",splitC="",parentC="";
   try{for(Function f:fm.getFunctions(true))if(!f.isExternal()){
    monitor.checkCancelled();String code=c(d,f);ok++;int w=code.split("WARNING:",-1).length-1;warnings+=w;
    if(code.contains("halt_baddata"))throw new IllegalStateException("Unsupported native generated C at "+f.getEntryPoint());
    if(f.getEntryPoint().equals(standalone))tailC=code;
    if(f.getEntryPoint().equals(split))splitC=code;
    if(f.getEntryPoint().equals(parent.getEntryPoint()))parentC=code;
   }}finally{d.dispose();}
   println("LAST_TWO_C_GATE nativeTotal="+ok+" warningLines="+warnings+
     " childC="+splitC.length()+" parentC="+parentC.length()+" loopC="+tailC.length());
   println("LAST_TWO_PARENT_C "+parentC.replace('\n',' '));
   println("LAST_TWO_SPLIT_C "+splitC.replace('\n',' '));
   println("LAST_TWO_LOOP_C "+tailC.replace('\n',' '));
   println("LAST_TWO_C_CONTRACT boolDO="+tailC.contains("do {")+" callee="+tailC.contains(callee.getName()+"();")+
      " parentCall="+parentC.contains(newChild.getName()+"();")+
      " childReturnCall="+splitC.contains("FUN_PM_0176();"));
   if(ok!=oldCount+2||warnings!=0||!tailC.contains("do {")||
      !tailC.contains(callee.getName()+"();")||!parentC.contains(newChild.getName()+"();")||
      !splitC.contains("FUN_PM_0176();"))
     throw new IllegalStateException("Native C semantics did not recover both behavior contracts");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("LAST_TWO_TRANSACTION="+(commit?"COMMIT":"ROLLBACK"));}
  if(!commit)throw new IllegalStateException("DSP full native coverage not accepted");
  println("LAST_TWO_APPLY_PASS nativeTotal="+fm.getFunctionCount()+" warnings=0");
 }
}
