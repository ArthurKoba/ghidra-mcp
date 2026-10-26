//@category Sunplus/Architecture
// Architecture-derived false IF LE proof for positive (0x0100 - AX0), with
// exact native LD AX0, flag-preserving move, and bounded native CALL entry.
// Recover function using normal Ghidra function discovery, never handwritten C.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
public class SunplusDSPProvenFalseLeEntryRecovery extends GhidraScript {
 private static final Pattern IMM=Pattern.compile("^LDI AX0,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
 private record Proven(Address first,Address branch,int ax0,String branchText,byte[] branchBytes) {}
 private int pcode(Instruction i,int code){int n=0;for(var op:i.getPcode())if(op.getOpcode()==code)n++;return n;}
 private boolean flagsPreserved(Instruction i){
  for(var p:i.getPcode()){
   var output=p.getOutput();if(output==null||!output.isRegister())continue;
   String name=output.toString().toUpperCase(Locale.ROOT);
   if(name.contains("AZF")||name.contains("ANF")||name.contains("AVF")||name.contains("ACF"))return false;
  }return true;
 }
 private boolean flowIntoMiddle(Address start,Address end){
  for(Address a=start.add(3);a.compareTo(end)<=0;a=a.add(3)){
   for(Reference r:currentProgram.getReferenceManager().getReferencesTo(a))
    if(r.getReferenceType().isFlow()&&!r.getFromAddress().equals(a.subtract(3)))return true;
  }return false;
 }
 private byte[] firmware()throws Exception{
  var sha=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address a=b.getStart();long n=b.getSize();while(n>0){monitor.checkCancelled();int take=(int)Math.min(n,buf.length);
    if(currentProgram.getMemory().getBytes(a,buf,0,take)!=take)throw new IllegalStateException("Firmware unreadable at "+a);
    sha.update(buf,0,take);n-=take;a=a.add(take);
   }
  }return sha.digest();
 }
 private Map<Address,String> inventory(){Map<Address,String> result=new TreeMap<>();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  result.put(f.getEntryPoint(),f.getName()+"|"+f.getBody()+"|"+f.hasNoReturn()+"|"+f.isThunk());return result;
 }
 private String c(DecompInterface d,Function f)throws Exception{
  var r=d.decompileFunction(f,40,monitor);if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
    throw new IllegalStateException("Native C generation failed "+f.getEntryPoint()+": "+r.getErrorMessage());
  String value=r.getDecompiledFunction().getC();if(value.isBlank())throw new IllegalStateException("Empty C "+f.getEntryPoint());return value;
 }
 public void run()throws Exception{
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
    throw new IllegalStateException("Wrong processor language");
  String[] args=getScriptArgs();if(args.length!=3||!Set.of("audit","apply-safe").contains(args[0])||
    !args[2].matches("(?i)[0-9a-f]{4}"))throw new IllegalArgumentException("audit|apply-safe originalSHA candidateEntry");
  if(!args[1].equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Source SHA mismatch");
  Address entry=currentProgram.getAddressFactory().getAddress("PM:"+args[2]);
  var fm=currentProgram.getFunctionManager();var listing=currentProgram.getListing();
  if(fm.getFunctionContaining(entry)!=null)throw new IllegalStateException("Native entry already owned");
  int incomingCalls=0;for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(entry))if(ref.getReferenceType().isCall())incomingCalls++;
  if(incomingCalls==0)throw new IllegalStateException("No machine CALL evidence");
  List<Proven> matches=new ArrayList<>();
  for(int delta=0;delta<240;delta++){
   monitor.checkCancelled();Address first=entry.add(3L*delta),last=first.add(9);
   if(fm.getFunctionContaining(first)!=null||fm.getFunctionContaining(last)!=null)break;
   Instruction set=listing.getInstructionAt(first),move=listing.getInstructionAt(first.add(3)),
       arithmetic=listing.getInstructionAt(first.add(6)),branch=listing.getInstructionAt(last);
   if(set==null||move==null||arithmetic==null||branch==null)break;
   Matcher imm=IMM.matcher(set.toString().trim());if(!imm.matches())continue;
   int ax0=Integer.parseInt(imm.group(1),16);
   if(ax0<0||ax0>=0x100)continue; // 0x0100 - AX0 is signed positive, overflow impossible
   if(!"I1 = AX0".equals(move.toString().trim())||!flagsPreserved(move)||
     !"AR = 0x0100 - AX0".equals(arithmetic.toString().trim())||
     !branch.toString().trim().startsWith("IF LE JUMP ")||
     pcode(branch,PcodeOp.CBRANCH)==0||flowIntoMiddle(first,last))continue;
   matches.add(new Proven(first,last,ax0,branch.toString(),branch.getBytes()));
  }
  if(matches.size()!=1)throw new IllegalStateException("Expected exactly one native constant-false LE proof, found "+matches.size());
  Proven proof=matches.get(0);
  println("FALSE_LE_NATIVE_PROOF entry="+entry+" incoming_CALL="+incomingCalls+" start="+proof.first()+
    " branch="+proof.branch()+" AX0="+proof.ax0()+" AR_positive="+(0x100-proof.ax0())+" branch_false=true");
  int oldCount=fm.getFunctionCount();println("FALSE_LE_PLAN oldNative="+oldCount+" target="+(oldCount+1)+" mode="+args[0]);
  if(args[0].equals("audit")){println("FALSE_LE_AUDIT_PASS");return;}
  Register flag=currentProgram.getProgramContext().getRegister("codec_branch_proven_not_taken");
  if(flag==null)throw new IllegalStateException("New model lacks false predicate proof context");
  byte[] beforeBytes=firmware();Map<Address,String> old=inventory();int oldInstructionCount=0;
  for(Instruction i:listing.getInstructions(true))oldInstructionCount++;
  int tx=currentProgram.startTransaction("CALL-derived DSP entry with proven unreachable false-LE branch");boolean commit=false;
  try{
   Instruction branch=listing.getInstructionAt(proof.branch());
   if(!proof.branchText().equals(branch.toString())||!Arrays.equals(proof.branchBytes(),branch.getBytes()))
    throw new IllegalStateException("Machine proof changed");
   // Preserve all user-authored native comments on the original instruction.
   CommentType[] types={CommentType.EOL,CommentType.PRE,CommentType.POST,CommentType.PLATE,CommentType.REPEATABLE};
   String[] comments=new String[types.length];for(int j=0;j<types.length;j++)comments[j]=listing.getComment(types[j],proof.branch());
   listing.clearCodeUnits(proof.branch(),proof.branch().add(2),false);
   currentProgram.getProgramContext().setValue(flag,proof.branch(),proof.branch(),BigInteger.ONE);
   var recode=new DisassembleCommand(new AddressSet(proof.branch(),proof.branch().add(2)),null,true);
   recode.enableCodeAnalysis(false);
   if(!recode.applyTo(currentProgram,monitor))throw new IllegalStateException("Native branch instruction update failed "+recode.getStatusMsg());
   Instruction updated=listing.getInstructionAt(proof.branch());
   if(updated==null||!Arrays.equals(updated.getBytes(),proof.branchBytes())||
     pcode(updated,PcodeOp.BRANCH)>0||pcode(updated,PcodeOp.CBRANCH)>0)
      throw new IllegalStateException("Provably false LE still has a flow edge");
   for(int j=0;j<types.length;j++)if(comments[j]!=null)listing.setComment(proof.branch(),types[j],comments[j]);
   var create=new CreateFunctionCmd(entry);
   if(!create.applyTo(currentProgram,monitor))throw new IllegalStateException("Ghidra CALL entry creation failed "+create.getStatusMsg());
   Function added=fm.getFunctionAt(entry);if(added==null||added.getBody().isEmpty())throw new IllegalStateException("Recovered function absent");
   if(fm.getFunctionCount()!=oldCount+1)throw new IllegalStateException("Unexpected function denominator");
   if(!Arrays.equals(beforeBytes,firmware()))throw new IllegalStateException("Original firmware modified");
   for(var e:old.entrySet())if(!e.getValue().equals(inventory().get(e.getKey())))
    throw new IllegalStateException("Old function name/body/metadata changed "+e.getKey());
   int newInstructions=0;for(Instruction i:listing.getInstructions(true))newInstructions++;
   if(newInstructions!=oldInstructionCount)throw new IllegalStateException("Original instruction count changed");
   DecompInterface d=new DecompInterface();if(!d.openProgram(currentProgram))throw new IllegalStateException("C backend unavailable");
   int count=0,warn=0;try{for(Function f:fm.getFunctions(true))if(!f.isExternal()){
     String generated=c(d,f);count++;int w=generated.split("WARNING:",-1).length-1;warn+=w;
     if(generated.contains("halt_baddata"))throw new IllegalStateException("Unsupported native C "+f.getEntryPoint());
     if(f.getEntryPoint().equals(entry))println("FALSE_LE_NEW_C body="+f.getBody()+" chars="+generated.length()+" warnings="+w);
   }}finally{d.dispose();}
   println("FALSE_LE_C_GATE functions="+count+" expected="+(oldCount+1)+" C_failed=0 warningLines="+warn);
   if(count!=oldCount+1||warn!=0)throw new IllegalStateException("Complete native C acceptance failed");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("FALSE_LE_TRANSACTION="+(commit?"COMMIT":"ROLLBACK"));}
  if(!commit)throw new IllegalStateException("Native flow acceptance failed");
  println("FALSE_LE_APPLY_PASS created=1 nativeTotal="+fm.getFunctionCount()+" warningLines=0");
 }
}
