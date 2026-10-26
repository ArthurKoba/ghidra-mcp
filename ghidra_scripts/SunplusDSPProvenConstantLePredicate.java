//@category Sunplus/Architecture
// Static native signed 16-bit AF=(AR-AY0), with constant AR/AY0 values
// and an intervening flag-preserving register load, makes IF LE provably true.
// No arbitrary PM address, firmware name, or manually manufactured target.
// Native SHA gated, all C checked. Preserve bytes, functions and existing names.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.mem.MemoryBlock;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
public class SunplusDSPProvenConstantLePredicate extends GhidraScript {
 private static final Pattern AR=Pattern.compile("^LDI AR,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
 private static final Pattern AY=Pattern.compile("^LDI AY0,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
 private record Proof(Address at,Function owner,byte[] bytes,String rendered,int lhs,int rhs) {}
 private Address prior(Address at,int n){return at.subtract(n*3L);}
 private int count(Instruction ins,int op){int n=0;for(var p:ins.getPcode())if(p.getOpcode()==op)n++;return n;}
 private String inv(){StringBuilder out=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  out.append(f.getEntryPoint()).append('/').append(f.getName()).append('/').append(f.getBody()).append('/').append(f.isThunk()).append('\n');return out.toString();}
 private byte[] hash()throws Exception{var d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address at=b.getStart();long n=b.getSize();while(n>0){monitor.checkCancelled();int z=(int)Math.min(n,buf.length);
    if(currentProgram.getMemory().getBytes(at,buf,0,z)!=z)throw new IllegalStateException("Unreadable firmware");
    d.update(buf,0,z);n-=z;at=at.add(z);
   }
  }return d.digest();}
 private String c(DecompInterface d,Function fn)throws Exception{
  DecompileResults r=d.decompileFunction(fn,27,monitor);
  if(!r.decompileCompleted()||r.getDecompiledFunction()==null||r.getDecompiledFunction().getC().isBlank())
   throw new IllegalStateException("Missing native C "+fn.getEntryPoint());
  return r.getDecompiledFunction().getC();}
 private int warn(String s){return s.split("WARNING:",-1).length-1;}
 private boolean foreignFlow(Address begin,Address finish){
  for(Address a=begin.add(3);a.compareTo(finish)<=0;a=a.add(3)){
   for(Reference r:currentProgram.getReferenceManager().getReferencesTo(a))
    if(r.getReferenceType().isFlow()&&!r.getFromAddress().equals(a.subtract(3)))return true;
  }return false;}
 public void run()throws Exception{
  if(currentProgram==null||!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Sunplus DSP program required");
  String[] args=getScriptArgs();String mode=args.length==0?"audit":args[0];
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit | apply-safe imageSHA");
  if(mode.equals("apply-safe")&&(args.length!=2||!args[1].equals(currentProgram.getExecutableSHA256())))
   throw new IllegalArgumentException("Executable identity mismatch");
  Register proofFlag=currentProgram.getProgramContext().getRegister("codec_le_proven_taken");
  if(proofFlag==null)throw new IllegalStateException("Missing supported architecture flag");
  List<Proof> sites=new ArrayList<>();Listing listing=currentProgram.getListing();FunctionManager fm=currentProgram.getFunctionManager();
  for(Instruction branch:listing.getInstructions(true)){
   monitor.checkCancelled();if(!"PM".equals(branch.getAddress().getAddressSpace().getName())||
     !branch.toString().trim().startsWith("IF LE JUMP ")||count(branch,PcodeOp.CBRANCH)==0)continue;
   Address at=branch.getAddress();Instruction extra=listing.getInstructionAt(prior(at,1));
   Instruction af=listing.getInstructionAt(prior(at,2));Instruction ay=listing.getInstructionAt(prior(at,3));
   Instruction ar=listing.getInstructionAt(prior(at,4));
   if(extra==null||af==null||ay==null||ar==null||
      !extra.toString().trim().startsWith("LDI AX0,")||
      !"AF = AR - AY0".equals(af.toString().trim()))continue;
   Matcher am=AR.matcher(ar.toString().trim()),bm=AY.matcher(ay.toString().trim());
   if(!am.matches()||!bm.matches())continue;
   int lhs=(short)Integer.parseInt(am.group(1),16),rhs=(short)Integer.parseInt(bm.group(1),16);
   // Both constants are nonnegative and their signed difference fits 16 bits;
   // LE is necessarily taken. Reject arithmetic ranges requiring overflow analysis.
   if(lhs<0||rhs<0||lhs>0x7fff||rhs>0x7fff||lhs>rhs)continue;
   boolean modifiesFlags=false;
   for(var op:extra.getPcode())if(op.getOutput()!=null&&op.getOutput().isRegister()){
    String rn=op.getOutput().toString().toUpperCase(Locale.ROOT);
    if(rn.contains("AZF")||rn.contains("ANF")||rn.contains("AVF")||rn.contains("ACF"))modifiesFlags=true;
   }
   if(modifiesFlags)continue;
   Function owner=fm.getFunctionContaining(at);
   if(owner==null||!owner.getBody().contains(ar.getAddress())||foreignFlow(ar.getAddress(),at))continue;
   if(BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(proofFlag,at,false)))continue;
   sites.add(new Proof(at,owner,branch.getBytes(),branch.toString(),lhs,rhs));
   println("DSP_CONST_LE_NATIVE_PROOF owner="+owner.getEntryPoint()+" branch="+at+
     " lhs="+lhs+" rhs="+rhs+" signed_diff="+(lhs-rhs)+" proven_true=1");
  }
  println("DSP_CONST_LE_PLAN program="+currentProgram.getName()+" native_functions="+fm.getFunctionCount()+
    " eligible_proven_false_branches="+sites.size()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_CONST_LE_AUDIT_PASS");return;}
  if(sites.isEmpty()){println("DSP_CONST_LE_APPLY_PASS changed=0");return;}
  byte[] before=hash();String functions=inv();int instN=0;
  for(Instruction i:listing.getInstructions(true))instN++;
  Map<Function,String> cBefore=new LinkedHashMap<>();DecompInterface dc=new DecompInterface();
  if(!dc.openProgram(currentProgram))throw new IllegalStateException("C backend missing");
  try{for(Function f:fm.getFunctions(true))if(!f.isExternal())cBefore.put(f,c(dc,f));}finally{dc.dispose();}
  int tx=currentProgram.startTransaction("Native-proven constant true signed LE predicate");boolean commit=false;
  try{
   for(Proof item:sites){
    Instruction previous=listing.getInstructionAt(item.at());
    if(previous==null||!Arrays.equals(previous.getBytes(),item.bytes())||!previous.toString().equals(item.rendered()))
     throw new IllegalStateException("Native constant proof changed "+item.at());
    listing.clearCodeUnits(item.at(),item.at().add(2),false);
    currentProgram.getProgramContext().setValue(proofFlag,item.at(),item.at(),BigInteger.ONE);
    var cmd=new DisassembleCommand(new AddressSet(item.at(),item.at().add(2)),null,true);
    cmd.enableCodeAnalysis(false);
    if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Cannot re-decode false branch "+item.at());
    Instruction next=listing.getInstructionAt(item.at());
    if(next==null||!Arrays.equals(next.getBytes(),item.bytes())||
       count(next,PcodeOp.CBRANCH)>0||count(next,PcodeOp.BRANCH)!=1)
      throw new IllegalStateException("Branch P-code has not been reduced to proven direct target "+item.at());
   }
   if(!Arrays.equals(before,hash())||!functions.equals(inv()))throw new IllegalStateException("Source or function identity changed");
   int newN=0;for(Instruction i:listing.getInstructions(true))newN++;
   if(newN!=instN)throw new IllegalStateException("Native instruction inventory changed");
   DecompInterface post=new DecompInterface();if(!post.openProgram(currentProgram))throw new IllegalStateException("No post C");
   int warnBefore=0,warnAfter=0,reg=0;try{
    for(var e:cBefore.entrySet()){
     String output=c(post,e.getKey());int a=warn(e.getValue()),b=warn(output);
     warnBefore+=a;warnAfter+=b;
     if(b>a||output.contains("halt_baddata"))reg++;
     if(b<a)println("DSP_CONST_LE_C_IMPROVEMENT owner="+e.getKey().getEntryPoint()+" warnings="+a+"->"+b);
    }
   }finally{post.dispose();}
   println("DSP_CONST_LE_C_GATE native="+cBefore.size()+" warning_lines="+warnBefore+"->"+warnAfter+" regressions="+reg);
   if(reg!=0||warnAfter>=warnBefore)throw new IllegalStateException("No verified C warning reduction");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("DSP_CONST_LE_TRANSACTION="+(commit?"COMMIT":"ROLLBACK"));}
  if(!commit)throw new IllegalStateException("Constant LE predicate proof rejected");
  println("DSP_CONST_LE_APPLY_PASS corrected="+sites.size());
 }
}
