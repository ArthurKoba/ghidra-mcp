//@category Sunplus/Architecture
// Static native proof that a 16-bit value shifted right >=16 becomes zero,
// followed by AR=(SR0 AND 1) and IF NE. No arbitrary PM address or file name.
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
public class SunplusDSPProvenZeroShiftPredicate extends GhidraScript {
 private static final Pattern SE=Pattern.compile("^LDI SE,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
 private record Proof(Address at,Function owner,byte[] bytes,String rendered,int shift) {}
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
  Register proofFlag=currentProgram.getProgramContext().getRegister("codec_branch_proven_not_taken");
  if(proofFlag==null)throw new IllegalStateException("Missing supported architecture flag");
  List<Proof> sites=new ArrayList<>();Listing listing=currentProgram.getListing();FunctionManager fm=currentProgram.getFunctionManager();
  for(Instruction branch:listing.getInstructions(true)){
   monitor.checkCancelled();if(!"PM".equals(branch.getAddress().getAddressSpace().getName())||
     !branch.toString().trim().startsWith("IF NE JUMP ")||count(branch,PcodeOp.CBRANCH)==0)continue;
   Address b=branch.getAddress();Instruction and=listing.getInstructionAt(prior(b,1));
   Instruction shift=listing.getInstructionAt(prior(b,2));Instruction set=listing.getInstructionAt(prior(b,3));
   if(and==null||shift==null||set==null||
      !"AR = SR0 AND 0x0001".equals(and.toString().trim())||
      !"SR = LSHIFT AR (LO)".equals(shift.toString().trim()))continue;
   Matcher m=SE.matcher(set.toString().trim());if(!m.matches())continue;
   int amount=(short)Integer.parseInt(m.group(1),16);
   // AR is an exact 16-bit operand; negative SE shifts right. A right shift
   // by at least 16 is identically zero before AND 1 sets the condition flags.
   if(amount>-16||amount>=0)continue;
   Function owner=fm.getFunctionContaining(b);
   if(owner==null||!owner.getBody().contains(set.getAddress())||foreignFlow(set.getAddress(),b))continue;
   if(BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(proofFlag,b,false)))continue;
   sites.add(new Proof(b,owner,branch.getBytes(),branch.toString(),amount));
   println("DSP_ZERO_SHIFT_NATIVE_PROOF owner="+owner.getEntryPoint()+" branch="+b+
     " native_SE="+amount+" original_branch="+branch+" AR_bits=16");
  }
  println("DSP_ZERO_SHIFT_PLAN program="+currentProgram.getName()+" native_functions="+fm.getFunctionCount()+
    " eligible_proven_false_branches="+sites.size()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_ZERO_SHIFT_AUDIT_PASS");return;}
  if(sites.isEmpty()){println("DSP_ZERO_SHIFT_APPLY_PASS changed=0");return;}
  byte[] before=hash();String functions=inv();int instN=0;
  for(Instruction i:listing.getInstructions(true))instN++;
  Map<Function,String> cBefore=new LinkedHashMap<>();DecompInterface dc=new DecompInterface();
  if(!dc.openProgram(currentProgram))throw new IllegalStateException("C backend missing");
  try{for(Function f:fm.getFunctions(true))if(!f.isExternal())cBefore.put(f,c(dc,f));}finally{dc.dispose();}
  int tx=currentProgram.startTransaction("Exact native-proven DSP false predicate elimination");boolean commit=false;
  try{
   for(Proof item:sites){
    Instruction previous=listing.getInstructionAt(item.at());
    if(previous==null||!Arrays.equals(previous.getBytes(),item.bytes())||!previous.toString().equals(item.rendered()))
     throw new IllegalStateException("Native proof changed "+item.at());
    listing.clearCodeUnits(item.at(),item.at().add(2),false);
    currentProgram.getProgramContext().setValue(proofFlag,item.at(),item.at(),BigInteger.ONE);
    var cmd=new DisassembleCommand(new AddressSet(item.at(),item.at().add(2)),null,true);
    cmd.enableCodeAnalysis(false);
    if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Cannot re-decode false branch "+item.at());
    Instruction next=listing.getInstructionAt(item.at());
    if(next==null||!Arrays.equals(next.getBytes(),item.bytes())||
       count(next,PcodeOp.CBRANCH)>0||count(next,PcodeOp.BRANCH)>0)
      throw new IllegalStateException("Branch P-code has not been neutralized "+item.at());
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
     if(b<a)println("DSP_ZERO_SHIFT_C_IMPROVEMENT owner="+e.getKey().getEntryPoint()+" warnings="+a+"->"+b);
    }
   }finally{post.dispose();}
   println("DSP_ZERO_SHIFT_C_GATE native="+cBefore.size()+" warning_lines="+warnBefore+"->"+warnAfter+" regressions="+reg);
   if(reg!=0||warnAfter>=warnBefore)throw new IllegalStateException("No verified C warning reduction");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("DSP_ZERO_SHIFT_TRANSACTION="+(commit?"COMMIT":"ROLLBACK"));}
  if(!commit)throw new IllegalStateException("False branch proof rejected");
  println("DSP_ZERO_SHIFT_APPLY_PASS corrected="+sites.size());
 }
}
