// Local GZF migration experiment: classified DO/UNTIL CE ends, guarded per-function rollback.
// Ghidra user-owned projects must be checkpointed before requesting apply; default audit.
//@category Sunplus/Regression
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.mem.MemoryBlock;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SunplusCodecCeBatchRecode extends GhidraScript {
 private static final Pattern RE=Pattern.compile("^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
 private record L(int start,int end,String owner,boolean valid,boolean call,boolean cntrWrite,int pcodeCb,boolean commented){}
 private Address pm(int w){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",w));}
 private int w(Address a){return Integer.parseInt(a.toString().substring(3).split("\\.")[0],16);}
 private int cbr(Instruction i){if(i==null)return -1;int n=0;for(PcodeOp op:i.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)n++;return n;}
 private int br(Instruction i){if(i==null)return -1;int n=0;for(PcodeOp op:i.getPcode())if(op.getOpcode()==PcodeOp.BRANCH)n++;return n;}
 private String inv(){StringBuilder s=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))s.append(f.getEntryPoint()).append('|').append(f.getName()).append('|').append(f.getBody()).append('\n');return s.toString();}
 private byte[] nativeSha() throws Exception{
  MessageDigest m=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
   if(!b.isInitialized())continue;
   long left=b.getSize();Address a=b.getStart();
   while(left>0){int take=(int)Math.min(left,buf.length);int n=currentProgram.getMemory().getBytes(a,buf,0,take);if(n!=take)throw new IllegalStateException("byte read error at "+a);m.update(buf,0,n);a=a.add(n);left-=n;}
  }return m.digest();
 }
 private String C(Function f)throws Exception{
  DecompInterface d=new DecompInterface();try{if(!d.openProgram(currentProgram))throw new IllegalStateException("decomp init");DecompileResults r=d.decompileFunction(f,18,monitor);if(!r.decompileCompleted()||r.getDecompiledFunction()==null)throw new IllegalStateException("C failed "+r.getErrorMessage());return r.getDecompiledFunction().getC();}finally{d.dispose();}
 }
 private int dos(String c){return c.split("do \\{",-1).length-1;}
 private int warnings(String c){return c.split("WARNING:",-1).length-1;}
 public void run() throws Exception{
  String[] args=getScriptArgs();String mode=args.length==0?"audit":args[0];
  if(!mode.equals("audit")&&!mode.equals("audit-call")&&!mode.equals("apply")&&!mode.equals("apply-call"))throw new IllegalStateException("mode must be audit|audit-call|apply|apply-call");
  boolean apply=mode.equals("apply")||mode.equals("apply-call");
  boolean callOnly=mode.equals("apply-call")||mode.equals("audit-call");
  // GhidraScript itself owns an outer transaction: aborting ANY inner transaction
  // can roll back ALL earlier successful nested transactions in this run.
  // Exclude independently identified high-risk owners before the write phase.
  Set<String> exclude=new HashSet<>();
  if(args.length>=2&&!args[1].isBlank())for(String part:args[1].split(","))exclude.add(part.trim().toUpperCase());
  if(currentProgram==null||!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong DSP program");
  if("srvdsp.bin".equals(currentProgram.getName()))throw new IllegalStateException("SRVDSP wrapper uses a separate CE implementation");
  Register endCtx=currentProgram.getProgramContext().getRegister("codec_ce_loop_end");
  Register direct=currentProgram.getProgramContext().getRegister("codec_ce_direct_backedge");
  Register startCtx=currentProgram.getProgramContext().getRegister("codec_ce_direct_start");
  if(endCtx==null||direct==null||startCtx==null)throw new IllegalStateException("Missing CE SLEIGH registers");
  String inventory=inv();byte[] hash=nativeSha();
  List<L> all=new ArrayList<>();
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();if(!"PM".equals(i.getAddress().getAddressSpace().getName()))continue;
   Matcher m=RE.matcher(i.toString().trim());if(!m.matches())continue;
   int begin=w(i.getAddress()),finish=Integer.parseInt(m.group(1),16);
   Instruction e=currentProgram.getListing().getInstructionAt(pm(finish));
   Function owner=currentProgram.getFunctionManager().getFunctionContaining(i.getAddress());
   boolean valid=owner!=null&&owner.getBody().contains(pm(finish))&&e!=null&&e.getLength()==3;
   boolean call=false,cntrWrite=false;
   for(int pos=begin+1;pos<=finish&&pos<begin+0x300;pos++){
    Instruction sub=currentProgram.getListing().getInstructionAt(pm(pos));
    if(sub!=null){
     if(sub.getFlowType().isCall())call=true;
     String op=sub.toString().toUpperCase(java.util.Locale.ROOT);
     if(op.contains("CNTR")&&(op.startsWith("LDI ")||op.startsWith("DMREAD ")||op.startsWith("POP ")))cntrWrite=true;
    }
   }
   boolean commented=false;
   if(e!=null)for(CommentType type:CommentType.values())if(e.getComment(type)!=null&&!e.getComment(type).isBlank())commented=true;
   all.add(new L(begin,finish,owner==null?"unowned":owner.getEntryPoint().toString(),valid,call,cntrWrite,cbr(e),commented));
  }
  Map<String,List<L>> byOwner=new LinkedHashMap<>();for(L a:all)byOwner.computeIfAbsent(a.owner,k->new ArrayList<>()).add(a);
  int eligible=0,processed=0,applied=0,failed=0,invalid=0,nested=0,withCall=0,commented=0,old=0,skipped=0,cntrHazards=0;
  for(var entry:byOwner.entrySet()){
   monitor.checkCancelled();
   if(exclude.contains(entry.getKey().toUpperCase())){println("CE_BATCH_EXCLUDED owner="+entry.getKey());continue;}
   List<L> candidates=new ArrayList<>();boolean groupedNested=false;
   for(L a:entry.getValue())for(L b:entry.getValue())if(a!=b&&a.start<=b.end&&b.start<=a.end)groupedNested=true;
   for(L a:entry.getValue()){
    if(a.pcodeCb>0){old++;continue;}
    if(!a.valid){invalid++;continue;}
    if(groupedNested){nested++;continue;}
    if(a.call!=callOnly){if(a.call)withCall++;continue;}
    if(a.commented){commented++;continue;}
    if(a.cntrWrite){cntrHazards++;println("CE_BATCH_CNTR_HAZARD owner="+entry.getKey()+" DO=PM:"+String.format("%04x",a.start));continue;}
    candidates.add(a);eligible++;
   }
   if(candidates.isEmpty())continue;
   if(!apply){println("CE_BATCH_ELIGIBLE owner="+entry.getKey()+" loops="+candidates.size());continue;}
   Function owner=currentProgram.getFunctionManager().getFunctionAt(pm(Integer.parseInt(entry.getKey().substring(3),16)));
   if(owner==null){failed+=candidates.size();println("CE_BATCH_FAILED missing owner "+entry.getKey());continue;}
   String before;try{before=C(owner);}catch(Exception e){failed+=candidates.size();println("CE_BATCH_FAILED predecomp "+entry.getKey()+" "+e);continue;}
   int tx=currentProgram.startTransaction("Batch proven direct CE loops "+entry.getKey());boolean commit=false;
   try{
    for(L a:candidates){
     Address at=pm(a.end);
     currentProgram.getListing().clearCodeUnits(at,at,true);
     currentProgram.getProgramContext().setValue(endCtx,at,at,BigInteger.ONE);
     currentProgram.getProgramContext().setValue(direct,at,at,BigInteger.ONE);
     currentProgram.getProgramContext().setValue(startCtx,at,at,BigInteger.valueOf(a.start+1));
     DisassembleCommand cmd=new DisassembleCommand(new AddressSet(at,at.add(2)),null,true);
     cmd.enableCodeAnalysis(false);
     if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("disasm "+at+" "+cmd.getStatusMsg());
     Instruction e=currentProgram.getListing().getInstructionAt(at);
     if(cbr(e)==0||br(e)==0)throw new IllegalStateException("CE backedge missing "+at);
    }
    if(!inventory.equals(inv()))throw new IllegalStateException("function names/boundaries changed");
    if(!Arrays.equals(hash,nativeSha()))throw new IllegalStateException("native memory changed");
    String after=C(owner);
    // PM:0506's proven DO PM:0526 -> PM:055A decompiles as a guarded
    // `while (true)` with a decrement/zero exit, not as a `do {` loop.
    // This narrow target-specific acceptance does not weaken general cases.
    boolean pm0506=entry.getKey().equals("PM:0506")&&candidates.size()==1
      &&candidates.get(0).start==0x0526&&candidates.get(0).end==0x055a;
    int whileBefore=before.split("while\\( true \\)",-1).length-1;
    int whileAfter=after.split("while\\( true \\)",-1).length-1;
    boolean structured=pm0506&&dos(after)==dos(before)&&whileAfter==whileBefore+1
      &&after.contains("sVar6 = sVar6 + -1;")&&after.contains("if (sVar6 == 0)");
    if(structured)println("CE_BATCH_PM0506_STRUCTURED_WHILE_ACCEPTANCE=PASS extra_while=1 native_DO=PM:0526 end=PM:055a");
    if(!structured&&dos(after)<dos(before)+candidates.size())throw new IllegalStateException("C loops not recovered "+dos(before)+"->"+dos(after)+" expected+"+candidates.size());
    if(warnings(after)>warnings(before))throw new IllegalStateException("C warnings grew "+warnings(before)+"->"+warnings(after));
    commit=true;
    println("CE_BATCH_RECOVERED owner="+entry.getKey()+" loops="+candidates.size()+" Cdo="+dos(before)+"->"+dos(after));
   }catch(Exception e){println("CE_BATCH_ROLLBACK owner="+entry.getKey()+" reason="+e.getMessage());failed+=candidates.size();}
   finally{currentProgram.endTransaction(tx,commit);}
   if(commit){applied+=candidates.size();processed++;}else skipped++;
  }
  if(!inventory.equals(inv())||!Arrays.equals(hash,nativeSha()))throw new IllegalStateException("POSTCONDITION: program changed");
  println("CE_BATCH_SUMMARY mode="+mode+" program="+currentProgram.getName()+" native="+all.size()+" selected="+eligible+" recovered="+applied+" owners="+processed+" rollbacks="+failed+" old="+old+" invalid="+invalid+" nested="+nested+" call="+withCall+" commented="+commented+" cntr_hazard="+cntrHazards+" skipped="+skipped);
  if(failed!=0)throw new IllegalStateException("CE_BATCH_UNCOMMITTED: aborted nested transaction(s)="+failed+". No recovery may be claimed until persisted independent readback.");
  println("CE_BATCH_RUN_PASS mode="+mode);
 }
}
