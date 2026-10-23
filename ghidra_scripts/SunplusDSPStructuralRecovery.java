//@category Sunplus/Architecture
// Architecture-derived DO..CE CFG recovery. No firmware-specific PM offsets,
// function names, profile filenames, or decode SHA constants.
//
// Default: audit (read only). To mutate an ISOLATED and backed-up program,
// call with: -postScript SunplusDSPStructuralRecovery.java apply-safe
// Any failed invariant, decompilation, or C improvement rolls back the entire
// program transaction. Unsupported loops stay UNKNOWN; never fabricate edges.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class SunplusDSPStructuralRecovery extends GhidraScript {
 private static final Pattern DO =
   Pattern.compile("^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private enum State {EXACT_DIRECT, INDIRECT, INTERNAL_ONLY, NO_CE, WRONG_DIRECT,
                     INVALID, NESTED, COUNTER_HAZARD, CALL_HAZARD}
 private record Loop(int start,int end,Address entry,Address finish,Function owner,int depth,
                     State state,String reason) {}
 private Address pm(int w){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",w));}
 private int word(Address addr){
  return (int)(addr.getOffset()/addr.getAddressSpace().getAddressableUnitSize());
 }
 private int pcodeCount(Instruction inst,int op){
  if(inst==null)return 0;
  int n=0;for(PcodeOp p:inst.getPcode())if(p.getOpcode()==op)n++;return n;
 }
 private boolean counterWrite(Instruction inst){
  String s=inst.toString().trim().toUpperCase(Locale.ROOT);
  return s.startsWith("LDI CNTR,")||s.startsWith("DMREAD CNTR,")||
     s.startsWith("POP CNTR")||s.startsWith("CNTR =");
 }
 private int cLoops(String code){return code.split("do \\{",-1).length-1;}
 private int cWarnings(String code){return code.split("WARNING:",-1).length-1;}
 private String c(DecompInterface d,Function f)throws Exception{
  DecompileResults r=d.decompileFunction(f,25,monitor);
  if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
    throw new IllegalStateException("C decomp failed at "+f.getEntryPoint()+": "+r.getErrorMessage());
  return r.getDecompiledFunction().getC();
 }
 private byte[] initializedSHA()throws Exception{
  MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
   if(!b.isInitialized())continue;
   Address at=b.getStart();long n=b.getSize();
   while(n>0){int m=(int)Math.min(n,buf.length);
    if(currentProgram.getMemory().getBytes(at,buf,0,m)!=m)
      throw new IllegalStateException("Unreadable original firmware bytes "+at);
    d.update(buf,0,m);at=at.add(m);n-=m;}
  }return d.digest();
 }
 private String functions(){
  StringBuilder b=new StringBuilder();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   b.append(f.getEntryPoint()).append(':').append(f.getName()).append(':').append(f.getBody()).append('\n');
  return b.toString();
 }
 private boolean overlapping(int a,int b,int c,int d){return a<=d && c<=b;}
 private boolean nestedParent(int a,int b,int c,int d){return a<c && d<b;}
 private List<Loop> discover(){
  ArrayList<int[]> raw=new ArrayList<>();
  ArrayList<Function> owners=new ArrayList<>();
  for(Instruction ins:currentProgram.getListing().getInstructions(true)){
   if(!"PM".equals(ins.getAddress().getAddressSpace().getName()))continue;
   Matcher m=DO.matcher(ins.toString().trim());
   if(!m.matches())continue;
   raw.add(new int[]{word(ins.getAddress()),Integer.parseInt(m.group(1),16)});
   owners.add(currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress()));
  }
  ArrayList<Loop> discovered=new ArrayList<>();
  for(int k=0;k<raw.size();k++){
   int begin=raw.get(k)[0],end=raw.get(k)[1];
   Function owner=owners.get(k);
   Instruction first=currentProgram.getListing().getInstructionAt(pm(begin));
   Instruction tail=currentProgram.getListing().getInstructionAt(pm(end));
   Address expected=pm(begin+1);
   String reason="";
   boolean valid=owner!=null&&begin<end&&end-begin<0x4000 &&
     first!=null&&first.getFallThrough()!=null&&expected.equals(first.getFallThrough()) &&
     tail!=null&&tail.getLength()==3&&owner.getBody().contains(expected)&&
     owner.getBody().contains(tail.getAddress());
   boolean conflict=false,participatesInNesting=false;int depth=1;
   for(int j=0;j<raw.size();j++){
    if(k==j)continue;
    int a=raw.get(j)[0],b=raw.get(j)[1];
    if(owners.get(j)!=owner||owner==null)continue;
    if(nestedParent(a,b,begin,end)){
      depth++;participatesInNesting=true; // this DO is an inner loop
    }else if(nestedParent(begin,end,a,b)){
      participatesInNesting=true; // this DO is an OUTER loop, also unsafe here
    }else if(overlapping(a,b,begin,end)){
      conflict=true; // crossing/shared endpoints are not a proven loop stack
    }
   }
   State state;
   if(!valid||conflict||depth>2){state=State.INVALID;reason="owner/interval/fallthrough/overlap"; }
   else if(participatesInNesting){state=State.NESTED;reason="outer or inner DO requires stack and CNTR provenance"; }
   else{
    int cb=0,brpm=0,matching=0,ind=0;
    for(PcodeOp op:tail.getPcode()){
      if(op.getOpcode()==PcodeOp.CBRANCH)cb++;
      if(op.getOpcode()==PcodeOp.BRANCH){
       Address a=op.getInput(0).getAddress();
       if("PM".equals(a.getAddressSpace().getName())){brpm++;if(expected.equals(a))matching++;}
      }
      if(op.getOpcode()==PcodeOp.BRANCHIND)ind++;
    }
    if(brpm>0 && (brpm!=1||matching!=1||cb==0)){state=State.WRONG_DIRECT;reason="external PM target differs from DO successor";}
    else if(brpm==1&&matching==1&&cb>0){state=State.EXACT_DIRECT;reason="confirmed PM branch target";}
    else if(ind>0&&cb>0){state=State.INDIRECT;reason="dynamic loop-register provenance required";}
    else {
      boolean call=false,counter=false,gap=false;
      for(int x=begin+1;x<=end;x++){
       Instruction ins=currentProgram.getListing().getInstructionAt(pm(x));
       if(ins==null){gap=true;break;}
       if(ins.getFlowType().isCall())call=true;
       if(x<end&&counterWrite(ins))counter=true;
      }
      if(gap){state=State.INVALID;reason="missing code inside loop";}
      else if(counter){state=State.COUNTER_HAZARD;reason="CNTR reload inside nominally nonnested loop";}
      else if(call){state=State.CALL_HAZARD;reason="callee may alter live hardware loop state";}
      else if(cb>0){state=State.INTERNAL_ONLY;reason="only local conditional P-code; no PM backedge";}
      else{state=State.NO_CE;reason="missing conditional loop-end P-code";}
    }
   }
   discovered.add(new Loop(begin,end,expected,pm(end),owner,depth,state,reason));
  }
  return discovered;
 }
 private Register reg(String id){
  Register r=currentProgram.getProgramContext().getRegister(id);
  if(r==null)throw new IllegalStateException("Missing DSP analysis context register "+id);
  return r;
 }
 private void updateEnd(Loop l,Register ce,Register direct,Register dest)throws Exception{
  Address at=l.finish();
  currentProgram.getListing().clearCodeUnits(at,at,true);
  currentProgram.getProgramContext().setValue(ce,at,at,BigInteger.ONE);
  currentProgram.getProgramContext().setValue(direct,at,at,BigInteger.ONE);
  currentProgram.getProgramContext().setValue(dest,at,at,BigInteger.valueOf(l.start()+1));
  DisassembleCommand cmd=new DisassembleCommand(new AddressSet(at,at.add(2)),null,true);
  cmd.enableCodeAnalysis(false);
  if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Cannot recode "+at+": "+cmd.getStatusMsg());
  Instruction finished=currentProgram.getListing().getInstructionAt(at);
  if(finished==null)throw new IllegalStateException("Missing recoded CE "+at);
  boolean cb=false,matching=false;
  for(PcodeOp p:finished.getPcode()){
   if(p.getOpcode()==PcodeOp.CBRANCH)cb=true;
   if(p.getOpcode()==PcodeOp.BRANCH&&l.entry().equals(p.getInput(0).getAddress()))matching=true;
  }
  if(!cb||!matching)throw new IllegalStateException("Not a proven direct hardware backedge at "+at);
 }
 public void run() throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))
    throw new IllegalStateException("Not Sunplus SPHE Audio DSP");
  String[] args=getScriptArgs();
  String mode=args.length==0?"audit":args[0];
  if(args.length>1||(!mode.equals("audit")&&!mode.equals("apply-safe")))
    throw new IllegalArgumentException("audit (default) or apply-safe on an isolated saved GZF");
  // The resident wrapper has a different, image-scoped processing contract.
  // It must never be rewritten by the generic codec analyzer.
  if("srvdsp.bin".equals(currentProgram.getName()))
    throw new IllegalStateException("Resident wrapper requires SunplusSrvdspPostProcessor");
  List<Loop> loops=discover();
  EnumMap<State,Integer> counts=new EnumMap<>(State.class);
  Map<Function,List<Loop>> proposed=new LinkedHashMap<>();
  for(Loop l:loops){
   counts.merge(l.state(),1,Integer::sum);
   println("DSP_MODEL_LOOP entry="+pm(l.start())+" end="+l.finish()+" owner="+
     (l.owner()==null?"NONE":l.owner().getName())+" depth="+l.depth()+
     " status="+l.state()+" evidence="+l.reason());
   if(l.state()==State.NO_CE||l.state()==State.INTERNAL_ONLY)
     proposed.computeIfAbsent(l.owner(),key->new ArrayList<>()).add(l);
  }
  println("DSP_MODEL_PLAN program="+currentProgram.getName()+" functions="+
    currentProgram.getFunctionManager().getFunctionCount()+" native_DO="+loops.size()+
    " states="+counts+" eligible_loops="+proposed.values().stream().mapToInt(List::size).sum()+
    " eligible_owners="+proposed.size()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_MODEL_AUDIT_PASS");return;}
  if(proposed.isEmpty()){println("DSP_MODEL_APPLY_PASS changed=0");return;}
  if(counts.getOrDefault(State.WRONG_DIRECT,0)>0||counts.getOrDefault(State.INVALID,0)>0)
    throw new IllegalStateException("Invalid/wrong native DO endpoints: mutation prohibited");
  Register ce=reg("codec_ce_loop_end"),direct=reg("codec_ce_direct_backedge"),dest=reg("codec_ce_direct_start");
  String beforeFuncs=functions();byte[] beforeBytes=initializedSHA();
  DecompInterface d=new DecompInterface();
  if(!d.openProgram(currentProgram))throw new IllegalStateException("Decompiler init failed");
  Map<Function,String> beforeC=new LinkedHashMap<>();
  try{for(Function f:proposed.keySet())beforeC.put(f,c(d,f));}finally{d.dispose();}
  int tx=currentProgram.startTransaction("Architecture-derived safe codec DO CE recovery");
  boolean commit=false;int changed=0;
  try{
   for(var e:proposed.entrySet()){
    monitor.checkCancelled();
    for(Loop l:e.getValue()){updateEnd(l,ce,direct,dest);changed++;}
   }
   if(!Arrays.equals(initializedSHA(),beforeBytes)||!functions().equals(beforeFuncs))
    throw new IllegalStateException("Native PM/DM source bytes or function boundaries changed");
   DecompInterface verify=new DecompInterface();
   if(!verify.openProgram(currentProgram))throw new IllegalStateException("Decompiler reread failed");
   try{
    for(var item:beforeC.entrySet()){
     String prior=item.getValue(),after=c(verify,item.getKey());
     int oldDO=cLoops(prior),newDO=cLoops(after),n=itemCount(proposed.get(item.getKey()));
     int oldWarn=cWarnings(prior),newWarn=cWarnings(after);
     println("DSP_MODEL_OWNER_DIFF owner="+item.getKey().getEntryPoint()+
       " applied="+n+" C_do="+oldDO+"->"+newDO+
       " warnings="+oldWarn+"->"+newWarn);
     if(newDO<oldDO+n||newWarn>oldWarn||after.contains("halt_baddata()"))
       throw new IllegalStateException("Per-owner C/CFG gate failed for "+item.getKey().getEntryPoint());
    }
   }finally{verify.dispose();}
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);}
  if(!commit)throw new IllegalStateException("Atomic DSP architecture CE transaction rolled back");
  println("DSP_MODEL_APPLY_PASS changed="+changed+" owners="+proposed.size());
 }
 private int itemCount(List<Loop> list){return list==null?0:list.size();}
}
