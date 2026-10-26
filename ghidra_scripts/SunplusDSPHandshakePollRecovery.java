//@category Sunplus/Architecture
// Hardware-neutral classification of shared DM status polling.
// Only a native-proven store -> repeated read -> conditional PM backedge
// can qualify. This does NOT identify a physical peripheral or RAM owner.
// Guarded opt-in local-only apply-safe with exact executable SHA.
// A store-one/read-until-zero polling contract implies another actor may update
// the word, but its physical owner remains LIKELY/UNKNOWN, never CONFIRMED.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import java.security.MessageDigest;
import java.util.*;

public class SunplusDSPHandshakePollRecovery extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private static final String WARNING="WARNING: Do nothing block with infinite loop";
 private record Access(Address instruction,Address cell,int opcode,boolean direct) {}
 private record Candidate(Function owner,Address cell,Address poll,Address edge,
    MemoryBlock block,int beforeWarnings,String reason) {}
 private String c(DecompInterface d,Function f)throws Exception {
  DecompileResults result=d.decompileFunction(f,35,monitor);
  if(!result.decompileCompleted()||result.getDecompiledFunction()==null)
   throw new IllegalStateException("C not complete for "+f.getEntryPoint());
  return result.getDecompiledFunction().getC();
 }
 private int count(String s,String term){return s.split(java.util.regex.Pattern.quote(term),-1).length-1;}
 private Address dm(long wordAddress){
  AddressSpace space=currentProgram.getAddressFactory().getAddressSpace("DM");
  if(space==null||wordAddress<0||wordAddress>0xffff)
   throw new IllegalArgumentException("Invalid DM word address: "+wordAddress);
  // Native LOAD/STORE inputs are word addresses. AddressSpace.getAddress(long)
  // accepts a byte offset; omitting this conversion targets a different cell.
  long byteOffset=Math.multiplyExact(wordAddress,(long)space.getAddressableUnitSize());
  Address address=space.getAddress(byteOffset);
  if(address.getAddressableWordOffset()!=wordAddress)
   throw new IllegalStateException("DM word/byte conversion did not roundtrip");
  return address;
 }
 private AddressSpace dmSpace(){return currentProgram.getAddressFactory().getAddressSpace("DM");}
 private boolean sameAddress(Address a,Address b){return a!=null&&a.equals(b);}
 private List<Access> accesses(Function f) throws Exception {
  List<Access> out=new ArrayList<>();
  int id=dmSpace().getSpaceID();
  for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true)) {
   monitor.checkCancelled();
   if(!"PM".equals(ins.getAddress().getAddressSpace().getName()))continue;
   for(PcodeOp p:ins.getPcode()){
    int opcode=p.getOpcode();
    if(opcode!=PcodeOp.LOAD&&opcode!=PcodeOp.STORE)continue;
    boolean isDm=p.getNumInputs()>=2&&p.getInput(0).isConstant()&&p.getInput(0).getOffset()==id;
    boolean constant=isDm&&p.getInput(1).isConstant();
    int width=opcode==PcodeOp.LOAD?(p.getOutput()==null?0:p.getOutput().getSize()):
      (p.getNumInputs()<3?0:p.getInput(2).getSize());
    Address at=constant?dm(p.getInput(1).getOffset()):null;
    out.add(new Access(ins.getAddress(),at,opcode,constant&&width==2));
   }
  }
  return out;
 }
 private List<Candidate> find(Function f,String c) throws Exception {
  if(!c.contains(WARNING))return List.of();
  List<Access> all=accesses(f);
  Map<Address,List<Access>> reads=new LinkedHashMap<>(),writes=new LinkedHashMap<>();
  for(Access a:all){
   if(!a.direct()||a.cell()==null)continue;
   (a.opcode()==PcodeOp.LOAD?reads:writes)
    .computeIfAbsent(a.cell(),k->new ArrayList<>()).add(a);
  }
  List<Candidate> result=new ArrayList<>();
  for(var item:reads.entrySet()){
   Address cell=item.getKey();
   List<Access> previousWrites=writes.get(cell);
   if(previousWrites==null||previousWrites.isEmpty())continue;
   MemoryBlock block=currentProgram.getMemory().getBlock(cell);
   if(block==null||block.isInitialized()||block.isVolatile()||!block.isRead()||!block.isWrite())continue;
   if(cell.getAddressSpace().getAddressableUnitSize()!=2)continue;
   // A single unambiguous 16-bit cell must be contained in one block.
   if(!block.contains(cell)||!block.contains(cell.add(1)))continue;
   for(Access read:item.getValue()) {
    Instruction backedge=null;
    boolean ambiguous=false;
    long begin=read.instruction().getOffset();
    for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true)){
     if(!ins.getAddress().getAddressSpace().equals(read.instruction().getAddressSpace())||
        ins.getAddress().compareTo(read.instruction())<=0)continue;
     for(PcodeOp op:ins.getPcode()) {
      if(op.getOpcode()!=PcodeOp.CBRANCH||op.getNumInputs()<1)continue;
      Address dst=op.getInput(0).getAddress();
      if(dst.getAddressSpace().equals(read.instruction().getAddressSpace())&&
         dst.getOffset()<=begin&&dst.getOffset()>=begin-24){
       if(backedge!=null && !backedge.getAddress().equals(ins.getAddress()))
         ambiguous=true;
       else backedge=ins;
      }
     }
    }
    if(backedge==null||ambiguous)continue;
    boolean precedingWrite=false,unsafe=false;
    // Prove an earlier explicit status publication; reject any alias-capable
    // store inside the polling interval, including variable-address STOREs.
    for(Access write:previousWrites)
     if(write.instruction().compareTo(read.instruction())<0)precedingWrite=true;
    if(!precedingWrite)continue;
    for(Access a:all)if(a.opcode()==PcodeOp.STORE&&
        a.instruction().compareTo(read.instruction())>=0&&
        a.instruction().compareTo(backedge.getAddress())<=0&&
        (!a.direct()||sameAddress(a.cell(),cell)))unsafe=true;
    if(unsafe)continue;
    boolean mayCall=false;
    for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true))
     if(ins.getAddress().compareTo(read.instruction())>=0&&
        ins.getAddress().compareTo(backedge.getAddress())<=0&&
        (ins.getFlowType().isCall()||ins.getFlowType().isComputed()))mayCall=true;
    if(mayCall)continue;
    result.add(new Candidate(f,cell,read.instruction(),backedge.getAddress(),block,
       count(c,"WARNING:"),"explicit 16-bit status write before polling; repeated native read and conditional PM backedge"));
   }
  }
  // One unique native status word/loop, never choose arbitrarily.
  return result.size()==1?result:List.of();
 }
 private String inventory(){
  StringBuilder s=new StringBuilder();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   s.append(f.getEntryPoint()).append('/').append(f.getName()).append('/').append(f.getBody()).append('\n');
  return s.toString();
 }
 private byte[] firmware()throws Exception{
  MessageDigest d=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks())if(b.isInitialized()){
   Address p=b.getStart();long remaining=b.getSize();
   while(remaining>0){int n=(int)Math.min(buffer.length,remaining);
    if(currentProgram.getMemory().getBytes(p,buffer,0,n)!=n)throw new IllegalStateException("Memory changed: "+p);
    d.update(buffer,0,n);p=p.add(n);remaining-=n;
   }
  }
  return d.digest();
 }
 private void isolate(Candidate c)throws Exception{
  Memory m=currentProgram.getMemory();MemoryBlock block=m.getBlock(c.cell());
  // Earlier split operations may have replaced the original MemoryBlock;
  // revalidate exact current ownership and permissions at every cell.
  if(block==null||block.isVolatile()||block.isInitialized()||
     !block.isRead()||!block.isWrite())
    throw new IllegalStateException("DM region changed before apply: "+c.cell());
  Address end=c.cell().add(1);
  if(end.getAddressableWordOffset()!=c.cell().getAddressableWordOffset())
   throw new IllegalStateException("Unaligned 16-bit DM isolation: "+c.cell());
  Symbol previous=currentProgram.getSymbolTable().getPrimarySymbol(c.cell());
  String name=previous==null?null:previous.getName();
  SourceType source=previous==null?null:previous.getSource();
  if(!block.getStart().equals(c.cell()))m.split(block,c.cell());
  block=m.getBlock(c.cell());
  if(!block.getEnd().equals(end))m.split(block,end.add(1));
  block=m.getBlock(c.cell());
  if(!block.getStart().equals(c.cell())||!block.getEnd().equals(end)||block.isVolatile())
   throw new IllegalStateException("DM cell isolation failed: "+c.cell());
  block.setVolatile(true);
  block.setComment("LIKELY: shared asynchronous 16-bit status cell; firmware writes before native bounded polling, then rereads across a conditional PM backedge. Physical owner UNKNOWN.");
  Symbol after=currentProgram.getSymbolTable().getPrimarySymbol(c.cell());
  if((name==null)!=(after==null) || (name!=null&&
     (!name.equals(after.getName())||source!=after.getSource())))
   throw new IllegalStateException("Status cell original symbol lost: "+c.cell());
 }
 public void run()throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Not a Sunplus audio DSP program");
  String[] a=getScriptArgs();String mode=a.length==0?"audit":a[0];
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))
   throw new IllegalArgumentException("audit | apply-safe original-executable-SHA");
  if(mode.equals("audit")&&a.length>1)throw new IllegalArgumentException("Audit accepts no mutation arguments");
  if(mode.equals("apply-safe")&&(a.length!=2||!a[1].equals(currentProgram.getExecutableSHA256())))
   throw new IllegalArgumentException("Exact original executable SHA required for isolated GZF repair");
  if("srvdsp.bin".equals(currentProgram.getName()))
   throw new IllegalStateException("Resident DSP wrapper has separate memory ownership");
  if(dmSpace()==null||dmSpace().getAddressableUnitSize()!=2)
   throw new IllegalStateException("Expected 16-bit word-addressed DSP DM");
  List<Candidate> proposals=new ArrayList<>();
  DecompInterface before=new DecompInterface();
  if(!before.openProgram(currentProgram))throw new IllegalStateException("C unavailable");
  Map<Function,String> prior=new LinkedHashMap<>();
  try{
   for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
    monitor.checkCancelled();String code=c(before,f);prior.put(f,code);
    List<Candidate> cases=find(f,code);proposals.addAll(cases);
   }
  }finally{before.dispose();}
  Set<Address> cells=new TreeSet<>();
  for(Candidate c:proposals){
   println("DSP_POLL_CANDIDATE owner="+c.owner().getEntryPoint()+" DM="+c.cell()+
    " read="+c.poll()+" backedge="+c.edge()+" reason="+c.reason());
   cells.add(c.cell());
  }
  println("DSP_POLL_PLAN program="+currentProgram.getName()+" funcs="+prior.size()+
    " eligible_functions="+proposals.size()+" eligible_cells="+cells.size()+" mode="+mode);
  if(mode.equals("audit")){println("DSP_POLL_AUDIT_PASS");return;}
  if(proposals.isEmpty()){println("DSP_POLL_APPLY_PASS cells=0");return;}
  if(proposals.size()!=1||cells.size()!=1)
   throw new IllegalStateException("Shared-status side effect has multiple candidates; resolve separately");
  // The modification is a model of software-visible state effects, not proof
  // that any particular physical peripheral writes the cell.
  String names=inventory();byte[] bytes=firmware();
  int tx=currentProgram.startTransaction("Native-proven shared DM polling volatility");
  boolean commit=false;
  try{
   Set<Address> changed=new HashSet<>();
   for(Candidate candidate:proposals){
    monitor.checkCancelled();
    if(changed.add(candidate.cell()))isolate(candidate);
   }
   if(!names.equals(inventory())||!Arrays.equals(bytes,firmware()))
    throw new IllegalStateException("Code or function inventory changed");
   DecompInterface after=new DecompInterface();
   if(!after.openProgram(currentProgram))throw new IllegalStateException("Postcondition C unavailable");
   try{
    Set<Function> owners=new HashSet<>();
    for(Candidate x:proposals)owners.add(x.owner());
    for(var pair:prior.entrySet()){
     monitor.checkCancelled();
     Function fn=pair.getKey();String old=pair.getValue(),now=c(after,fn);
     int w0=count(old,"WARNING:"),w1=count(now,"WARNING:");
     int p0=count(old,WARNING),p1=count(now,WARNING);
     if(owners.contains(fn))
      println("DSP_POLL_C_DIFF owner="+fn.getEntryPoint()+" warnings="+w0+"->"+w1+
        " empty_spin="+p0+"->"+p1);
     if(w1>w0||now.contains("halt_baddata()")||
        count(now,"do {")<count(old,"do {")||
        (owners.contains(fn)&&p1>=p0))
      throw new IllegalStateException("Full-corpus C regression / no improvement for "+fn.getEntryPoint());
    }
   }finally{after.dispose();}
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);}
  if(!commit)throw new IllegalStateException("DM polling transaction rolled back");
  println("DSP_POLL_APPLY_PASS cells="+cells.size()+" owner_functions="+proposals.size());
 }
}
