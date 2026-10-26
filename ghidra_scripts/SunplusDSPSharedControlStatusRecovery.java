//@category Sunplus/Architecture
// Bounded nativeTotal evidence for asynchronously mutable DSP DM control words.
// Program -> bounded native repeated status read/write -> possible external shared state.
// Supports DSP shared status region DM:3c00..3fff; does not assume hardware owner.
// LIKELY external consumer: source ISA and ABI do not by themselves prove
// actual chip peripherals. No blanket DM volatility or false C suppression.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.security.MessageDigest;
import java.util.*;
public class SunplusDSPSharedControlStatusRecovery extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private String c(DecompInterface d,Function f)throws Exception{
  var r=d.decompileFunction(f,26,monitor);
  if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
   throw new IllegalStateException("Native C missing "+f.getEntryPoint()+": "+r.getErrorMessage());
  return r.getDecompiledFunction().getC();
 }
 private int warnings(String s){return s.split("WARNING:",-1).length-1;}
 private byte[] hash()throws Exception{
  var md=MessageDigest.getInstance("SHA-256");byte[] bytes=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   Address at=block.getStart();long left=block.getSize();
   while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,bytes.length);
    if(currentProgram.getMemory().getBytes(at,bytes,0,n)!=n)throw new IllegalStateException("Native memory unavailable");
    md.update(bytes,0,n);at=at.add(n);left-=n;
   }
  }
  return md.digest();
 }
 private String nativeFunctions(){var out=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  out.append(f.getEntryPoint()).append('/').append(f.getBody()).append('/').append(f.getName()).append('\n');return out.toString();}
 private int countInstructions(){int n=0;for(Instruction i:currentProgram.getListing().getInstructions(true))
  if(i.getAddress().getAddressSpace().getName().equals("PM"))n++;return n;}
 public void run()throws Exception {
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong DSP ISA");
  String[] args=getScriptArgs();if(args.length<2||args.length>3)throw new IllegalArgumentException("audit|apply-safe DM:xxxx [original source SHA]");
  String mode=args[0];if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit or apply-safe");
  if(mode.equals("apply-safe")&&(args.length!=3||!args[2].equals(currentProgram.getExecutableSHA256())))
   throw new IllegalArgumentException("Native source SHA required before persistent annotation");
  Address mmio=toAddr(args[1]);
  if(mmio==null||!mmio.getAddressSpace().getName().equals("DM")||
     mmio.getAddressableWordOffset()<0x3c00||mmio.getAddressableWordOffset()>0x3fff)
   throw new IllegalArgumentException("Scoped DSP control register is outside nativeTotal shared-status aperture");
  MemoryBlock block=currentProgram.getMemory().getBlock(mmio);
  if(block==null||!block.contains(mmio)||
     !block.isRead()||!block.isWrite()||block.isVolatile())
   throw new IllegalStateException("Shared status cell is not writable nonvolatile DM memory");
  var listing=currentProgram.getListing();int reads=0,writes=0;
  String suffix="0X"+Long.toHexString(mmio.getAddressableWordOffset()).toUpperCase(Locale.ROOT);
  for(Instruction ins:listing.getInstructions(true)){
   if(!ins.getAddress().getAddressSpace().getName().equals("PM"))continue;
   String text=ins.toString().trim().toUpperCase(Locale.ROOT);
   if(text.startsWith("DMREAD ")&&text.endsWith(","+suffix))reads++;
   if(text.startsWith("DMWRITE "+suffix+","))writes++;
  }
  if(reads<2||writes<2)throw new IllegalStateException("Native code lacks repeated read/write to shared status");
  int verifiedLoops=0;int nativeLoopEndpoints=0;int reported=0;
  var fm=currentProgram.getFunctionManager();
  for(Instruction ins:listing.getInstructions(true)){
   // DSP status loops normally use an IF-branch back to a repeated DMREAD.
   // Reject computed/invalid transfers, but retain conditionally taken native
   // backedges; an unconditional transfer is not a necessary polling witness.
   if(!ins.getAddress().getAddressSpace().getName().equals("PM")||
      !ins.getFlowType().isJump()||ins.getFlowType().isComputed())continue;
   Address[] dest=ins.getFlows();if(dest.length!=1||!dest[0].getAddressSpace().getName().equals("PM"))continue;
   int delta=(int)(ins.getAddress().getAddressableWordOffset()-dest[0].getAddressableWordOffset());
   if(delta<2||delta>16)continue;
   nativeLoopEndpoints++;
   boolean readInside=false,writeInside=false;
   for(int i=0;i<=delta;i++){
    // PM is word-addressed but each native instruction occupies three
    // executable bytes. Address.add(i) samples the interiors of opcodes;
    // advance by the actual native instruction length instead.
    Address cursor=dest[0].add(i*3L);
    if(cursor.compareTo(ins.getAddress())>0)break;
    Instruction body=listing.getInstructionAt(cursor);
    if(body==null||body.getLength()!=3)break;
    String text=body.toString().trim().toUpperCase(Locale.ROOT);
    if(text.startsWith("DMREAD ")&&text.endsWith(","+suffix))readInside=true;
    if(text.startsWith("DMWRITE "+suffix+","))writeInside=true;
   }
   // Earlier writes by the same function may publish a command and then
   // poll the cell until a separate software/resident actor clears it.
   boolean priorStore=false;Function loopOwner=fm.getFunctionContaining(ins.getAddress());
   if(loopOwner!=null){
    for(Instruction precursor:listing.getInstructions(loopOwner.getBody(),true)){
     if(precursor.getAddress().compareTo(dest[0])>=0)break;
     if(precursor.getAddress().compareTo(dest[0].subtract(0x60*3L))<0)continue;
     String t=precursor.toString().trim().toUpperCase(Locale.ROOT);
     if(t.startsWith("DMWRITE "+suffix+","))priorStore=true;
    }
   }
   if((readInside||writeInside)&&reported++<24)println("DSP_MMIO_LOOP_CANDIDATE start="+dest[0]+
      " end="+ins.getAddress()+" span="+delta+" native_read="+readInside+" native_write="+writeInside+" preceding_native_store="+priorStore+
      " branch="+ins.toString()+" conditional="+ins.getFlowType().isConditional()+" source_owner="+currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress()));
   if(readInside&&(writeInside||priorStore)){verifiedLoops++;println("DSP_MMIO_POLLING_NATIVE_EVIDENCE loop="+dest[0]+".."+ins.getAddress()+" MMR="+mmio);}
  }
  if(verifiedLoops==0)throw new IllegalStateException("No native write-then-poll or readwrite-loop witness");
  int nativeTotal=0;for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal())nativeTotal++;
  println("DSP_MMIO_PROVEN_PLAN program="+currentProgram.getName()+" nativeTotal="+nativeTotal+
    " MMR="+mmio+" reads="+reads+" writes="+writes+" readwrite_cycles="+verifiedLoops+
    " other_native_loops="+nativeLoopEndpoints+" mode="+mode+
    " hardware_provider=UNKNOWN");
  if(mode.equals("audit")){println("DSP_MMIO_PROVEN_AUDIT_PASS");return;}
  byte[] raw=hash();String fns=nativeFunctions();int instructions=countInstructions();
  Map<Function,Integer> before=new LinkedHashMap<>();int warningsBefore=0;
  DecompInterface baseline=new DecompInterface();if(!baseline.openProgram(currentProgram))throw new IllegalStateException("C baseline unavailable");
  try{for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal()){
    int w=warnings(c(baseline,f));before.put(f,w);if(w>0)warningsBefore++;
  }}finally{baseline.dispose();}
  if(before.size()!=nativeTotal)throw new IllegalStateException("Native C coverage incomplete");
  int tx=currentProgram.startTransaction("Scoped nativeTotal DSP MMIO register asynchronous side effects");boolean accept=false;
  try{
   // Separate exactly one DSP-DM addressable word. Typed DM blocks may
   // cover multiple addresses; do not mark neighboring MMRs volatile.
   Memory mem=currentProgram.getMemory();
   MemoryBlock selected=mem.getBlock(mmio);
   if(!selected.getStart().equals(mmio)){
    mem.split(selected,mmio);selected=mem.getBlock(mmio);
   }
   Address wordEnd=mmio.add(1);
   if(wordEnd.getAddressableWordOffset()!=mmio.getAddressableWordOffset())
    throw new IllegalStateException("Invalid 16-bit DSP DM word mapping");
   if(selected.getEnd().compareTo(wordEnd)>0){
    mem.split(selected,wordEnd.add(1));selected=mem.getBlock(mmio);
   }
   if(!selected.getStart().equals(mmio)||!selected.getEnd().equals(wordEnd)||selected.getSize()!=2)
    throw new IllegalStateException("Volatile annotation must isolate exactly one 16-bit DM word");
   selected.setVolatile(true);
   if(!selected.isVolatile())throw new IllegalStateException("MMIO volatility not applied");
   if(!Arrays.equals(raw,hash())||!fns.equals(nativeFunctions())||instructions!=countInstructions())
    throw new IllegalStateException("Native machine words, function boundaries or instructions changed");
   DecompInterface after=new DecompInterface();if(!after.openProgram(currentProgram))throw new IllegalStateException("C after side effects unavailable");
   int warningOwners=0,improved=0,regressed=0,lines=0;
   try{for(var e:before.entrySet()){
    monitor.checkCancelled();String code=c(after,e.getKey());int next=warnings(code),prev=e.getValue();
    if(next>0)warningOwners++;lines+=next;
    if(next<prev){improved++;println("DSP_MMIO_PROVEN_C_DIFF owner="+e.getKey().getEntryPoint()+" warnings="+prev+"->"+next);}
    if(next>prev||code.contains("halt_baddata()")){
     regressed++;println("DSP_MMIO_PROVEN_C_REGRESSION owner="+e.getKey().getEntryPoint()+" warnings="+prev+"->"+next);}
   }}finally{after.dispose();}
   println("DSP_MMIO_PROVEN_C_SUMMARY nativeTotal="+nativeTotal+" C_ok="+before.size()+" C_failed=0"+
     " warning_owners="+warningsBefore+"->"+warningOwners+
     " improved="+improved+" regressed="+regressed+" remaining_warning_lines="+lines);
   if(regressed!=0||warningOwners>=warningsBefore||improved==0)
    throw new IllegalStateException("MMIO static side effect annotation did not improve nativeTotal C");
   currentProgram.getOptions("RUSH DSP MMIO Volatility").setString("Static acceptance "+mmio,
    "LIKELY SHARED STATUS WORD image="+currentProgram.getExecutableSHA256()+
    " control="+mmio+" native_reads="+reads+" native_writes="+writes+
    " readwrite_cycles="+verifiedLoops+" C_ok="+nativeTotal+
    " warning_owners="+warningsBefore+"->"+warningOwners+" hardware/external provider=UNKNOWN");
   accept=true;
  }finally{currentProgram.endTransaction(tx,accept);println("DSP_MMIO_PROVEN_TRANSACTION="+(accept?"COMMITTED_ISOLATED":"ROLLED_BACK"));}
  if(!accept)throw new IllegalStateException("Scoped nativeTotal MMIO annotation rolled back");
  println("DSP_MMIO_PROVEN_APPLY_PASS nativeTotal="+nativeTotal+" memory_word="+mmio);
 }
}
