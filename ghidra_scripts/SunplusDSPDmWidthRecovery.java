//@category Sunplus/Architecture
// Architecture-driven 16-bit DM cell typing from Ghidra's OWN decompiled-C
// evidence of undersized global symbols. No firmware address lists, counts,
// profile-specific names, private GZF paths or arbitrary whole-DM mapping.
//
// audit (default): read-only planner.
// apply-safe: transactional metadata-only change on an isolated saved Ghidra
// program with independent backup; rejects user-defined non-undefined data,
// missing labels, unexpected sizes, overlaps, and any C/warning regression.
//
// Semantic caveat: a 16-bit DM word does NOT imply ownership RAM/MMIO or
// nonvolatile hardware behavior. This script never guesses these properties.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class SunplusDSPDmWidthRecovery extends GhidraScript {
 private static final Pattern UNDERSIZED =
   Pattern.compile("\\b_([a-zA-Z][a-zA-Z_0-9]*)\\b");
 private static final Pattern AUTO_DM =
   Pattern.compile("^DAT_DM_([0-9a-fA-F]{1,4})$");
 private static final String OVERLAP =
   "Globals starting with '_' overlap smaller symbols at the same address";
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private record Cell(Address address,Symbol label,String reason) {}
 private record Diff(int funcs,int successful,int warningFunctions,int overlapFunctions,
                     int semanticFunctions,int badDataFunctions,int doLoops) {}
 private Address dm(int w){return currentProgram.getAddressFactory().getAddress(String.format("DM:%04x",w));}
 private int word(Address a){return (int)(a.getOffset()/a.getAddressSpace().getAddressableUnitSize());}
 private String c(DecompInterface d,Function f){
  DecompileResults res=d.decompileFunction(f,25,monitor);
  return res.decompileCompleted()&&res.getDecompiledFunction()!=null
   ?res.getDecompiledFunction().getC():null;
 }
 private Diff summary(Map<Function,String> c){
  int funcs=0,successful=0,warns=0,aliases=0,semantics=0,bad=0,dos=0;
  for(String val:c.values()){
   funcs++;
   if(val==null)continue;
   successful++;boolean alias=false,semantic=false;
   for(String line:val.split("\n"))if(line.contains("WARNING:")){
    if(line.contains(OVERLAP))alias=true;else semantic=true;
   }
   if(alias||semantic)warns++;
   if(alias)aliases++;
   if(semantic)semantics++;
   if(val.contains("halt_baddata()"))bad++;
   dos+=val.split("do \\{",-1).length-1;
  }
  return new Diff(funcs,successful,warns,aliases,semantics,bad,dos);
 }
 private String funcs(){
  StringBuilder sb=new StringBuilder();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   sb.append(f.getEntryPoint()).append(':').append(f.getName()).append(':').append(f.getBody()).append('\n');
  return sb.toString();
 }
 private byte[] bytes()throws Exception {
  MessageDigest md=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
   if(!b.isInitialized())continue;
   long n=b.getSize();Address p=b.getStart();
   while(n>0){
    int k=(int)Math.min(n,buf.length);
    if(currentProgram.getMemory().getBytes(p,buf,0,k)!=k)
     throw new IllegalStateException("Unexpected raw native memory read "+p);
    md.update(buf,0,k);p=p.add(k);n-=k;
   }
  }return md.digest();
 }
 private Map<Function,String> decompileAll()throws Exception {
  Map<Function,String> result=new LinkedHashMap<>();
  DecompInterface d=new DecompInterface();
  try {
   d.toggleCCode(true);d.setSimplificationStyle("decompile");
   if(!d.openProgram(currentProgram))throw new IllegalStateException("Ghidra decompiler failed to initialize");
   for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
    monitor.checkCancelled();
    result.put(f,c(d,f));
   }
  }finally{d.dispose();}
  return result;
 }
 private Symbol resolve(String symbol){
  Matcher auto=AUTO_DM.matcher(symbol);
  if(auto.matches()){
   int w=Integer.parseInt(auto.group(1),16);
   Address at=dm(w);
   Symbol lbl=currentProgram.getSymbolTable().getPrimarySymbol(at);
   return lbl!=null && symbol.equals(lbl.getName())?lbl:null;
  }
  List<Symbol> symbols=currentProgram.getSymbolTable().getGlobalSymbols(symbol);
  if(symbols.size()!=1)return null;
  Symbol s=symbols.get(0);
  return "DM".equals(s.getAddress().getAddressSpace().getName())?s:null;
 }
 private SortedMap<Integer,Cell> infer(Map<Function,String> codes,int[] counts){
  SortedMap<Integer,Cell> evidence=new TreeMap<>();
  Set<String> unknown=new TreeSet<>();
  int affected=0;
  for(var e:codes.entrySet()){
   String text=e.getValue();
   if(text==null||!text.contains(OVERLAP))continue;
   affected++;
   Matcher m=UNDERSIZED.matcher(text);
   Set<String> names=new HashSet<>();
   while(m.find())names.add(m.group(1));
   for(String n:names){
    Symbol label=resolve(n);
    if(label==null){if(n.startsWith("DAT_DM_")||n.startsWith("g_")||n.startsWith("aux_"))unknown.add(n);continue;}
    Address at=label.getAddress();
    if(!"DM".equals(at.getAddressSpace().getName()))continue;
    int w=word(at);
    if(label.getSource()!=SourceType.DEFAULT && label.getSource()!=SourceType.USER_DEFINED &&
       label.getSource()!=SourceType.ANALYSIS){unknown.add(n);continue;}
    MemoryBlock mem=currentProgram.getMemory().getBlock(at);
    Data data=currentProgram.getListing().getDataContaining(at);
    // Only a previously undefined single-byte data element is safe.
    // Existing semantically typed user data or hardware owners are off limits.
    if(mem!=null&&(mem.isInitialized()||mem.isVolatile()||!mem.isRead()||!mem.isWrite())){
      unknown.add(n+":preexisting-memory-owner");continue;
    }
    if(data!=null && (data.getLength()!=1 || !data.getDataType().getName().equals("undefined"))){
      // An existing correctly typed word needs no repair.
      if(data.getAddress().equals(at) && data.getLength()==2)continue;
      unknown.add(n+":preexisting-data");continue;
    }
    if(evidence.containsKey(w)){
      if(!evidence.get(w).label().getName().equals(label.getName()))
       throw new IllegalStateException("Inconsistent DM aliases "+at);
    }else evidence.put(w,new Cell(at,label,e.getKey().getName()));
   }
  }
  // Some globals with size conflicts are optimized out of emitted C.
  // Recover ONLY when the native P-code itself proves a 2-byte constant-
  // addressed DM LOAD/STORE inside a function with an overlap warning.
  // This closes holes without resorting to firmware addresses or a whole-DM map.
  AddressSpace dmSpace=currentProgram.getAddressFactory().getAddressSpace("DM");
  int spaceId=dmSpace.getSpaceID(),pcodeInferred=0;
  for(var owner:codes.entrySet()){
   String text=owner.getValue();
   if(text==null||!text.contains(OVERLAP))continue;
   for(Instruction inst:currentProgram.getListing().getInstructions(owner.getKey().getBody(),true)){
    if(!"PM".equals(inst.getAddress().getAddressSpace().getName()))continue;
    for(PcodeOp op:inst.getPcode()){
     int code=op.getOpcode();
     if(code!=PcodeOp.LOAD && code!=PcodeOp.STORE)continue;
     if(op.getNumInputs()<2 || !op.getInput(0).isConstant() ||
        op.getInput(0).getOffset()!=spaceId || !op.getInput(1).isConstant())
      continue;
     int width=code==PcodeOp.LOAD
       ? (op.getOutput()==null?0:op.getOutput().getSize())
       : (op.getNumInputs()<3?0:op.getInput(2).getSize());
     if(width!=2)continue;
     long raw=op.getInput(1).getOffset();
     if(raw<0||raw>0xffff)continue;
     int w=(int)raw;
     if(evidence.containsKey(w))continue;
     Address at=dm(w);
     Symbol label=currentProgram.getSymbolTable().getPrimarySymbol(at);
     if(label==null||(label.getSource()!=SourceType.DEFAULT &&
         label.getSource()!=SourceType.USER_DEFINED &&
         label.getSource()!=SourceType.ANALYSIS))continue;
     MemoryBlock block=currentProgram.getMemory().getBlock(at);
     if(block!=null&&(block.isInitialized()||block.isVolatile()||
          !block.isRead()||!block.isWrite()))continue;
     Data data=currentProgram.getListing().getDataContaining(at);
     if(data!=null&&(data.getLength()!=1 ||
          !data.getDataType().getName().equals("undefined")))continue;
     evidence.put(w,new Cell(at,label,"native 2-byte DM P-code at "+inst.getAddress()));
     pcodeInferred++;
     println("DSP_DM_NATIVE_WORD_PROOF addr="+at+" owner="+owner.getKey().getEntryPoint()+
       " instruction="+inst.getAddress()+" operation="+PcodeOp.getMnemonic(code));
    }
   }
  }
  counts[3]=pcodeInferred;
  counts[0]=affected;counts[1]=unknown.size();counts[2]=0;
  for(Cell c:evidence.values())if(c.label().getSource()==SourceType.USER_DEFINED)counts[2]++;
  if(!unknown.isEmpty()){
   int shown=0;
   for(String s:unknown)if(shown++<12)println("DSP_DM_UNRESOLVED_SYMBOL "+s);
  }
  return evidence;
 }
 private void write(SortedMap<Integer,Cell> cells)throws Exception{
  Memory mem=currentProgram.getMemory();Listing listing=currentProgram.getListing();
  int i=0;List<Integer> absent=new ArrayList<>();
  for(var cell:cells.entrySet())if(mem.getBlock(cell.getValue().address())==null)absent.add(cell.getKey());
  while(i<absent.size()){
   int start=absent.get(i),end=start,j=i+1;
   while(j<absent.size()&&absent.get(j)==end+1){end=absent.get(j);j++;}
   MemoryBlock b=mem.createUninitializedBlock(
      String.format("DSP_DM_TYPED_%04x_%04x",start,end),dm(start),(long)(end-start+1)*2L,false);
   b.setRead(true);b.setWrite(true);
   b.setComment("Uninitialized 16-bit architectural DM words; owner/volatile status unproven");
   if(b.isInitialized()||b.getSize()!=(long)(end-start+1)*2L)
    throw new IllegalStateException("Unexpected Ghidra DM memory allocation "+b.getName());
   i=j;
  }
  for(Cell c:cells.values()){
   monitor.checkCancelled();Address at=c.address();
   String name=c.label().getName();SourceType source=c.label().getSource();
   Data data=listing.createData(at,Undefined2DataType.dataType);
   Symbol label=currentProgram.getSymbolTable().getPrimarySymbol(at);
   if(data==null||data.getLength()!=2||!data.getDataType().getName().equals("undefined2")||
       label==null||!name.equals(label.getName())||source!=label.getSource())
    throw new IllegalStateException("Preserved DM label/type postcondition failed "+at);
  }
 }
 @Override public void run()throws Exception {
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Not Sunplus Audio DSP");
  String[] args=getScriptArgs();
  String mode=args.length==0?"audit":args[0];
  if(args.length>1||(!mode.equals("audit")&&!mode.equals("apply-safe")))
   throw new IllegalArgumentException("audit (default) or apply-safe on private GZF only");
  AddressSpace dm=currentProgram.getAddressFactory().getAddressSpace("DM");
  if(dm==null||dm.getAddressableUnitSize()!=2)
   throw new IllegalStateException("16-bit DM architecture required");
  String inventory=funcs();byte[] source=bytes();
  Map<Function,String> before=decompileAll();
  Diff baseline=summary(before);int[] counts=new int[4];
  SortedMap<Integer,Cell> candidates=infer(before,counts);
  int blocks=0,absent=0;Integer last=null;
  for(int w:candidates.keySet()){
   if(currentProgram.getMemory().getBlock(dm(w))==null){
    if(last==null||w!=last+1)blocks++;
    last=w;absent++;
   }else last=null;
  }
  println("DSP_DM_PLAN program="+currentProgram.getName()+" funcs="+baseline.funcs()+
    " C_success="+baseline.successful()+" warning_functions="+baseline.warningFunctions()+
    " symbol_warning_functions="+baseline.overlapFunctions()+
    " semantic_warning_functions="+baseline.semanticFunctions()+
    " candidates="+candidates.size()+" native_pcode_proofs="+counts[3]+" user_labels="+counts[2]+
    " unrecognized_identifiers="+counts[1]+" missing_memory_words="+absent+
    " new_uninitialized_runs="+blocks+" mode="+mode);
  if(mode.equals("audit")){println("DSP_DM_AUDIT_PASS");return;}
  if(candidates.isEmpty()){println("DSP_DM_APPLY_PASS changed=0");return;}
  if(baseline.successful()!=baseline.funcs())
   throw new IllegalStateException("Cannot metadata-retype while C generation is incomplete");
  int tx=currentProgram.startTransaction("Architecture-derived DM word size correction");
  boolean commit=false;
  try{
   write(candidates);
   if(!Arrays.equals(source,bytes())||!inventory.equals(funcs()))
    throw new IllegalStateException("PM firmware initialized bytes/functions altered");
   Map<Function,String> after=decompileAll();
   Diff result=summary(after);
   println("DSP_DM_RESULT program="+currentProgram.getName()+" before="+baseline+" after="+result);
   if(result.successful()!=baseline.successful()||result.warningFunctions()>baseline.warningFunctions()||
      result.overlapFunctions()>=baseline.overlapFunctions()||
      result.semanticFunctions()>baseline.semanticFunctions()||
      result.badDataFunctions()>baseline.badDataFunctions()||
      result.doLoops()<baseline.doLoops())
     throw new IllegalStateException("Decompiler/C/CFG or warning postcondition failed, rollback");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);}
  if(!commit)throw new IllegalStateException("DM typing transaction rolled back");
  println("DSP_DM_APPLY_PASS words="+candidates.size()+" owners="+baseline.overlapFunctions());
 }
}
