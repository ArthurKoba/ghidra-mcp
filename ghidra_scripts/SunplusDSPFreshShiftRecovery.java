//@category Sunplus/Architecture
// Refresh only native immediate-shift P-code proven stale against current SLEIGH.
// No PM addresses, module names, absolute ISA offsets, or C-warning suppressions.
// Read-only audit by default; apply-safe is restricted to an isolated saved GZF
// and requires the original executable SHA plus complete no-regression native C.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class SunplusDSPFreshShiftRecovery extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private static final Pattern SHIFT=Pattern.compile("\\b(LSHIFT|ASHIFT)\\b[^\\n]*\\bBY\\s+(-?0x[0-9a-f]+)\\s+\\((HI|LO)\\)",Pattern.CASE_INSENSITIVE);
 private record NativeShift(Address at,byte[] encoded,String text,String original,String updated,
    String owner,boolean negative,boolean arithmetic) {}
 private boolean has(PcodeOp[] code,int mnemonic){for(PcodeOp op:code)if(op.getOpcode()==mnemonic)return true;return false;}
 private String pcode(Instruction i){StringBuilder b=new StringBuilder();for(PcodeOp op:i.getPcode())b.append(op.toString()).append(';');return b.toString();}
 private String error(Function f,Exception exception){return f.getEntryPoint()+": "+exception;}
 private PseudoInstruction parseFresh(Instruction i)throws Exception{
  Language language=currentProgram.getLanguage();byte[] raw=i.getBytes();
  var buffer=new ByteMemBufferImpl(i.getAddress(),raw,true);
  ProcessorContextImpl context=new ProcessorContextImpl(language);
  for(Register reg:language.getContextRegisters()){
   var value=currentProgram.getProgramContext().getValue(reg,i.getAddress(),false);
   if(value!=null)context.setValue(reg,value);
  }
  var prototype=language.parse(buffer,context,false);
  return new PseudoInstruction(currentProgram.getAddressFactory(),i.getAddress(),prototype,buffer,context);
 }
 private List<NativeShift> candidates()throws Exception {
  List<NativeShift> changes=new ArrayList<>();
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();
   if(!i.getAddress().getAddressSpace().getName().equals("PM")||i.getLength()!=3)continue;
   Matcher m=SHIFT.matcher(i.toString());if(!m.find())continue;
   byte[] raw=i.getBytes();int signed=(byte)raw[2];
   String literal=m.group(2);int visible=literal.startsWith("-")?
       -Integer.parseInt(literal.substring(3),16):Integer.parseInt(literal.substring(2),16);
   if(signed!=visible)throw new IllegalStateException("Native signed shift amount does not match original instruction "+i.getAddress());
   PseudoInstruction fresh=parseFresh(i);
   if(!Arrays.equals(fresh.getBytes(),raw)||!i.toString().equals(fresh.toString()))
    throw new IllegalStateException("Current SLEIGH changed native instruction identity "+i.getAddress());
   String old=pcode(i),next=pcode(fresh);
   if(old.equals(next))continue;
   boolean negative=visible<0,arithmetic=m.group(1).equalsIgnoreCase("ASHIFT");
   PcodeOp[] original=i.getPcode(),now=fresh.getPcode();
   if(negative){
    if(!has(original,PcodeOp.INT_LEFT)||!has(now,arithmetic?PcodeOp.INT_SRIGHT:PcodeOp.INT_RIGHT))
     throw new IllegalStateException("Negative shift is not a proven left-to-right correction "+i.getAddress());
   } else {
    if(!(has(original,PcodeOp.INT_RIGHT)||has(original,PcodeOp.INT_SRIGHT))||
       !has(now,PcodeOp.INT_LEFT)||has(now,PcodeOp.INT_RIGHT)||has(now,PcodeOp.INT_SRIGHT))
     throw new IllegalStateException("Positive shift is not a proven right-to-left correction "+i.getAddress());
   }
   var owner=currentProgram.getFunctionManager().getFunctionContaining(i.getAddress());
   changes.add(new NativeShift(i.getAddress(),raw,i.toString(),old,next,
      owner==null?"UNKNOWN":owner.getEntryPoint().toString(),negative,arithmetic));
  }
  if(changes.size()>600)throw new IllegalStateException("Unbounded native shift parser discrepancy count");
  return changes;
 }
 private byte[] originalImageDigest()throws Exception {
  var md=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   Address at=block.getStart();long count=block.getSize();
   while(count>0){monitor.checkCancelled();int n=(int)Math.min(count,buffer.length);
    if(currentProgram.getMemory().getBytes(at,buffer,0,n)!=n)throw new IllegalStateException("Source native memory unreadable "+at);
    md.update(buffer,0,n);at=at.add(n);count-=n;
   }
  }
  return md.digest();
 }
 private String functionIdentity(){
  var result=new StringBuilder();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   result.append(f.getEntryPoint()).append('|').append(f.getBody()).append('|').append(f.getName()).append('|').append(f.isThunk()).append('\n');
  return result.toString();
 }
 private int countNativeInstructions(){int n=0;for(Instruction i:currentProgram.getListing().getInstructions(true))
  if(i.getAddress().getAddressSpace().getName().equals("PM"))n++;return n;}
 private String c(DecompInterface d,Function f)throws Exception{
  var r=d.decompileFunction(f,27,monitor);
  if(!r.decompileCompleted()||r.getDecompiledFunction()==null)throw new IllegalStateException("Native C missing "+f.getEntryPoint()+" "+r.getErrorMessage());
  String result=r.getDecompiledFunction().getC();if(result.isBlank())throw new IllegalStateException("Native C empty "+f.getEntryPoint());
  return result;
 }
 private int warnings(String c){return c.split("WARNING:",-1).length-1;}
 public void run()throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Not a native Sunplus DSP");
  String[] args=getScriptArgs();String mode=args.length==0?"audit":args[0];
  if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("Use audit or apply-safe");
  if(mode.equals("apply-safe")&&(args.length!=2||!args[1].equals(currentProgram.getExecutableSHA256())))
   throw new IllegalArgumentException("Apply needs exact source executable SHA");
  boolean originallyChanged=currentProgram.isChanged();int savedVersion=currentProgram.getDomainFile().getVersion();
  List<NativeShift> stale=candidates();int positive=0,negative=0,unowned=0;
  var owners=new TreeMap<String,Integer>();
  for(NativeShift entry:stale){
   if(entry.negative())negative++;else positive++;
   if(entry.owner().equals("UNKNOWN"))unowned++;else owners.merge(entry.owner(),1,Integer::sum);
  }
  var nativeTotal=0;
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal())nativeTotal++;
  println("DSP_FRESH_SHIFT_PLAN program="+currentProgram.getName()+" native_total="+nativeTotal+
    " stale_shift_pcode="+stale.size()+" positive="+positive+" negative="+negative+
    " unowned="+unowned+" affected_functions="+owners.size()+" mode="+mode);
  for(var e:owners.entrySet())println("DSP_FRESH_SHIFT_OWNER owner="+e.getKey()+" stale_native_shifts="+e.getValue());
  if(mode.equals("audit")){
   if(originallyChanged!=currentProgram.isChanged()||savedVersion!=currentProgram.getDomainFile().getVersion())
    throw new IllegalStateException("Audit unexpectedly modified saved program");
   println("DSP_FRESH_SHIFT_AUDIT_PASS");return;
  }
  if(stale.isEmpty()){println("DSP_FRESH_SHIFT_APPLY_PASS changed=0");return;}
  byte[] before=originalImageDigest();String inventory=functionIdentity();int beforeInstructions=countNativeInstructions();
  var manager=currentProgram.getFunctionManager();
  DecompInterface old=new DecompInterface();if(!old.openProgram(currentProgram))throw new IllegalStateException("Baseline C unavailable");
  Map<Function,Integer> originalC=new LinkedHashMap<>();int ownersBefore=0;
  try{
   for(Function f:manager.getFunctions(true))if(!f.isExternal()){
    int warning=warnings(c(old,f));originalC.put(f,warning);if(warning>0)ownersBefore++;
   }
  }finally{old.dispose();}
  if(originalC.size()!=nativeTotal)throw new IllegalStateException("Native C coverage baseline is incomplete");
  var listing=currentProgram.getListing();int tx=currentProgram.startTransaction("Byte-proven fresh Sunplus positive/negative shift SLEIGH Pcode repair");
  boolean commit=false;
  try{
   for(NativeShift shift:stale){
    monitor.checkCancelled();Instruction i=listing.getInstructionAt(shift.at());
    if(i==null||!i.toString().equals(shift.text())||!Arrays.equals(i.getBytes(),shift.encoded())||!pcode(i).equals(shift.original()))
     throw new IllegalStateException("Cached shift evidence changed before re-decode "+shift.at());
    Address at=shift.at();listing.clearCodeUnits(at,at.add(2),true);
    var cmd=new DisassembleCommand(new AddressSet(at,at.add(2)),null,true);cmd.enableCodeAnalysis(false);
    if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Native DSP instruction decode failed "+at+" "+cmd.getStatusMsg());
    Instruction newer=listing.getInstructionAt(at);
    if(newer==null||!Arrays.equals(newer.getBytes(),shift.encoded())||!newer.toString().equals(shift.text())||
       !shift.updated().equals(pcode(newer)))throw new IllegalStateException("Fresh native Pcode doesn't match current SLEIGH "+at);
   }
   if(!Arrays.equals(before,originalImageDigest())||!inventory.equals(functionIdentity())||countNativeInstructions()!=beforeInstructions)
    throw new IllegalStateException("Original DSP native image, functions or instruction inventory mutated");
   DecompInterface check=new DecompInterface();if(!check.openProgram(currentProgram))throw new IllegalStateException("Post-C backend unavailable");
   int warningsAfter=0,regressions=0,improvements=0,warnLines=0;
   try{
    for(var item:originalC.entrySet()){
     monitor.checkCancelled();Function f=item.getKey();int beforeWarn=item.getValue();String code=c(check,f);int afterWarn=warnings(code);
     if(afterWarn>0)warningsAfter++;warnLines+=afterWarn;
     if(afterWarn<beforeWarn){improvements++;println("DSP_FRESH_SHIFT_C_DIFF owner="+f.getEntryPoint()+" warnings="+beforeWarn+"->"+afterWarn);}
     if(afterWarn>beforeWarn||code.contains("halt_baddata()")){
      regressions++;println("DSP_FRESH_SHIFT_C_REGRESSION owner="+f.getEntryPoint()+" warnings="+beforeWarn+"->"+afterWarn);
     }
    }
   }finally{check.dispose();}
   println("DSP_FRESH_SHIFT_C_SUMMARY program="+currentProgram.getName()+" native_total="+nativeTotal+
      " C_ok="+originalC.size()+" C_failed=0 warning_owners="+ownersBefore+"->"+warningsAfter+
      " corrected_native_words="+stale.size()+" improved_functions="+improvements+
      " regressions="+regressions+" remaining_warning_lines="+warnLines);
   if(regressions!=0||warningsAfter>ownersBefore)
    throw new IllegalStateException("Fresh shift semantics introduced native C regressions");
   currentProgram.getOptions("RUSH DSP Fresh Shift Pcode").setString("Acceptance",
     "CONFIRMED-STATIC image="+currentProgram.getExecutableSHA256()+" shifts="+stale.size()+
     " positive="+positive+" negative="+negative+" C_ok="+nativeTotal+
     " warning_owners="+ownersBefore+"->"+warningsAfter+" hardware execution UNKNOWN");
   commit=true;
  }finally{
   currentProgram.endTransaction(tx,commit);
   println("DSP_FRESH_SHIFT_TRANSACTION="+(commit?"COMMITTED_ISOLATED":"ROLLED_BACK"));
  }
  if(!commit)throw new IllegalStateException("Entire native fresh shift transaction rolled back");
  println("DSP_FRESH_SHIFT_APPLY_PASS changed="+stale.size()+" native_C="+nativeTotal);
 }
}
