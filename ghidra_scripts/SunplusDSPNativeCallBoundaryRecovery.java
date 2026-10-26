//@category Sunplus/Architecture
// Create only machine-code CALL-proven, decoded and currently unowned DSP function entries.
// No firmware offsets/filenames hardcoded. Original native code, old function
// identities and complete C must remain preserved. Operate on isolated GZF.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Reference;
import java.security.MessageDigest;
import java.util.*;
public class SunplusDSPNativeCallBoundaryRecovery extends GhidraScript {
 private byte[] firmware()throws Exception{
  var digest=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   Address a=block.getStart();long left=block.getSize();while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,buf.length);
    if(currentProgram.getMemory().getBytes(a,buf,0,n)!=n)throw new IllegalStateException("Native image read failure at "+a);
    digest.update(buf,0,n);a=a.add(n);left-=n;
   }
  }return digest.digest();
 }
 private Map<Address,String> priorFunctions(){
  Map<Address,String> result=new TreeMap<>();
  for(Function f:currentProgram.getFunctionManager().getFunctions(true))
   result.put(f.getEntryPoint(),f.getName()+"|"+f.getBody()+"|"+f.isThunk()+"|"+f.hasNoReturn());
  return result;
 }
 private String c(DecompInterface d,Function f)throws Exception{
  var result=d.decompileFunction(f,35,monitor);
  if(!result.decompileCompleted()||result.getDecompiledFunction()==null)
    throw new IllegalStateException("Analyzer C missing for "+f.getEntryPoint()+": "+result.getErrorMessage());
  String code=result.getDecompiledFunction().getC();if(code.isBlank())throw new IllegalStateException("Empty native C "+f.getEntryPoint());
  return code;
 }
 private int warnings(String code){return code.split("WARNING:",-1).length-1;}
 public void run()throws Exception{
  if(currentProgram==null||!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Native DSP language required");
  String[] argv=getScriptArgs();if(argv.length<3||argv.length>100)throw new IllegalArgumentException("mode SHA native-entries (1..98)");
  String mode=argv[0],expectedSHA=argv[1];if(!mode.equals("audit")&&!mode.equals("apply-safe"))throw new IllegalArgumentException("audit|apply-safe");
  if(!expectedSHA.equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Firmware identity mismatch");
  var fm=currentProgram.getFunctionManager();var listing=currentProgram.getListing();
  NavigableMap<Address,Integer> entries=new TreeMap<>();
  for(int i=2;i<argv.length;i++){
   if(!argv[i].matches("(?i)[0-9a-f]{4}"))throw new IllegalArgumentException("Native entry must be 4 hex words");
   Address a=currentProgram.getAddressFactory().getAddress("PM:"+argv[i]);
   if(entries.containsKey(a))throw new IllegalArgumentException("Duplicate native entry "+a);
   if(fm.getFunctionContaining(a)!=null)throw new IllegalStateException("Function ownership conflict "+a);
   Instruction opcode=listing.getInstructionAt(a);
   if(opcode==null||opcode.getLength()!=3)throw new IllegalStateException("Unrecognized instruction at native entry "+a);
   int calls=0;
   for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(a))if(ref.getReferenceType().isCall())calls++;
   if(calls<1)throw new IllegalStateException("Native entry without real CALL evidence "+a);
   entries.put(a,calls);
   println("NATIVE_CALL_PROOF entry="+a+" calls="+calls+" first="+opcode.toString());
  }
  int beforeCount=fm.getFunctionCount();
  println("NATIVE_CALL_PLAN program="+currentProgram.getName()+" oldFunctions="+beforeCount+
     " native_CALL_entries="+entries.size()+" targetFunctions="+(beforeCount+entries.size())+" mode="+mode);
  if(mode.equals("audit")){println("NATIVE_CALL_AUDIT_PASS");return;}
  byte[] raw=firmware();Map<Address,String> inventory=priorFunctions();int oldInstructionCount=0;
  for(Instruction i:listing.getInstructions(true))oldInstructionCount++;
  DecompInterface priorD=new DecompInterface();if(!priorD.openProgram(currentProgram))throw new IllegalStateException("Decompiler missing");
  Map<Address,Integer> oldWarn=new TreeMap<>();
  try{for(Function f:fm.getFunctions(true))if(!f.isExternal())oldWarn.put(f.getEntryPoint(),warnings(c(priorD,f)));}
  finally{priorD.dispose();}
  int tx=currentProgram.startTransaction("Native CALL verified DSP function boundary recovery");boolean commit=false;
  try{
   // Descending order prevents an earlier low-address entry from absorbing
   // a later unowned CALL entry during graph expansion.
   for(Address address:entries.descendingKeySet()){
    monitor.checkCancelled();if(fm.getFunctionContaining(address)!=null)throw new IllegalStateException("Consumed CALL target "+address);
    var cmd=new CreateFunctionCmd(address);
    if(!cmd.applyTo(currentProgram,monitor))throw new IllegalStateException("Ghidra function creation failed "+address+": "+cmd.getStatusMsg());
    Function f=fm.getFunctionAt(address);if(f==null||f.getBody().isEmpty())throw new IllegalStateException("Empty recovered action "+address);
    println("NATIVE_CALL_CREATED at="+address+" name="+f.getName()+" body="+f.getBody());
   }
   if(!Arrays.equals(raw,firmware()))throw new IllegalStateException("Firmware native words changed");
   Map<Address,String> next=priorFunctions();
   if(next.size()!=inventory.size()+entries.size()||fm.getFunctionCount()!=beforeCount+entries.size())
      throw new IllegalStateException("Wrong native C denominator "+next.size());
   for(var prev:inventory.entrySet())if(!prev.getValue().equals(next.get(prev.getKey())))
      throw new IllegalStateException("Original function identity/body changed "+prev.getKey());
   int newInstructions=0;for(Instruction i:listing.getInstructions(true))newInstructions++;
   if(newInstructions!=oldInstructionCount)throw new IllegalStateException("Instruction coverage changed");
   DecompInterface afterD=new DecompInterface();if(!afterD.openProgram(currentProgram))throw new IllegalStateException("C generator missing");
   int total=0,cOk=0,failed=0,warningLines=0,newFunctions=0;
   try{for(Function f:fm.getFunctions(true))if(!f.isExternal()){
     monitor.checkCancelled();total++;
     String generated=c(afterD,f);cOk++;int w=warnings(generated);warningLines+=w;
     Integer old=oldWarn.get(f.getEntryPoint());
     if(old==null){newFunctions++;println("NATIVE_CALL_NEW_C at="+f.getEntryPoint()+" C_chars="+generated.length()+" warnings="+w);}
     else if(w>old)throw new IllegalStateException("C warning regression in previously accepted function "+f.getEntryPoint()+": "+old+"->"+w);
     if(generated.contains("halt_baddata"))throw new IllegalStateException("Unsupported C generated at "+f.getEntryPoint());
   }}finally{afterD.dispose();}
   println("NATIVE_CALL_C_GATE total="+total+" C_ok="+cOk+" C_failed="+failed+" newFunctions="+newFunctions+" warningLines="+warningLines);
   if(total!=beforeCount+entries.size()||cOk!=total||newFunctions!=entries.size()||warningLines>0)
      throw new IllegalStateException("Complete native C acceptance failed");
   commit=true;
  }finally{currentProgram.endTransaction(tx,commit);println("NATIVE_CALL_TRANSACTION="+(commit?"COMMIT":"ROLLBACK"));}
  if(!commit)throw new IllegalStateException("Native function recovery not accepted");
  println("NATIVE_CALL_APPLY_PASS created="+entries.size()+" nativeTotal="+fm.getFunctionCount());
 }
}
