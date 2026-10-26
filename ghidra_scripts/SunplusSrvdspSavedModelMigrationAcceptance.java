//@category Sunplus/Architecture
// Validates the canonical saved-program update path via SunplusSrvdspPostProcessor.
// apply: backed-up isolated GZF only; readback: no mutation. Preserves saved PM bytes,
// native functions, and all C; failures stop acceptance and prevent caller save.
import com.xebyte.core.SunplusSrvdspPostProcessor;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
public class SunplusSrvdspSavedModelMigrationAcceptance extends GhidraScript {
 private static final int[] WRAPPER={0x1823,0x183d,0x1842,0x1847,0x184e,0x1853,0x1854,0x1866,0x186b,0x186c,0x186e,0x1875,0x1878,0x1879,0x188c,0x188e,0x1890,0x1894};
 private byte[] source() throws Exception {
  MessageDigest sha=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   Address a=block.getStart();long remaining=block.getSize();while(remaining>0){
    monitor.checkCancelled();int n=(int)Math.min(buffer.length,remaining);
    if(currentProgram.getMemory().getBytes(a,buffer,0,n)!=n)throw new IllegalStateException("Unreadable native image");
    sha.update(buffer,0,n);a=a.add(n);remaining-=n;
   }
  }return sha.digest();
 }
 private String functions(){StringBuilder s=new StringBuilder();for(Function f:currentProgram.getFunctionManager().getFunctions(true))
  s.append(f.getEntryPoint()).append('/').append(f.getBody()).append('/').append(f.getName()).append('/').append(f.isThunk()).append('\n');return s.toString();}
 private int instructions(){int n=0;for(Instruction i:currentProgram.getListing().getInstructions(true))
  if("PM".equals(i.getAddress().getAddressSpace().getName()))n++;return n;}
 public void run()throws Exception{
  if(!"srvdsp.bin".equals(currentProgram.getName()) || !SunplusSrvdspPostProcessor.LANGUAGE_ID.equals(currentProgram.getLanguageID().getIdAsString()))
   throw new IllegalStateException("Unexpected native processor/module");
  String[] argv=getScriptArgs();String mode=argv.length==1?argv[0]:"readback";
  if(!mode.equals("apply")&&!mode.equals("readback"))throw new IllegalArgumentException("apply | readback");
  if(currentProgram.getFunctionManager().getFunctionCount()!=9)throw new IllegalStateException("Non-canonical function corpus");
  byte[] priorBytes=source();String names=functions();int originalInstructions=instructions();
  int before=currentProgram.getOptions("Sunplus SPHE Audio DSP").getInt("srvdsp.analysis_model_version",0);
  if(mode.equals("apply")){
    SunplusSrvdspPostProcessor.Result prepared=SunplusSrvdspPostProcessor.prepare(currentProgram,monitor);
    if(!prepared.applicable()||prepared.handlerCount()!=9)throw new IllegalStateException("Processor postprocessor did not accept saved wrapper");
  }
  if(!Arrays.equals(priorBytes,source())||!names.equals(functions())||originalInstructions!=instructions())
    throw new IllegalStateException("Original bytes/function names/bodies/instructions changed");
  int after=currentProgram.getOptions("Sunplus SPHE Audio DSP").getInt("srvdsp.analysis_model_version",0);
  if(after!=SunplusSrvdspPostProcessor.ANALYSIS_MODEL_VERSION)throw new IllegalStateException("Stale model version "+after);
  Register wrapperMode=currentProgram.getRegister("srvdsp_wrapper_mode");
  if(wrapperMode==null)throw new IllegalStateException("DSP context missing");
  for(int w:WRAPPER){Address a=currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",w));
    if(!BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(wrapperMode,a,false)))
      throw new IllegalStateException("Saved wrapper context missing at "+a);
    if(currentProgram.getListing().getInstructionAt(a)==null)
      throw new IllegalStateException("Saved wrapper instruction disappeared at "+a);
  }
  DecompInterface dc=new DecompInterface();dc.toggleCCode(true);dc.setSimplificationStyle("decompile");
  if(!dc.openProgram(currentProgram))throw new IllegalStateException("C backend unavailable");
  int nativeTotal=0,cOk=0,warnings=0,bad=0;
  try{for(Function f:currentProgram.getFunctionManager().getFunctions(true))if(!f.isExternal()){
    monitor.checkCancelled();nativeTotal++;
    DecompileResults result=dc.decompileFunction(f,30,monitor);
    if(!result.decompileCompleted()||result.getDecompiledFunction()==null)continue;
    String code=result.getDecompiledFunction().getC();cOk++;
    warnings+=code.split("WARNING:",-1).length-1;
    if(code.contains("halt_baddata"))bad++;
  }}finally{dc.dispose();}
  println("SRVDSP_SAVED_MODEL mode="+mode+" model="+before+"->"+after+" native="+nativeTotal+
    " C_ok="+cOk+" warnings="+warnings+" bad="+bad+" original_instructions="+originalInstructions+" wrapper_sites="+WRAPPER.length);
  if(nativeTotal!=9||cOk!=9||warnings!=0||bad!=0)throw new IllegalStateException("Saved wrapper acceptance failed");
  println("SRVDSP_SAVED_MODEL_PASS mode="+mode);
 }
}
