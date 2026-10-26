//@category Sunplus/Audit
// Read-only: locate C no-return diagnostics and inspect true native RETURN
// provenance, callee flags, function boundaries, call sites and CE endpoints.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import java.util.*;
public class SunplusDSPWarningCallContractAudit extends GhidraScript {
 private record Span(int n,int returns,int returnPcode,int loops,int calls,int jumps) {}
 private Span nativeSpan(Function fn){int n=0,r=0,p=0,d=0,call=0,j=0;
  for(Instruction ins:currentProgram.getListing().getInstructions(fn.getBody(),true)){
   if(!"PM".equals(ins.getAddress().getAddressSpace().getName()))continue;
   n++;String text=ins.toString().toUpperCase(Locale.ROOT);
   if(text.equals("RTS")||text.endsWith(" RTS"))r++;
   if(text.startsWith("DO "))d++;
   if(ins.getFlowType().isCall())call++;
   if(ins.getFlowType().isJump())j++;
   for(PcodeOp op:ins.getPcode())if(op.getOpcode()==PcodeOp.RETURN)p++;
  }
  return new Span(n,r,p,d,call,j);
 }
 public void run()throws Exception{
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong DSP ISA");
  DecompInterface d=new DecompInterface();d.toggleCCode(true);d.setSimplificationStyle("decompile");
  if(!d.openProgram(currentProgram))throw new IllegalStateException("C backend unavailable");
  int warns=0,functions=0;Map<String,Integer> providers=new TreeMap<>();
  try{for(Function fn:currentProgram.getFunctionManager().getFunctions(true))if(!fn.isExternal()){
   monitor.checkCancelled();functions++;
   var result=d.decompileFunction(fn,30,monitor);if(!result.decompileCompleted()||result.getDecompiledFunction()==null)throw new IllegalStateException("C missing "+fn.getEntryPoint());
   String code=result.getDecompiledFunction().getC();int w=code.split("WARNING:",-1).length-1;
   if(w==0)continue;warns++;
   Span span=nativeSpan(fn);
   println("WARN_OWNER at="+fn.getEntryPoint()+" name="+fn.getName()+" nWarnings="+w+
     " noReturn="+fn.hasNoReturn()+" nativeSpan="+span+" body="+fn.getBody());
   int shown=0;
   for(Instruction ins:currentProgram.getListing().getInstructions(fn.getBody(),true)){
    if(!ins.getFlowType().isCall())continue;
    for(Address target:ins.getFlows()){
     Function callee=currentProgram.getFunctionManager().getFunctionAt(target);
     String key=callee==null?"UNRESOLVED":callee.getEntryPoint().toString();providers.merge(key,1,Integer::sum);
     if(shown++>=25)continue;
     println("WARN_CALL owner="+fn.getEntryPoint()+" site="+ins.getAddress()+" ins="+ins+
       " target="+target+" callee="+(callee==null?"NONE":callee.getName())+
       " callee_noReturn="+(callee==null?"UNKNOWN":callee.hasNoReturn())+
       " callee_native="+(callee==null?"NONE":nativeSpan(callee)));
    }
   }
  }}finally{d.dispose();}
  println("WARN_CALL_TOTAL program="+currentProgram.getName()+" funcs="+functions+" warnOwners="+warns+" providers="+providers);
  println("WARN_CALL_AUDIT_PASS");
 }
}
