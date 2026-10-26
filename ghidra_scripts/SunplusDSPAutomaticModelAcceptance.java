//@category Sunplus/Verification
// One broad, read-only acceptance for the installed processor auto-analyzer.
// No synthetic C, and no program modifications. Works across all saved profiles.
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import java.util.*;
public class SunplusDSPAutomaticModelAcceptance extends GhidraScript {
 private static final String ANALYZER_NAME="Sunplus DSP Native DO/CE Flow";
 private static final String LANGUAGE="SunplusSPHEAudioDSP:BE:16:default";
 public void run() throws Exception {
  String[] args=getScriptArgs();if(args.length!=1||!LANGUAGE.equals(currentProgram.getLanguageID().getIdAsString())||
   !args[0].equals(currentProgram.getExecutableSHA256())||currentProgram.isChanged())
      throw new IllegalArgumentException("Read-only original Sunplus DSP source SHA required");
  int version=currentProgram.getDomainFile().getVersion();int nativeFns=currentProgram.getFunctionManager().getFunctionCount();
  Analyzer found=null;int analyzers=0;
  for(Analyzer analyzer:ClassSearcher.getInstances(Analyzer.class)){
   analyzers++;
   if(ANALYZER_NAME.equals(analyzer.getName())){
      if(found!=null)throw new IllegalStateException("Multiple matching architecture analyzers");
      found=analyzer;
   }
  }
  if(found==null||!found.canAnalyze(currentProgram))throw new IllegalStateException("Architecture analyzer not discovered in installed Ghidra extension");
  var props=currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
  String enabled="UNINITIALIZED";
  if(props.getOptionNames().contains(ANALYZER_NAME))enabled=String.valueOf(props.getBoolean(ANALYZER_NAME,false));
  int nativeLoops=0,conditional=0,missing=0,invalid=0;
  for(Instruction ins:currentProgram.getListing().getInstructions(true)){
   if(!"PM".equals(ins.getAddress().getAddressSpace().getName())||
      !ins.toString().trim().matches("(?i)^DO\\s+(?:0x)?[0-9a-f]+\\s+UNTIL CE$"))continue;
   nativeLoops++;
   String operand=ins.toString().replaceFirst("(?i)^DO\\s+(?:0x)?", "").replaceFirst("(?i)\\s+UNTIL CE$","");
   Instruction tail=currentProgram.getListing().getInstructionAt(currentProgram.getAddressFactory().getAddress("PM:"+operand));
   if(tail==null){invalid++;continue;}
   boolean condition=false;
   for(PcodeOp op:tail.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)condition=true;
   if(condition)conditional++;else missing++;
  }
  if(currentProgram.isChanged()||currentProgram.getDomainFile().getVersion()!=version||
      nativeFns!=currentProgram.getFunctionManager().getFunctionCount())
      throw new IllegalStateException("Read-only saved source Analyzer model mutated");
  println("AUTO_MODEL_DISCOVERY program="+currentProgram.getName()+" class="+found.getClass().getName()+
    " sourceGhidraAnalyzerCount="+analyzers+" canAnalyze=true enabledProgramOption="+enabled+
    " nativeFunctions="+nativeFns+" nativeDO="+nativeLoops+" withConditionalBackedge="+conditional+
    " currentlyMissing="+missing+" undecodedLoopEnds="+invalid+" currentFirmwareNotReimported=true");
  println("AUTO_MODEL_DISCOVERY_PASS");
 }
}
