// Full, read-only corpus acceptance for saved SPHE8202R DSP projects.
// Usage: -postScript SunplusDSPFullCorpusAcceptance.java baseline|strict <output-dir>
// Each known native function is decompiled and indexed; strict requires complete CE P-code.
//@category Sunplus/Regression
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.address.Address;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.TreeMap;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SunplusDSPFreshCodecCorpusAcceptance extends GhidraScript {
  private static final Map<String,Integer> EXPECTED=Map.of(
    "srvdsp.bin",9,"aux-profile.bin",61,"pcm-profile.bin",115,
    "ac3-profile.bin",37,"dts-profile.bin",100);
  private static final Pattern CE=Pattern.compile("^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
  private static String tidy(String a){return a.replace('\t',' ').replace('\r',' ').replace('\n',' ').replace('|','/');}
  public void run() throws Exception {
    if(currentProgram==null)throw new IllegalStateException("no program");
    String program=currentProgram.getName();
    String[] args=getScriptArgs();
    Integer expected=EXPECTED.get(program);
    if("pcm-automatic-vector-qa.bin".equals(program) &&
       "be1cda3ac614db29818fc68423063ea3820c6033b207442367ccbb7b967242eb".equals(currentProgram.getExecutableSHA256()))
      expected=108;
    // Fresh QA source images may have unique names. The program must remain
    // inside the dedicated validation folder, match the original source SHA,
    // and supply an explicit, reviewable function denominator; no guesswork.
    if(expected==null && args.length>=3 && currentProgram.getDomainFile()!=null &&
       currentProgram.getDomainFile().getPathname().startsWith("/RUSH28-architecture-import-validation/") &&
       "be1cda3ac614db29818fc68423063ea3820c6033b207442367ccbb7b967242eb".equals(
           currentProgram.getExecutableSHA256())) {
      int scoped=Integer.parseInt(args[2]);
      if(scoped<1 || scoped>2000)throw new IllegalStateException("invalid scoped native inventory="+scoped);
      expected=scoped;
    }
    // Generic original-source validation for any new codec QA image. The
    // strict-native six-argument corpus gate uses this SAME fresh QA path
    // with exact original SHA and explicit function/source denominators.
    // Never accept a name-only match or an inferred discovery count.
    if(expected==null && args.length>=4 &&
       args[3].matches("[0-9a-f]{64}") &&
       args[3].equals(currentProgram.getExecutableSHA256()) &&
       currentProgram.getDomainFile()!=null &&
       currentProgram.getDomainFile().getPathname().startsWith(
           "/RUSH28-architecture-import-validation/")) {
      int scoped=Integer.parseInt(args[2]);
      if(scoped<1 || scoped>2000)throw new IllegalStateException("Invalid native scoped inventory "+scoped);
      expected=scoped;
    }
    if(expected==null)throw new IllegalStateException("unexpected program "+program);
    if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))
      throw new IllegalStateException("wrong DSP ISA "+currentProgram.getLanguageID());
    String mode=args.length==0?"baseline":args[0];
    if(!mode.equals("baseline")&&!mode.equals("strict")&&
       !mode.equals("strict-native"))
      throw new IllegalStateException("mode=baseline|strict|strict-native");
    boolean strict=mode.equals("strict")||mode.equals("strict-native");
    boolean releaseNative=mode.equals("strict-native");
    // The release-native gate cannot mistake a smaller newly discovered
    // instruction inventory for complete CE/C coverage. Its frozen source
    // requirements are supplied by the authoritative module truth table,
    // never inferred from a freshly modified Analyzer database.
    if(releaseNative && (args.length!=6 ||
       !args[3].matches("[0-9a-f]{64}") ||
       !args[3].equals(currentProgram.getExecutableSHA256())))
      throw new IllegalStateException(
          "strict-native needs exact source SHA, functions, sourceDO, decodedPM");
    // Optional exact snapshot inventory for a *cloned* project after guarded
    // function discovery. Never infer acceptance from the number found: caller
    // must name a concrete denominator and all resulting functions are audited.
    if(args.length>=3){
      int explicit=Integer.parseInt(args[2]);
      if(explicit<expected||explicit>2000)throw new IllegalStateException("Invalid scoped function inventory="+explicit);
      expected=explicit;
    }
    int count=currentProgram.getFunctionManager().getFunctionCount();
    if(count!=expected)throw new IllegalStateException("expected functions="+expected+" actual="+count+" program="+program);
    Path out=null;
    if(args.length>=2){
      Path root=Path.of(args[1]).toAbsolutePath().normalize();
      Files.createDirectories(root);
      out=root.resolve(program);
      Files.createDirectories(out);
    }
    int seen=0,ok=0,fail=0,empty=0,warningFunctions=0,unknownOpcode=0,semanticWarningFunctions=0,symbolOverlapFunctions=0;
    List<String> index=new ArrayList<>();
    index.add("address|name|status|C_chars|C_do|warning_count|bad_data|reason");
    DecompInterface dc=new DecompInterface();
    dc.toggleCCode(true);
    dc.setSimplificationStyle("decompile");
    if(!dc.openProgram(currentProgram))throw new IllegalStateException("DecompInterface open failed");
    try {
      for(Function fn:currentProgram.getFunctionManager().getFunctions(true)){
        monitor.checkCancelled();seen++;
        DecompileResults dr=dc.decompileFunction(fn,25,monitor);
        String c=dr.getDecompiledFunction()==null?"":dr.getDecompiledFunction().getC();
        boolean success=dr.decompileCompleted()&&!c.isBlank();
        if(success)ok++;else{fail++;if(c.isBlank())empty++;}
        int warns=(c.split("WARNING:",-1).length-1);
        int dos=(c.split("do \\{",-1).length-1);
        int bad=(c.split("halt_baddata",-1).length-1);
        if(warns>0)warningFunctions++;
        int semanticWarnings=0;boolean symbolOverlap=false;
        for(String line:c.split("\n")){
          if(!line.contains("WARNING:"))continue;
          if(line.contains("Globals starting with '_' overlap smaller symbols at the same address"))symbolOverlap=true;
          else semanticWarnings++;
        }
        if(semanticWarnings>0)semanticWarningFunctions++;
        if(symbolOverlap)symbolOverlapFunctions++;
        if(bad>0)unknownOpcode++;
        String why=tidy(dr.getErrorMessage()==null?"":dr.getErrorMessage());
        String loc=fn.getEntryPoint().toString().replace(':','_');
        index.add(fn.getEntryPoint()+"|"+fn.getName()+"|"+(success?"OK":"FAIL")+"|"+c.length()+"|"+dos+"|"+warns+"|"+bad+"|"+why);
        if(out!=null)Files.writeString(out.resolve(loc+".c"),c,StandardOpenOption.CREATE_NEW);
        if(!success||warns>0||bad>0)println("FULL_CORPUS_FUNCTION "+program+" "+fn.getEntryPoint()+" ok="+success+" warnings="+warns+" bad="+bad+" error="+why);
      }
    }finally{dc.dispose();}
    if(out!=null)Files.write(out.resolve("index.psv"),index,StandardOpenOption.CREATE_NEW);
    int ceCount=0,withConditional=0,withoutConditional=0,ownerMissing=0,endMissing=0,withDirect=0,withIndirect=0;
    int sourceDecodedPm=0;
    int rawInvalidNativeFlow=0;
    // Presence of CBRANCH is NOT evidence of a native DO..CE backedge.
    // Sign/shift P-code inside the final instruction may emit only a local
    // relative CBRANCH in constant space without any PM control-flow edge.
    int externalBackedgeShape=0,internalConditionalOnly=0;
    int confirmedDirectTarget=0,wrongDirectTarget=0,unresolvedIndirectTarget=0;
    TreeMap<String,int[]> byOwner=new TreeMap<>();
    for(Instruction inst:currentProgram.getListing().getInstructions(true)){
      monitor.checkCancelled();
      if(!"PM".equals(inst.getAddress().getAddressSpace().getName()))continue;
      sourceDecodedPm++;
      if("INVALID".equals(inst.getFlowType().toString()))
        rawInvalidNativeFlow++;
      Matcher m=CE.matcher(inst.toString().trim());
      if(!m.matches())continue;
      ceCount++;
      Address end=currentProgram.getAddressFactory().getAddress("PM:"+m.group(1));
      Instruction finish=currentProgram.getListing().getInstructionAt(end);
      Function owner=currentProgram.getFunctionManager().getFunctionContaining(inst.getAddress());
      if(owner==null||!owner.getBody().contains(end))ownerMissing++;
      if(finish==null)endMissing++;
      int cb=0,br=0,ind=0,externalCb=0,branchPm=0,matchedDirect=0;
      Address expectedBackedge=inst.getFallThrough();
      if(finish!=null)for(PcodeOp op:finish.getPcode()){
        if(op.getOpcode()==PcodeOp.CBRANCH){
          cb++;
          if("PM".equals(op.getInput(0).getAddress().getAddressSpace().getName())){
            externalCb++;
            if(expectedBackedge!=null && expectedBackedge.equals(op.getInput(0).getAddress()))
              matchedDirect++;
          }
        }
        if(op.getOpcode()==PcodeOp.BRANCH){
          br++;
          if("PM".equals(op.getInput(0).getAddress().getAddressSpace().getName())){
            branchPm++;
            if(expectedBackedge!=null && expectedBackedge.equals(op.getInput(0).getAddress()))
              matchedDirect++;
          }
        }
        if(op.getOpcode()==PcodeOp.BRANCHIND)ind++;
      }
      // Shape evidence, NOT a complete semantic proof of the loop target:
      // either a conditional PM destination, or a conditional instruction
      // with an explicit external BRANCH/BRANCHIND in its P-code.
      boolean externalShape=externalCb>0||(cb>0&&(branchPm>0||ind>0));
      if(externalShape)externalBackedgeShape++;
      else if(cb>0)internalConditionalOnly++;
      if(cb>0 && matchedDirect>0)confirmedDirectTarget++;
      // A PM edge which misses the DO successor cannot establish a direct
      // CE backedge. BRANCHIND may still carry the hardware loop target;
      // record this as unresolved, not as a fabricated wrong target.
      if(cb>0 && (externalCb>0||branchPm>0) && matchedDirect==0 && ind==0){
        wrongDirectTarget++;
        println("FULL_CORPUS_WRONG_CE_DIRECT program="+program+
          " DO="+inst.getAddress()+" expected="+expectedBackedge+" end="+end);
      }
      if(cb>0 && ind>0 && matchedDirect==0)unresolvedIndirectTarget++;
      if(cb>0)withConditional++;else withoutConditional++;
      if(br>0)withDirect++;if(ind>0)withIndirect++;
      String ownerName=owner==null?"unowned":owner.getName();
      int[] o=byOwner.computeIfAbsent(ownerName,k->new int[3]);o[0]++;if(cb>0)o[1]++;else o[2]++;
      if(cb==0)println("FULL_CORPUS_MISSING_CE "+program+" "+ownerName+" "+inst.getAddress()+" -> "+end);
    }
    println("FULL_CORPUS_SUMMARY program="+program+" expected="+expected+" scanned="+seen+" ok="+ok+" failures="+fail+" empty="+empty+" warning_functions="+warningFunctions+" semantic_warning_functions="+semanticWarningFunctions+" symbol_overlap_functions="+symbolOverlapFunctions+" bad_data_functions="+unknownOpcode+" ce="+ceCount+" ce_conditional="+withConditional+" ce_missing="+withoutConditional+" ce_external_backedge_shape="+externalBackedgeShape+" ce_internal_conditional_only="+internalConditionalOnly+" ce_direct="+withDirect+" ce_indirect="+withIndirect+
      " ce_proven_direct_target="+confirmedDirectTarget+
      " ce_wrong_direct_target="+wrongDirectTarget+
      " ce_unresolved_indirect_target="+unresolvedIndirectTarget+
      " ce_missing_end="+endMissing+" ce_invalid_owner="+ownerMissing+" mode="+mode);
    if(fail!=0||seen!=expected)throw new IllegalStateException("Incomplete whole-function C corpus: "+program);
    if(releaseNative) {
      int sourceDO=Integer.parseInt(args[4]);
      int expectedDecodedPM=Integer.parseInt(args[5]);
      if(sourceDO<1||expectedDecodedPM<1)
        throw new IllegalStateException("Invalid frozen native source denominator");
      println("FULL_NATIVE_SOURCE_INVENTORY program="+program+
        " DO="+ceCount+"/"+sourceDO+
        " decoded_PM="+sourceDecodedPm+"/"+expectedDecodedPM+
        " source_sha256="+currentProgram.getExecutableSHA256());
      if(ceCount!=sourceDO||sourceDecodedPm!=expectedDecodedPM)
        throw new IllegalStateException("Native source inventory drift: "+
          program+" DO "+ceCount+"/"+sourceDO+" decoded "+
          sourceDecodedPm+"/"+expectedDecodedPM);
      // The native ISA can encode CALL and counted CE in one instruction.
      // Ghidra's FlowType cannot express both, so allow INVALID only when
      // the processor's source-backed composite proof is saved in this SAME
      // program, and no INVALID instruction remains unexplained.
      var compound=currentProgram.getOptions(
        "Sunplus DSP Native Composite CE CALL");
      int confirmed=compound.getInt("verified_composite_ce_call_count",0);
      int unresolved=compound.getInt("unresolved_invalid_native_flow_count",0);
      println("FULL_NATIVE_COMPOSITE_FLOW program="+program+
        " raw_invalid="+rawInvalidNativeFlow+
        " source_verified="+confirmed+" unsupported="+unresolved);
      if(rawInvalidNativeFlow!=confirmed || unresolved!=0)
        throw new IllegalStateException("UNSUPPORTED compound CALL/CE Ghidra flow: "+
          program+" raw="+rawInvalidNativeFlow+
          " confirmed="+confirmed+" unresolved="+unresolved);
      if(unresolvedIndirectTarget!=0 || withIndirect!=0)
        throw new IllegalStateException("UNSUPPORTED indirect native CE targets: "+
          program+" indirect="+withIndirect+
          " unresolved="+unresolvedIndirectTarget);
    }
    if(strict&&(ownerMissing!=0||endMissing!=0))
      throw new IllegalStateException("Basic corpus acceptance failure: "+program);
    if(strict&&(wrongDirectTarget!=0||withoutConditional!=0||externalBackedgeShape!=ceCount||unknownOpcode!=0||
                 semanticWarningFunctions!=0||symbolOverlapFunctions!=0))
      throw new IllegalStateException("Strict corpus gaps: "+program+" no_CE="+withoutConditional+
        " ce_without_external_shape="+(ceCount-externalBackedgeShape)+
        " wrong_CE_direct_target="+wrongDirectTarget+" bad_C="+unknownOpcode+
        " semantic_warning_functions="+semanticWarningFunctions+" symbol_overlap_functions="+symbolOverlapFunctions);
    println((strict ? "FULL_CORPUS_ACCEPTANCE=PASS" : "FULL_CORPUS_BASELINE_CAPTURED=PASS")+" program="+program+" mode="+mode);
  }
}
