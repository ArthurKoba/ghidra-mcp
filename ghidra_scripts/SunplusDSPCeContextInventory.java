//@category Sunplus/Architecture
// Read-only characterization of saved DO..CE backedge semantics and program-context evidence.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.address.Address;
import java.util.*;
import java.util.regex.*;
public class SunplusDSPCeContextInventory extends GhidraScript {
 private static final Pattern DO=Pattern.compile("^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
 private String ctx(String name,Address a){Register r=currentProgram.getRegister(name);return r==null?"NO_REGISTER":String.valueOf(currentProgram.getProgramContext().getValue(r,a,false));}
 public void run()throws Exception{
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("DSP language required");
  boolean changed=currentProgram.isChanged();int version=currentProgram.getDomainFile().getVersion();
  int loops=0,direct=0,indirect=0,internalOnly=0,missing=0,unknown=0,owned=0,badOwner=0;Map<String,Integer> missingOwners=new TreeMap<>();
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();if(!"PM".equals(i.getAddress().getAddressSpace().getName()))continue;
   Matcher m=DO.matcher(i.toString().trim());if(!m.matches())continue;
   loops++;Address finish=currentProgram.getAddressFactory().getAddress("PM:"+m.group(1));
   Instruction end=currentProgram.getListing().getInstructionAt(finish);
   Function owner=currentProgram.getFunctionManager().getFunctionContaining(i.getAddress());
   boolean valid=owner!=null&&owner.getBody().contains(finish);
   if(valid)owned++;else badOwner++;
   if(end==null){missing++;continue;}
   int cb=0,br=0,bi=0,pm=0;
   for(PcodeOp p:end.getPcode()){
    if(p.getOpcode()==PcodeOp.CBRANCH){cb++;if("PM".equals(p.getInput(0).getAddress().getAddressSpace().getName()))pm++;}
    if(p.getOpcode()==PcodeOp.BRANCH){br++;if("PM".equals(p.getInput(0).getAddress().getAddressSpace().getName()))pm++;}
    if(p.getOpcode()==PcodeOp.BRANCHIND)bi++;
   }
   if(pm>0)direct++;
   else if(bi>0)indirect++;
   else {unknown++;if(cb>0)internalOnly++;
     String entry=owner==null?"UNOWNED":owner.getEntryPoint().toString();missingOwners.merge(entry,1,Integer::sum);
     if(unknown<=20)println("CE_MISSING_SITE owner="+entry+" do="+i.getAddress()+" end="+finish+" end_ins="+end.getMnemonicString()+" cb="+cb+" br="+br+" bi="+bi+" loopCtx="+ctx("codec_ce_loop_end",finish)+" directCtx="+ctx("codec_ce_direct_backedge",finish)+" startCtx="+ctx("codec_ce_direct_start",finish)+" nested="+ctx("codec_ce_nested_mode",finish)+" staticDepth="+ctx("codec_ce_static_depth",finish));
   }
  }
  println("CE_CONTEXT_SUMMARY program="+currentProgram.getName()+" version="+version+" native_DO="+loops+" direct="+direct+" indirect="+indirect+" no_PMcflow="+unknown+" conditional_only="+internalOnly+" missing_end="+missing+" owned_valid="+owned+" owner_gap="+badOwner+" missing_owners="+missingOwners);
  if(currentProgram.isChanged()!=changed||currentProgram.getDomainFile().getVersion()!=version)throw new IllegalStateException("Read-only scan changed saved state");
  println("CE_CONTEXT_AUDIT_PASS");
 }
}
