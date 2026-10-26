//@category Sunplus/Architecture
// Read-only native CALL entry and ownership survey, grounded by external accepted PM list.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.util.*;
public class SunplusDSPCallEvidenceAudit extends GhidraScript {
 public void run()throws Exception {
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong DSP ISA");
  var args=getScriptArgs();if(args.length<1||args.length>256)throw new IllegalArgumentException("Pass 1-256 reference entries");
  int ver=currentProgram.getDomainFile().getVersion();boolean changed=currentProgram.isChanged();
  int ready=0,owned=0,missing=0,call=0,noCall=0,existing=0;
  var fm=currentProgram.getFunctionManager();var listing=currentProgram.getListing();
  for(String word:args){monitor.checkCancelled();if(!word.matches("(?i)[0-9a-f]{4}"))throw new IllegalArgumentException("Invalid entry "+word);
   Address at=currentProgram.getAddressFactory().getAddress("PM:"+word);
   var ins=listing.getInstructionAt(at);Function here=fm.getFunctionAt(at),owner=fm.getFunctionContaining(at);
   int calls=0,jumps=0;StringBuilder examples=new StringBuilder();
   for(Reference r:currentProgram.getReferenceManager().getReferencesTo(at)){
    if(r.getReferenceType().isCall())calls++;else if(r.getReferenceType().isFlow())jumps++;
    if(examples.length()<100)examples.append(r.getFromAddress()).append('/').append(r.getReferenceType()).append(',');
   }
   if(calls>0)call++;else noCall++;
   if(here!=null)existing++;else if(ins==null)missing++;else if(owner!=null)owned++;else ready++;
   println("RUSH27_ENTRY_AUDIT at="+at+" ins="+(ins==null?"NONE":ins.toString())+
    " owner="+(owner==null?"NONE":owner.getEntryPoint())+" entry="+(here==null?"NONE":here.getEntryPoint())+
    " CALL="+calls+" JUMP="+jumps+" refs="+examples);
  }
  println("RUSH27_ENTRY_SUMMARY total="+args.length+" ready_unowned="+ready+" owned_conflicts="+owned+
   " undecoded="+missing+" existing="+existing+" call_proven="+call+" no_call="+noCall+
   " functions="+fm.getFunctionCount()+" version="+ver);
  if(currentProgram.isChanged()!=changed||currentProgram.getDomainFile().getVersion()!=ver)throw new IllegalStateException("Read-only mutation");
  println("RUSH27_ENTRY_AUDIT_PASS");
 }
}
