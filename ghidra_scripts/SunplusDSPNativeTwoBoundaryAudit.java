//@category Sunplus/Architecture
// Bounded evidence for split-of-overowned CALL target and uncalled DO/RTS body.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Reference;
import java.util.*;
public class SunplusDSPNativeTwoBoundaryAudit extends GhidraScript {
 public void run()throws Exception{
  String[] args=getScriptArgs();if(args.length!=2)throw new IllegalArgumentException("two 4hex entries");
  int old=currentProgram.getFunctionManager().getFunctionCount();int version=currentProgram.getDomainFile().getVersion();boolean changed=currentProgram.isChanged();
  var listing=currentProgram.getListing();var fm=currentProgram.getFunctionManager();
  for(String w:args){
   if(!w.matches("(?i)[0-9a-f]{4}"))throw new IllegalArgumentException("Bad word");
   Address a=currentProgram.getAddressFactory().getAddress("PM:"+w);
   Function parent=fm.getFunctionContaining(a),at=fm.getFunctionAt(a);
   println("TWO_BOUNDARY_ENTRY="+a+" currentOwner="+(parent==null?"NONE":parent.getEntryPoint())+
     " newEntry="+(at==null?"NONE":at.getEntryPoint())+" body="+(parent==null?"NONE":parent.getBody()));
   int call=0,jump=0;
   for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(a)){
    if(ref.getReferenceType().isCall())call++;
    if(ref.getReferenceType().isJump())jump++;
    println("TWO_BOUNDARY_INREF entry="+a+" from="+ref.getFromAddress()+" type="+ref.getReferenceType());
   }
   int ret=0,loops=0,calls=0,count=0;
   for(int offset=-3;offset<85;offset++){
    Address x=a.add(offset*3L);Instruction i=listing.getInstructionAt(x);
    if(i==null)continue;
    Function o=fm.getFunctionContaining(x);
    if(offset>=0){count++;if(i.toString().trim().equals("RTS"))ret++;
     if(i.toString().trim().startsWith("DO "))loops++;
     if(i.getFlowType().isCall())calls++;
    }
    if(offset<0||offset<25||i.toString().equals("RTS")||i.toString().startsWith("DO ")||i.getFlowType().isJump()||i.getFlowType().isCall())
     println("TWO_BOUNDARY_WORD at="+x+" relative="+offset+" ins="+i+" owner="+
       (o==null?"NONE":o.getEntryPoint())+" flow="+i.getFlowType()+" fall="+i.getFallThrough());
   }
   println("TWO_BOUNDARY_SUMMARY entry="+a+" calls="+call+" jumps="+jump+" nearbyDecoded="+count+
     " nativeRTS="+ret+" nativeDO="+loops+" outgoingCALL="+calls);
  }
  if(fm.getFunctionCount()!=old||currentProgram.isChanged()!=changed||currentProgram.getDomainFile().getVersion()!=version)
   throw new IllegalStateException("Read-only audit mutated program");
  println("TWO_BOUNDARY_AUDIT_PASS");
 }
}
