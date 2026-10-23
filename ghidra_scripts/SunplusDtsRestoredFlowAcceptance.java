// Read-only acceptance of local DTS function-body and native call-return repairs.
// Exact saved 102/103-function GZF; no canonical Analysis mutation.
//@category Sunplus/Regression
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import java.util.HashSet;
import java.util.Set;
public class SunplusDtsRestoredFlowAcceptance extends GhidraScript {
 private Address pm(int v){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",v));}
 private void need(boolean value,String failure){if(!value)throw new IllegalStateException(failure);}
 public void run()throws Exception {
  need(currentProgram!=null&&"dts-profile.bin".equals(currentProgram.getName()),"Require isolated DTS binary");
  FunctionManager fm=currentProgram.getFunctionManager();int functionCount=fm.getFunctionCount();need(functionCount==102||functionCount==103,"Require saved 102/103-function DTS checkpoint");
  Function decoder=fm.getFunctionAt(pm(0x03d7)),initializer=fm.getFunctionAt(pm(0x1364));
  need(decoder!=null&&decoder.getBody().getMaxAddress().equals(pm(0x048d).add(2)),"Restored decoder function boundary lost");
  need(initializer!=null&&initializer.getBody().getMaxAddress().equals(pm(0x1394).add(2)),"RTS-bounded initializer lost");
  for(int[] evidence:new int[][]{{0x06a9,0x06b4},{0x06c1,0x06ca}}){Function callee=fm.getFunctionAt(pm(evidence[0]));Instruction rts=currentProgram.getListing().getInstructionAt(pm(evidence[1]));need(callee!=null&&!callee.hasNoReturn()&&rts!=null&&rts.getMnemonicString().equals("RTS"),"False no-return regression at "+pm(evidence[0]));}
  for(int w:new int[]{0x0212,0x0271,0x02b1,0x03de}){Instruction ins=currentProgram.getListing().getInstructionAt(pm(w));need(ins!=null&&ins.toString().equals("CALL 0x06c1")&&ins.getFlowOverride()==FlowOverride.NONE&&ins.getFlowType().isCall()&&!ins.getFlowType().isTerminal()&&ins.getFallThrough()!=null,"Incorrect nonreturn CALL override "+pm(w));}
  int decoded=0,ownerDo=0;
  for(int w=0x03df;w<=0x048d;w++){monitor.checkCancelled();Instruction ins=currentProgram.getListing().getInstructionAt(pm(w));need(ins!=null&&ins.getLength()==3&&decoder.getBody().contains(pm(w)),"Hidden native instruction gap "+pm(w));decoded++;if(ins.toString().contains("UNTIL CE"))ownerDo++;}
  need(decoded==175&&ownerDo==12,"Expanded native decoder DO inventory changed");
  Instruction ce=currentProgram.getListing().getInstructionAt(pm(0x1369));need(ce!=null&&initializer.getBody().contains(pm(0x1369)),"Orphan native CE still unowned");
  boolean branch=false;for(PcodeOp op:ce.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)branch=true;
  need(branch,"Restored native PM1368 CE lacks P-code CBRANCH");
  if(functionCount==103){
   Function newOwner=fm.getFunctionAt(pm(0x06b5)),prev=fm.getFunctionAt(pm(0x06a9)),next=fm.getFunctionAt(pm(0x06c1));
   need(newOwner!=null&&prev!=null&&next!=null&&prev.getBody().getMaxAddress().equals(pm(0x06b4).add(2))&&newOwner.getBody().getMaxAddress().equals(pm(0x06c0).add(2)),"New native CALL target PM06B5 boundary changed");
   Instruction start=currentProgram.getListing().getInstructionAt(pm(0x06b5)),end=currentProgram.getListing().getInstructionAt(pm(0x06bf)),ret=currentProgram.getListing().getInstructionAt(pm(0x06c0));
   need(start!=null&&start.toString().equals("DO 0x06bf UNTIL CE")&&end!=null&&ret!=null&&ret.getMnemonicString().equals("RTS"),"Native PM06B5 DO/RTS changed");
   boolean loopEdge=false;for(PcodeOp op:end.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)loopEdge=true;
   need(loopEdge&&newOwner.getBody().contains(pm(0x06bf)),"PM06B5 native CE lost owner or backedge");
   HashSet<String> callers=new HashSet<>();for(Reference x:currentProgram.getReferenceManager().getReferencesTo(pm(0x06b5)))if(x.getReferenceType().isCall())callers.add(x.getFromAddress().toString());
   need(callers.equals(Set.of("PM:043c","PM:0443","PM:044a")),"PM06B5 direct call evidence changed: "+callers);
   for(int a:new int[]{0x043c,0x0443,0x044a})need(decoder.getBody().contains(pm(a)),"PM06B5 CALL from unrelated function");
   println("SUNPLUS_DTS_EXTRA_CALL_OWNER_ACCEPTANCE=PASS native_entry=PM:06b5 incoming=3 owned_CE=PM:06bf native_RTS=PM:06c0");
  }
  println("SUNPLUS_DTS_RESTORED_FLOW_ACCEPTANCE=PASS functions="+functionCount+" new_decoder_instr=175 newly_exposed_DO=12 false_noreturn=0 false_CALL_RETURN=0 owned_1368_CE=true owned_06b5_CE="+(functionCount==103));
 }
}
