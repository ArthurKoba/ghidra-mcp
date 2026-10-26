//@category Sunplus/Audit
// Bounded read-only instruction/body and CFG diagnosis. Native 24-bit PM words.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.Reference;
public class SunplusDSPNativeFlowGapProbe extends GhidraScript {
 private Address at(int w){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",w));}
 private String ctx(String key,Address a){Register r=currentProgram.getRegister(key);return r==null?"NONE":String.valueOf(currentProgram.getProgramContext().getValue(r,a,false));}
 public void run()throws Exception{
  String[] args=getScriptArgs();if(args.length!=2)throw new IllegalArgumentException("start word; end word");
  int lo=Integer.parseInt(args[0],16),hi=Integer.parseInt(args[1],16);if(lo>hi||hi-lo>100)throw new IllegalArgumentException("max 100 PM words");
  int version=currentProgram.getDomainFile().getVersion();boolean changed=currentProgram.isChanged();
  var listing=currentProgram.getListing();var fm=currentProgram.getFunctionManager();int n=0,unowned=0,incoming=0;
  for(int w=lo;w<=hi;w++){
   monitor.checkCancelled();Address a=at(w);Instruction ins=listing.getInstructionAt(a);
   Function owner=fm.getFunctionContaining(a);if(owner==null)unowned++;
   int call=0,jump=0;StringBuilder samples=new StringBuilder();
   for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(a))if(ref.getReferenceType().isFlow()){
    if(ref.getReferenceType().isCall())call++;else jump++;
    if(samples.length()<110)samples.append(ref.getFromAddress()).append('/').append(ref.getReferenceType()).append(',');
   }
   incoming+=call+jump;
   if(ins==null){println("FLOW_GAP_PM="+a+" UNDECODED owner="+(owner==null?"NONE":owner.getEntryPoint()));continue;}
   int cb=0,br=0,ind=0,ret=0;StringBuilder targets=new StringBuilder();
   for(PcodeOp op:ins.getPcode()){
    if(op.getOpcode()==PcodeOp.CBRANCH)cb++;
    if(op.getOpcode()==PcodeOp.BRANCH){br++;if(targets.length()<60)targets.append(op.getInput(0).getAddress()).append(';');}
    if(op.getOpcode()==PcodeOp.BRANCHIND)ind++;
    if(op.getOpcode()==PcodeOp.RETURN)ret++;
   }
   println("FLOW_WORD at="+a+" owner="+(owner==null?"NONE":owner.getEntryPoint())+
     " ins="+ins.toString()+" flow="+ins.getFlowType()+" override="+ins.getFlowOverride()+" fall="+ins.getFallThrough()+
     " calls="+call+" jumps="+jump+" ref="+samples+" PcodeCB="+cb+" PcodeBR="+br+
     " PcodeIND="+ind+" PcodeRTS="+ret+" dst="+targets+
     " CE="+ctx("codec_ce_loop_end",a)+" signedSE="+ctx("codec_se_proven_negative",a)+
     " nonnegSE="+ctx("codec_se_proven_nonnegative",a)+" nested="+ctx("codec_ce_nested_mode",a));n++;
  }
  println("FLOW_GAP_SUMMARY program="+currentProgram.getName()+" version="+version+" decoded="+n+" unowned="+unowned+" refEdges="+incoming);
  if(currentProgram.getDomainFile().getVersion()!=version||currentProgram.isChanged()!=changed)throw new IllegalStateException("read-only audit modified program");
 }
}
