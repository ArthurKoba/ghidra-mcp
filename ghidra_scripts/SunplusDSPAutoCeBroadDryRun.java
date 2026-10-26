//@category Sunplus/Verification
// Exercise the installed architecture auto-analyzer over the entire original
// program inside a top-level ROLLBACK. No new saved functions, PM bytes or
// fabricated C. Batch-proves self-consistency for new firmware deployments.
import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.classfinder.ClassSearcher;
import java.security.MessageDigest;
import java.util.*;
public class SunplusDSPAutoCeBroadDryRun extends GhidraScript {
 private static final String NAME="Sunplus DSP Native DO/CE Flow";
 private byte[] sha()throws Exception{
  var digest=MessageDigest.getInstance("SHA-256");byte[] b=new byte[8192];
  for(MemoryBlock block:currentProgram.getMemory().getBlocks())if(block.isInitialized()){
   var at=block.getStart();long left=block.getSize();
   while(left>0){monitor.checkCancelled();int n=(int)Math.min(left,b.length);
    if(currentProgram.getMemory().getBytes(at,b,0,n)!=n)throw new IllegalStateException("Native firmware source read failed");
    digest.update(b,0,n);at=at.add(n);left-=n;}}
  return digest.digest();
 }
 private int countCE(){int n=0;
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   if(!i.toString().trim().matches("(?i)^DO\\s+0x[0-9a-f]+ UNTIL CE$"))continue;
   String s=i.toString().replaceFirst("(?i)^DO 0x","").replaceFirst("(?i) UNTIL CE$","");
   var end=currentProgram.getListing().getInstructionAt(currentProgram.getAddressFactory().getAddress("PM:"+s));
   if(end!=null)for(PcodeOp op:end.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH){n++;break;}
  }return n;}
 public void run()throws Exception{
  String[] a=getScriptArgs();if(a.length!=1||!a[0].equals(currentProgram.getExecutableSHA256())||
    !"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString())||currentProgram.isChanged())
    throw new IllegalArgumentException("Require clean saved Sunplus native SHA");
  int f0=currentProgram.getFunctionManager().getFunctionCount();int c0=countCE();byte[] image=sha();
  long version=currentProgram.getDomainFile().getVersion();Analyzer analyzer=null;
  for(Analyzer candidate:ClassSearcher.getInstances(Analyzer.class))if(NAME.equals(candidate.getName())){
    if(analyzer!=null)throw new IllegalStateException("Duplicate automatic processor analyzer");analyzer=candidate;
  }
  if(analyzer==null||!analyzer.canAnalyze(currentProgram))throw new IllegalStateException("Ghidra does not expose native CE analyzer");
  String message="";boolean ok=false;int c1=0;
  MessageLog evidence=new MessageLog();
  AddressSetView loaded=currentProgram.getMemory().getLoadedAndInitializedAddressSet();
  ok=((com.xebyte.sunplus.SunplusNativeCeAutoAnalyzer)analyzer).dryRun(currentProgram,loaded,monitor,evidence);
  c1=countCE();message=evidence.toString();
  if(!ok||!Arrays.equals(image,sha())||f0!=currentProgram.getFunctionManager().getFunctionCount())
    throw new IllegalStateException("Native source integrity or function count lost in automatic dry-run");
  int c2=countCE();
  boolean sameSource=Arrays.equals(image,sha());
  boolean sameVersion=currentProgram.getDomainFile().getVersion()==version;
  boolean dirty=currentProgram.isChanged();
  println("AUTO_CE_BROAD_READ_ONLY_GATE program="+currentProgram.getName()+
    " beforeCE="+c0+" trialCE="+c1+" rollbackCE="+c2+" sameSource="+sameSource+
    " sameVersion="+sameVersion+" dirty="+dirty+" evidence="+message.replace('\n',' ').substring(0,Math.min(520,message.length())));
  if(c2!=c0||!sameSource||!sameVersion||dirty)
    throw new IllegalStateException("Auto-analyzer rollback changed saved program; inspect individual gate");
  String result=message.replace('\n',' ').replace('\r',' ');
  if(result.length()>1200)result=result.substring(0,1200);
  println("AUTO_CE_BROAD_RESULT program="+currentProgram.getName()+" functions="+f0+
    " originalCE="+c0+" afterPurePlanCE="+c1+" genuineSourceUnchanged="+(c0==c1)+
    " sourceIntact=true planOnly=true CAcceptancePendingForNewImports=true log="+result);
  println("AUTO_CE_BROAD_PASS");
 }
}
