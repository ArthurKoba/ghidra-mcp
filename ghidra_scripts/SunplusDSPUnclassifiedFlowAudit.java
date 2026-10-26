//@category Sunplus/Architecture
// Read-only classification of PM 24-bit words without decoded instructions.
// Direct flow evidence is necessary for automatic executable recovery; gaps
// with no incoming code flows remain UNKNOWN, not silently executable.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.util.*;
public class SunplusDSPUnclassifiedFlowAudit extends GhidraScript {
 private record Span(Address first,Address last,int words,int falls,int calls,int jumps,int data){}
 public void run()throws Exception{
  if(!"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong DSP ISA");
  int version=currentProgram.getDomainFile().getVersion();boolean changed=currentProgram.isChanged();
  var pm=currentProgram.getAddressFactory().getAddressSpace("PM");if(pm==null||pm.getAddressableUnitSize()!=3)throw new IllegalStateException("Unexpected PM mapping");
  var listing=currentProgram.getListing();var refs=currentProgram.getReferenceManager();
  int decoded=0,missing=0,flowRooted=0,unknown=0,explicitData=0,callRooted=0,jumpRooted=0,fallRooted=0;
  List<Span> spans=new ArrayList<>();
  for(MemoryBlock block:currentProgram.getMemory().getBlocks()){
   if(!block.isInitialized()||!block.getStart().getAddressSpace().equals(pm))continue;
   int slots=(int)(block.getSize()/3);if(slots>40000)throw new IllegalStateException("Unbounded PM image");
   for(int i=0;i<slots;){
    monitor.checkCancelled();Address first=block.getStart().add(i*3L);
    if(listing.getInstructionAt(first)!=null){decoded++;i++;continue;}
    Address last=first;int n=0,calls=0,jumps=0,falls=0,data=0;
    do{
     Address a=block.getStart().add(i*3L);if(listing.getInstructionAt(a)!=null)break;
     if(listing.getDefinedDataAt(a)!=null)data++;
     Instruction prev=listing.getInstructionAt(a.getOffset()>=3?a.subtract(3):a);if(prev!=null&&a.equals(prev.getFallThrough()))falls++;
     for(Reference r:refs.getReferencesTo(a))if(r.getReferenceType().isFlow()){
       if(r.getReferenceType().isCall())calls++;else jumps++;
     }
     n++;missing++;last=a;i++;
    }while(i<slots);
    if(n<=0)throw new IllegalStateException("Zero-gap invariant");
    spans.add(new Span(first,last,n,falls,calls,jumps,data));
    if(falls+calls+jumps>0){flowRooted+=n;callRooted+=calls;jumpRooted+=jumps;fallRooted+=falls;}
    else unknown+=n;explicitData+=data;
   }
  }
  for(Span s:spans)println("PM_GAP_RANGE program="+currentProgram.getName()+" start="+s.first()+" end="+s.last()+
   " missing_words="+s.words()+" incoming_calls="+s.calls()+" incoming_jumps="+s.jumps()+" prior_fallthrough="+s.falls()+
   " defined_data_words="+s.data()+" classification="+(s.falls()+s.calls()+s.jumps()>0?"LIKELY_FLOW_ROOTED":"UNKNOWN_NO_FLOW"));
  println("PM_GAP_SUMMARY program="+currentProgram.getName()+" decoded="+decoded+" missing_words="+missing+
   " regions="+spans.size()+" flow_rooted_words="+flowRooted+" without_flow_words="+unknown+
   " rooted_calls="+callRooted+" rooted_jumps="+jumpRooted+" rooted_fallthrough="+fallRooted+
   " defined_data_words="+explicitData);
  if(currentProgram.getDomainFile().getVersion()!=version||currentProgram.isChanged()!=changed)throw new IllegalStateException("Read-only audit modified program");
  println("PM_GAP_AUDIT_PASS");
 }
}
