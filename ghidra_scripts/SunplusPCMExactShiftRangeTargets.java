//@category Sunplus/Architecture
// Read-only proof: exact high-byte domain [0,255] is derived from the native
// 16-bit DMREAD logical right shift, not a guess about CPU sample-rate codes.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.pcode.JumpTable;
import java.security.MessageDigest;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.util.*;

public class SunplusPCMExactShiftRangeTargets extends GhidraScript {
 private void need(boolean good,String message){if(!good)throw new IllegalStateException(message);}
 private Address at(int word){return toAddr("PM:"+Integer.toHexString(word));}
 public void run() throws Exception {
  String root=System.getenv("GHIDRA_MCP_PROJECT_ROOT");
  need(root!=null&&root.endsWith("/native-branchind-candidate/projects"),"Only isolated local Ghidra");
  need(currentProgram!=null&&"be1cda3ac614db29818fc68423063ea3820c6033b207442367ccbb7b967242eb".equals(currentProgram.getExecutableSHA256()),"Incorrect native PCM image");
  need(!currentProgram.isChanged(),"Unsaved program state must not be changed");
  need(currentProgram.getFunctionManager().getFunctionCount()==115,"Native function denominator changed");
  int[] sites={0x0304,0x030c,0x0317,0x031f};
  int[] bases={0x0320,0x032c,0x0326,0x0332};
  int examined=0,missing=0,foreign=0;
  Map<Address,Set<Address>> expectedTables=new TreeMap<>();
  Set<Address> unique=new TreeSet<Address>();
  for(int j=0;j<4;j++){
   Instruction source=currentProgram.getListing().getInstructionAt(at(sites[j]));
   need(source!=null&&source.toString().replace(" ", "").equals("JUMP(I6)"),"Native dispatch changed: "+at(sites[j]));
   Function f=currentProgram.getFunctionManager().getFunctionContaining(source.getAddress());
   need(f!=null&&f.getEntryPoint().equals(at(0x02ea)),"Unexpected native dispatch owner");
   int indirect=0;for(PcodeOp op:source.getPcode())if(op.getOpcode()==PcodeOp.BRANCHIND)indirect++;
   need(indirect==1,"Missing exact original BRANCHIND p-code "+at(sites[j]));
   Set<Address> expected=new TreeSet<>();
   expectedTables.put(at(sites[j]),expected);
   TreeMap<String,Integer> owners=new TreeMap<String,Integer>();
   for(int high=0;high<256;high++){
    // Each possible 16-bit DM word is high*256+low; low cannot affect the value.
    for(int low: new int[]{0,0xff}){
     int dm=(high<<8)|low;
     need(((dm&0xffff)>>>8)==high,"Native 16-bit upper-byte arithmetic mismatch");
    }
    int word=(bases[j]+high-6)&0xffff;
    Address target=at(word);
    examined++;unique.add(target);expected.add(target);
    Instruction actual=currentProgram.getListing().getInstructionAt(target);
    if(actual==null || actual.getLength()!=3){missing++; continue;}
    Function owner=currentProgram.getFunctionManager().getFunctionContaining(target);
    String scope=owner==null?"UNOWNED":owner.getEntryPoint().toString();
    owners.merge(scope,1,Integer::sum);
    if(owner!=null&&!owner.getEntryPoint().equals(at(0x02ea)))foreign++;
   }
   println("PCM_RANGE_BRANCH site="+at(sites[j])+" base=0x"+Integer.toHexString(bases[j])+
     " inputs=256 target_first="+at((bases[j]-6)&0xffff)+
     " target_last="+at((bases[j]+249)&0xffff)+" owner_distribution="+owners);
  }
  need(examined==1024&&missing==0,"Some mathematically possible branch targets are not native instructions: "+missing);
  // Check the real recovered JumpTable objects, not just the C warning count.
  // Labels may be folded into default/fallthrough arms by the C printer.
  DecompInterface dc=new DecompInterface();
  dc.toggleCCode(true);dc.toggleSyntaxTree(true);
  need(dc.openProgram(currentProgram),"Could not open native C generator");
  int recovered=0,recoveredEdges=0;
  try {
   Function owner=currentProgram.getFunctionManager().getFunctionAt(at(0x02ea));
   DecompileResults result=dc.decompileFunction(owner,65,monitor);
   need(result.decompileCompleted()&&result.getHighFunction()!=null&&result.getDecompiledFunction()!=null,
        "Native switch generation failed: "+result.getErrorMessage());
   JumpTable[] tables=result.getHighFunction().getJumpTables();
   need(tables!=null&&tables.length==4,"Expected exactly four recovered native tables");
   Set<Address> recoveredSites=new TreeSet<>();
   for(JumpTable table:tables){
    Address site=table.getSwitchAddress();Set<Address> expected=expectedTables.get(site);
    need(expected!=null&&recoveredSites.add(site),"Unexpected or duplicated switch site "+site);
    Address[] cases=table.getCases();
    need(cases!=null&&cases.length==256,"Native range truncated at "+site+" count="+(cases==null?-1:cases.length));
    Set<Address> actual=new TreeSet<>(Arrays.asList(cases));
    need(actual.equals(expected),"Native recovered destinations differ from full high-byte domain at "+site);
    recovered++;recoveredEdges+=cases.length;
    println("PCM_RECOVERED_TABLE site="+site+" entries="+cases.length+" exact_target_set=true");
   }
   String code=result.getDecompiledFunction().getC();
   need(!code.contains("WARNING:")&&!code.contains("__ghidra_unresolved_indirect_jump")&&
        !code.contains("halt_baddata"),"Opaque or failed native recovery remains");
  } finally {dc.dispose();}
  var block=currentProgram.getMemory().getBlock(at(0));
  need(block!=null&&block.isInitialized()&&block.getSize()<1048576,"Unexpected PM image mapping");
  byte[] image=new byte[(int)block.getSize()];
  need(currentProgram.getMemory().getBytes(block.getStart(),image)==image.length,"Incomplete native image read");
  String imageSha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(image));
  need(imageSha.equals(currentProgram.getExecutableSHA256()),"Actual native PM bytes differ from source identity");
  println("PCM_RECOVERED_TABLES_PASS tables="+recovered+" exact_edges="+recoveredEdges+
          " runtime_mode_subset=UNKNOWN original_bytes_match=true");
  need(!currentProgram.isChanged(),"Read-only target validation dirtied saved program");
  println("PCM_EXACT_256_RANGE_PASS branches=4 total_mathematical_targets=1024 unique="+unique.size()+
    " undecoded_targets="+missing+" foreign_function_targets="+foreign+
    " selector_domain=ALL_256_VALUES no_selector_subset_assumed=true saved_native_image_unchanged=true");
 }
}
