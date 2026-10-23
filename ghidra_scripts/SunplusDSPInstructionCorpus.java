//@category Sunplus/Architecture
// Read-only, complete listing inventory for independent assembler comparisons.
// Exports do not replace the saved Analyzer program or prove hardware semantics.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;

public class SunplusDSPInstructionCorpus extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private static final int MAX_WORDS=65536;
 private String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
 private Map<String,Object> row(Object... a){Map<String,Object> m=new LinkedHashMap<>();for(int i=0;i<a.length;i+=2)m.put((String)a[i],a[i+1]);return m;}
 public void run()throws Exception{
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))throw new IllegalStateException("Wrong ISA");
  String[] args=getScriptArgs();if(args.length!=1)throw new IllegalArgumentException("One absolute export directory required");
  String configured=System.getenv("GHIDRA_MCP_FILE_ROOT");if(configured==null)throw new IllegalStateException("Missing artifact root");
  Path root=Path.of(configured).toRealPath();Path out=Path.of(args[0]).toAbsolutePath().normalize();
  if(!out.startsWith(root)||out.equals(root))throw new IllegalArgumentException("Export outside artifact root");
  Files.createDirectories(out);if(!out.toRealPath().startsWith(root))throw new IllegalArgumentException("Export symlink escapes artifact root");
  Path destination=out.resolve(currentProgram.getName()+".instruction-corpus.json");if(Files.exists(destination))throw new IllegalStateException("Refuse overwrite "+destination);
  boolean initialChanged=currentProgram.isChanged();int version=currentProgram.getDomainFile().getVersion();
  AddressSpace pm=currentProgram.getAddressFactory().getAddressSpace("PM");
  if(pm==null||pm.getAddressableUnitSize()!=3||!currentProgram.getLanguage().isBigEndian())throw new IllegalStateException("Invalid PM architecture");
  List<Map<String,Object>> blocks=new ArrayList<>(),instructions=new ArrayList<>(),unclassified=new ArrayList<>(),functions=new ArrayList<>();
  AddressSet codeBytes=new AddressSet(),pmBytes=new AddressSet();int nativeTotal=0,external=0,thunks=0;
  for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
   monitor.checkCancelled();if(f.isExternal())external++;else{nativeTotal++;if(f.isThunk())thunks++;}
   functions.add(row("address",f.getEntryPoint().toString(),"name",f.getName(),"body",f.getBody().toString(),"external",f.isExternal(),"thunk",f.isThunk()));
  }
  // Some Analyzer APIs keep external stubs outside getFunctions(true).
  int externalIteratorCount=0;for(Function f:currentProgram.getFunctionManager().getExternalFunctions()){externalIteratorCount++;}
  int malformed=0,owned=0,words=0;
  for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
   if(!b.getStart().getAddressSpace().equals(pm)||!b.isInitialized())continue;
   if(b.getSize()>3L*MAX_WORDS)throw new IllegalStateException("Unexpected PM block size");
   byte[] raw=new byte[(int)b.getSize()];if(currentProgram.getMemory().getBytes(b.getStart(),raw)!=raw.length)throw new IllegalStateException("Short PM read");
   blocks.add(row("name",b.getName(),"start",b.getStart().toString(),"end",b.getEnd().toString(),"start_byte",b.getStart().getOffset(),"byte_count",raw.length,"sha256",sha(raw),"executable",b.isExecute()));
   pmBytes.add(b.getStart(),b.getEnd());words+=raw.length/3;
  }
  if(words>MAX_WORDS)throw new IllegalStateException("Unexpected total PM inventory");
  for(Instruction i:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();if(!i.getAddress().getAddressSpace().equals(pm)||!pmBytes.contains(i.getAddress()))continue;
   if(i.getLength()!=3||i.getAddress().getOffset()%3!=0||!pmBytes.contains(i.getMinAddress(),i.getMaxAddress())){malformed++;continue;}
   byte[] bytes=i.getBytes();Function owner=currentProgram.getFunctionManager().getFunctionContaining(i.getAddress());if(owner!=null)owned++;
   List<String> direct=new ArrayList<>();for(Address a:i.getFlows())direct.add(a.toString());
   Map<String,Integer> ir=new TreeMap<>();for(PcodeOp p:i.getPcode())ir.merge(p.getMnemonic(),1,Integer::sum);
   instructions.add(row("address",i.getAddress().toString(),"word_address",i.getAddress().getAddressableWordOffset(),"byte_offset",i.getAddress().getOffset(),"bytes",HexFormat.of().formatHex(bytes),"text",i.toString(),"mnemonic",i.getMnemonicString(),"owner",owner==null?null:owner.getEntryPoint().toString(),"flow",i.getFlowType().toString(),"direct_flows",direct,"ir_op_counts",ir));
   codeBytes.add(i.getMinAddress(),i.getMaxAddress());
  }
  AddressSet remaining=pmBytes.subtract(codeBytes);
  for(AddressRange range:remaining.getAddressRanges()){
   unclassified.add(row("start",range.getMinAddress().toString(),"end",range.getMaxAddress().toString(),"bytes",range.getLength(),"classification","NOT_A_DECODED_INSTRUCTION; data or unclassified, not implicitly executable"));
  }
  Map<String,Object> result=row("schema_version",1,"project",currentProgram.getDomainFile().getProjectLocator().getName(),"program_path",currentProgram.getDomainFile().getPathname(),"program",currentProgram.getName(),"saved_version",version,"source_sha256",currentProgram.getExecutableSHA256(),"language",ISA,"compiler",currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString(),"endianness","big","pm_addressable_unit_bytes",3,"dm_addressable_unit_bytes",currentProgram.getAddressFactory().getAddressSpace("DM").getAddressableUnitSize(),"scope","ALL saved listing PM instructions, with and without function owners; no linear decoding of data","native_total",nativeTotal,"external_in_functions",external,"external_stubs",externalIteratorCount,"thunks",thunks,"pm_bytes",pmBytes.getNumAddresses(),"pm_complete_word_slots",words,"decoded_instructions",instructions.size(),"owned_instructions",owned,"unowned_instructions",instructions.size()-owned,"malformed_instructions",malformed,"non_instruction_bytes",remaining.getNumAddresses(),"blocks",blocks,"functions",functions,"instructions",instructions,"unclassified_ranges",unclassified);
  if(malformed!=0||instructions.size()*3L+remaining.getNumAddresses()!=pmBytes.getNumAddresses())throw new IllegalStateException("Inventory accounting failure");
  if(currentProgram.isChanged()!=initialChanged||currentProgram.getDomainFile().getVersion()!=version)throw new IllegalStateException("Program changed during inventory");
  byte[] json=new GsonBuilder().serializeNulls().disableHtmlEscaping().create().toJson(result).getBytes(java.nio.charset.StandardCharsets.UTF_8);
  Files.write(destination,json,StandardOpenOption.CREATE_NEW);if(!Arrays.equals(json,Files.readAllBytes(destination)))throw new IllegalStateException("Export readback differs");
  println("INSTRUCTION_CORPUS_EXPORTED program="+currentProgram.getName()+" native_total="+nativeTotal+" external="+externalIteratorCount+" instructions="+instructions.size()+" unowned="+(instructions.size()-owned)+" non_instruction_bytes="+remaining.getNumAddresses()+" export="+destination+" sha256="+sha(json));
 }
}
