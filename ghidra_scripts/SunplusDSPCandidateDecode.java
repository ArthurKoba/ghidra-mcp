//@category Sunplus/Architecture
// Parse the real saved instruction corpus with a private candidate language.
// No global language replacement, ProgramDB creation, native execution or edits.
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.listing.Instruction;
import generic.jar.ResourceFile;
import java.nio.file.*;
import java.security.MessageDigest;
import java.lang.reflect.Constructor;
import java.util.*;
import com.google.gson.*;

public class SunplusDSPCandidateDecode extends GhidraScript {
 public void run()throws Exception{
  String[] args=getScriptArgs();
  if(args.length!=2)throw new IllegalArgumentException("candidate directory; expected SLA sha256");
  if(!currentProgram.getLanguageID().toString().equals("SunplusSPHEAudioDSP:BE:16:default"))throw new Exception("Wrong native ISA");
  Path artifact=Path.of(System.getenv("GHIDRA_MCP_FILE_ROOT")).toRealPath();
  Path dir=Path.of(args[0]).toRealPath();if(!dir.startsWith(artifact.resolve("dsp-candidates")))throw new Exception("Candidate root not permitted");
  Path sla=dir.resolve("sunplus_sphe_audio_dsp.sla");
  String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(sla)));
  if(!sha.equals(args[1]))throw new Exception("Candidate SHA mismatch");
  Language old=currentProgram.getLanguage();
  SleighLanguageDescription description=new SleighLanguageDescription(new LanguageID("SunplusCandidate:BE:16:default"),"Private DSP encoding validation",old.getProcessor(),Endian.BIG,Endian.BIG,16,"default",1,0,false,new HashMap<>(),old.getCompatibleCompilerSpecDescriptions(),new HashMap<>());
  description.setSlaFile(new ResourceFile(sla.toFile()));
  description.setSpecFile(new ResourceFile(dir.resolve("sunplus_sphe_audio_dsp.pspec").toFile()));
  description.setDefsFile(new ResourceFile(dir.resolve("candidate.ldefs").toFile()));
  // Ghidra's constructor is package-private. This creates an isolated language
  // object only; the provider registry and active Program language stay untouched.
  Constructor<SleighLanguage> constructor=SleighLanguage.class.getDeclaredConstructor(SleighLanguageDescription.class);
  constructor.setAccessible(true);SleighLanguage candidate=constructor.newInstance(description);
  boolean initialChanged=currentProgram.isChanged();int version=currentProgram.getDomainFile().getVersion();
  JsonArray differences=new JsonArray(),failures=new JsonArray();int count=0;
  for(Instruction nativeIns:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();if(!nativeIns.getAddress().getAddressSpace().getName().equals("PM"))continue;
   if(++count>65536||nativeIns.getLength()!=3)throw new Exception("Unexpected native instruction bounds");
   var address=candidate.getDefaultSpace().getAddress(nativeIns.getAddress().getOffset());
   byte[] bytes=nativeIns.getBytes();var buffer=new ByteMemBufferImpl(address,bytes,true);
   var context=new ProcessorContextImpl(candidate);
   for(Register reg:candidate.getContextRegisters()){
    Register prior=old.getRegister(reg.getName());if(prior==null)continue;
    var value=currentProgram.getProgramContext().getValue(prior,nativeIns.getAddress(),false);
    if(value!=null)context.setValue(reg,value);
   }
   try{
    var prototype=candidate.parse(buffer,context,false);
    var decoded=new PseudoInstruction(candidate.getAddressFactory(),address,prototype,buffer,context);
    String before=nativeIns.toString(),after=decoded.toString();
    if(!before.equals(after)){
     JsonObject r=new JsonObject();r.addProperty("address",nativeIns.getAddress().toString());r.addProperty("word_address",nativeIns.getAddress().getAddressableWordOffset());r.addProperty("bytes",HexFormat.of().formatHex(bytes));r.addProperty("before",before);r.addProperty("after",after);
     JsonArray ir=new JsonArray();for(var op:decoded.getPcode())ir.add(op.toString());r.add("candidate_pcode",ir);differences.add(r);
    }
   }catch(ghidra.program.model.lang.UnknownInstructionException ex){JsonObject r=new JsonObject();r.addProperty("address",nativeIns.getAddress().toString());r.addProperty("error",ex.toString());failures.add(r);}
  }
  if(currentProgram.getLanguage()!=old||currentProgram.isChanged()!=initialChanged||currentProgram.getDomainFile().getVersion()!=version)throw new Exception("Saved program changed");
  JsonObject r=new JsonObject();r.addProperty("program",currentProgram.getName());r.addProperty("path",currentProgram.getDomainFile().getPathname());r.addProperty("version",version);r.addProperty("source_sha256",currentProgram.getExecutableSHA256());r.addProperty("candidate_sha256",sha);r.addProperty("inspected",count);r.addProperty("decode_failed",failures.size());r.add("differences",differences);r.add("failures",failures);
  println("CANDIDATE_DECODE_JSON_BEGIN");println(new Gson().toJson(r));println("CANDIDATE_DECODE_JSON_END");
 }
}
