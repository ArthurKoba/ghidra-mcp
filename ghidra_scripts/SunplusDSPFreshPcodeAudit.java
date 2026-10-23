//@category Sunplus/Architecture
// Read-only current-SLEIGH parse comparison with saved native Ghidra P-code.
// Reports stale decoder semantics WITHOUT suppressing warnings or editing GZF.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
public class SunplusDSPFreshPcodeAudit extends GhidraScript {
 private static final String ISA="SunplusSPHEAudioDSP:BE:16:default";
 private String ops(PcodeOp[] list){var result=new StringBuilder();for(PcodeOp op:list)result.append(op.toString()).append(';');return result.toString();}
 // Same byte-preserving unique-space canonicalization used by the existing
 // native variable-shift proof. Recompiled temporary offsets are not behavior.
 private String node(Varnode value,Map<Long,Integer> bytes){
  if(value==null)return "-";
  if(!value.isUnique())return value.getAddress().getAddressSpace().getName()+":"+value.getOffset()+":"+value.getSize();
  StringBuilder result=new StringBuilder("u[");
  for(int n=0;n<value.getSize();n++){long at=value.getOffset()+n;bytes.putIfAbsent(at,bytes.size());result.append(bytes.get(at)).append(',');}
  return result.append(']').toString();
 }
 private String normalized(PcodeOp[] operations){
  Map<Long,Integer> bytes=new HashMap<>();StringBuilder result=new StringBuilder();
  for(PcodeOp op:operations){result.append(op.getOpcode()).append(':').append(node(op.getOutput(),bytes));for(Varnode in:op.getInputs())result.append('|').append(node(in,bytes));result.append(';');}
  return result.toString();
 }
 private String sha(String value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}
 private JsonObject reportRow(Object... args){JsonObject row=new JsonObject();for(int n=0;n<args.length;n+=2)row.addProperty((String)args[n],String.valueOf(args[n+1]));return row;}
 public void run()throws Exception {
  if(currentProgram==null||!ISA.equals(currentProgram.getLanguageID().getIdAsString()))throw new Exception("Wrong Sunplus DSP ISA");
  String[] argv=getScriptArgs();if(argv.length<1||argv.length>2||(argv.length==2&&!argv[1].equals("strict-normalized")))throw new IllegalArgumentException("Output directory [strict-normalized]");
  boolean strict=argv.length==2;
  String fileRoot=System.getenv("GHIDRA_MCP_FILE_ROOT");if(fileRoot==null)throw new IllegalStateException("File root unavailable");
  Path sandbox=Path.of(fileRoot).toRealPath(),out=Path.of(argv[0]).toAbsolutePath().normalize();
  if(!out.startsWith(sandbox)||out.equals(sandbox))throw new IllegalArgumentException("Outside permitted artifact path");
  Files.createDirectories(out);if(!out.toRealPath().startsWith(sandbox))throw new IllegalStateException("Unexpected output symlink");
  Path report=out.resolve(currentProgram.getName()+".pcode-delta.json");if(Files.exists(report))throw new IllegalStateException("Refuse overwrite of saved P-code audit");
  Language language=currentProgram.getLanguage();int version=currentProgram.getDomainFile().getVersion();boolean modified=currentProgram.isChanged();
  int scanned=0,changes=0,rendered=0,failures=0,contextCount=0,examples=0;
  var byOwner=new TreeMap<String,Integer>();var byMnemonic=new TreeMap<String,Integer>();var changesArr=new JsonArray();var failuresArr=new JsonArray();
  for(Instruction ins:currentProgram.getListing().getInstructions(true)){
   monitor.checkCancelled();if(!ins.getAddress().getAddressSpace().getName().equals("PM"))continue;
   if(++scanned>40000||ins.getLength()!=3)throw new IllegalStateException("Not the expected bounded PM24 instruction inventory");
   byte[] code=ins.getBytes();var buffer=new ByteMemBufferImpl(ins.getAddress(),code,true);
   ProcessorContextImpl context=new ProcessorContextImpl(language);
   for(Register reg:language.getContextRegisters()){
    var v=currentProgram.getProgramContext().getValue(reg,ins.getAddress(),false);
    if(v!=null){context.setValue(reg,v);contextCount++;}
   }
   if(strict){Register mode=language.getRegister("codec_arch_stack_mode");if(mode!=null)context.setValue(mode,java.math.BigInteger.ZERO);}
   try{
    InstructionPrototype proto=language.parse(buffer,context,false);
    Instruction after=new PseudoInstruction(currentProgram.getAddressFactory(),ins.getAddress(),proto,buffer,context);
    if(!ins.toString().trim().equals(after.toString().trim()))rendered++;
    String oldP=strict?normalized(ins.getPcode()):ops(ins.getPcode()),newP=strict?normalized(after.getPcode()):ops(after.getPcode());
    if(oldP.equals(newP))continue;
    changes++;
    Function owner=currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
    String owned=owner==null?"UNKNOWN":owner.getEntryPoint().toString();
    byOwner.merge(owned,1,Integer::sum);byMnemonic.merge(ins.getMnemonicString(),1,Integer::sum);
    var entry=reportRow("address",ins.getAddress(),"source",HexFormat.of().formatHex(code),"before",ins.toString(),
      "fresh",after.toString(),"owner",owned,"original_Pcode_sha",sha(oldP),"fresh_Pcode_sha",sha(newP),
      "old_ops",ins.getPcode().length,"fresh_ops",after.getPcode().length);
    if(examples++<100){entry.addProperty("old_pcode",oldP);entry.addProperty("new_pcode",newP);}
    changesArr.add(entry);
   }catch(Exception error){failures++;failuresArr.add(reportRow("address",ins.getAddress(),"error",error.toString()));}
  }
  if(currentProgram.isChanged()!=modified||currentProgram.getDomainFile().getVersion()!=version||currentProgram.getLanguage()!=language)
   throw new IllegalStateException("Saved program changed during read-only parser audit");
  var result=new JsonObject();
  result.addProperty("program",currentProgram.getName());result.addProperty("native_image_sha256",currentProgram.getExecutableSHA256());
  result.addProperty("saved_version",version);result.addProperty("inspected",scanned);
  result.addProperty("normalized_strict",strict);result.addProperty("Pcode_discrepancies",changes);result.addProperty("text_discrepancies",rendered);
  result.addProperty("parse_failures",failures);result.addProperty("context_assignments",contextCount);
  result.addProperty("scope","read-only native saved Ghidra instruction P-code vs fresh current SLEIGH parse; not a hardware reference");
  result.add("opcode_changes",changesArr);result.add("failures",failuresArr);
  JsonObject grouped=new JsonObject();for(var e:byOwner.entrySet())grouped.addProperty(e.getKey(),e.getValue());result.add("owners",grouped);
  JsonObject mnemonic=new JsonObject();for(var e:byMnemonic.entrySet())mnemonic.addProperty(e.getKey(),e.getValue());result.add("mnemonics",mnemonic);
  Files.writeString(report,new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n");
  println("DSP_FRESH_PCODE_AUDIT program="+currentProgram.getName()+" inspected="+scanned+
    " differences="+changes+" text_differences="+rendered+" parse_failures="+failures+
    " candidate_owners="+byOwner.size()+" context_values="+contextCount+" output="+report);
  if(strict&&(changes!=0||failures!=0||rendered!=0))throw new IllegalStateException("Fresh native compatibility failure: "+changes+" semantic, "+rendered+" text, "+failures+" decoder");
  println("DSP_FRESH_PCODE_AUDIT_PASS");
 }
}
