//@category Sunplus/Architecture
// LOCAL-ONLY candidate: an explicit native four-instruction constant-LE proof
// opts in one conditional transfer. Other LE sites remain untouched.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import java.math.BigInteger;
import java.util.*;
import java.security.MessageDigest;

public class Rush26NativeProvenLeBranchRecovery extends GhidraScript {
 private static final String IMAGE="d0a391f61b271c3faac77101271df62729bd643862264fa435421f03365b0c3a";
 private void need(boolean valid,String reason){if(!valid)throw new IllegalStateException(reason);}
 private Address pm(int word){return toAddr("PM:"+Integer.toHexString(word));}
 private Instruction ins(int word,String hex,String text)throws Exception{
  Instruction i=currentProgram.getListing().getInstructionAt(pm(word));
  need(i!=null&&i.getLength()==3&&HexFormat.of().formatHex(i.getBytes()).equals(hex)&&i.toString().equals(text),"Original native word mismatch "+pm(word));
  need(currentProgram.getFunctionManager().getFunctionContaining(i.getAddress()).getEntryPoint().equals(pm(0x25dc)),"Unexpected native owner "+pm(word));
  return i;
 }
 private int codeCount(Instruction i,int opcode){int count=0;for(PcodeOp op:i.getPcode())if(op.getOpcode()==opcode)count++;return count;}
 private String c(Function f)throws Exception{
  DecompInterface d=new DecompInterface();d.toggleCCode(true);d.setSimplificationStyle("decompile");
  need(d.openProgram(currentProgram),"Unable to start Analyzer C");
  try{
   DecompileResults r=d.decompileFunction(f,65,monitor);
   need(r.decompileCompleted()&&r.getDecompiledFunction()!=null,"Native C failed: "+r.getErrorMessage());
   return r.getDecompiledFunction().getC();
  }finally{d.dispose();}
 }
 private int warnings(String c){return c.split("WARNING:",-1).length-1;}
 private String wholeNativeSHA()throws Exception{
  var space=currentProgram.getAddressFactory().getAddressSpace("PM");var block=currentProgram.getMemory().getBlock(pm(0));
  need(block!=null&&block.isInitialized()&&block.getStart().equals(pm(0)),"Missing original PM image");
  byte[] bytes=new byte[(int)block.getSize()];need(currentProgram.getMemory().getBytes(block.getStart(),bytes)==bytes.length,"Incomplete original image");
  return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
 }
 public void run()throws Exception {
  String[] a=getScriptArgs();need(a.length==1&&(a[0].equals("audit")||a[0].equals("apply")||a[0].equals("readback")),"audit/apply/readback");
  String root=System.getenv("GHIDRA_MCP_PROJECT_ROOT");
  need(root!=null&&root.endsWith("/ac3-constant-branch-candidate/projects"),"Forbidden nonisolated Analyzer");
  need(IMAGE.equals(currentProgram.getExecutableSHA256()),"Source identity changed");
  need(IMAGE.equals(wholeNativeSHA()),"Original native PM bytes changed");
  need(currentProgram.getFunctionManager().getFunctionCount()==166,"Unexpected native function inventory");
  Function owner=currentProgram.getFunctionManager().getFunctionAt(pm(0x25dc));
  need(owner!=null&&owner.getBody().contains(pm(0x2630)),"Wrong native function body");
  ins(0x262c,"40000a","LDI AR,0x0");
  ins(0x262d,"400074","LDI AY0,0x7");
  ins(0x262e,"26e20f","AF = AR - AY0");
  Instruction preserved=ins(0x262f,"401e00","LDI AX0,0x1e0");
  Instruction branch=ins(0x2630,"1a63a3","IF LE JUMP 0x263a");
  need(codeCount(preserved,PcodeOp.CBRANCH)==0,"AX0 assignment branches");
  for(PcodeOp op:preserved.getPcode()) if(op.getOutput()!=null) {
   String target=op.getOutput().toString().toLowerCase(Locale.ROOT);
   need(!target.contains("azf")&&!target.contains("anf")&&!target.contains("avf"),"AX0 immediate changes required LE flags");
  }
  for(int word=0x262d;word<=0x2630;word++){
   for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(pm(word)))
    if(ref.getReferenceType().isFlow() && !ref.getFromAddress().equals(pm(word-1)))
     throw new IllegalStateException("Foreign entry bypasses constant-LE proof: "+ref);
  }
  need(0-7<0,"Native arithmetic proof invalid");
  need(Arrays.asList(branch.getFlows()).contains(pm(0x263a)),"Original direct branch destination changed");
  Register mode=currentProgram.getProgramContext().getRegister("codec_le_proven_taken");
  need(mode!=null,"Candidate SLEIGH context was not loaded into local Ghidra");
  BigInteger existing=currentProgram.getProgramContext().getValue(mode,pm(0x2630),false);
  boolean proved=BigInteger.ONE.equals(existing);
  if(a[0].equals("readback")){
   need(proved,"Saved proven-branch context absent");
   need(codeCount(branch,PcodeOp.CBRANCH)==0 && codeCount(branch,PcodeOp.BRANCH)==1,"Saved native target remains conditional");
   int wc=warnings(c(owner));need(wc==0,"Readback C diagnostic not eliminated: "+wc);
   println("PROVEN_LE_READBACK_PASS owner=PM:25dc warning_lines=0 native_bytes_unchanged=true");
   return;
  }
  int old=warnings(c(owner));need(old==3,"Expected 3 native dead-branch C warnings; found "+old);
  need(!proved&&codeCount(branch,PcodeOp.CBRANCH)>=1,"Branch already specialized");
  println("PROVEN_LE_BASELINE owner=PM:25dc warning_lines="+old+" native_LE_taken=true all_foreign_incoming=0");
  if(a[0].equals("audit")){println("PROVEN_LE_AUDIT_PASS change=false");return;}
  need(!currentProgram.isChanged(),"Pre-existing unsaved edits");
  int tx=currentProgram.startTransaction("Native-verified conditional LE constant-fold specialization (isolated)");boolean accepted=false;
  try{
   currentProgram.getListing().clearCodeUnits(pm(0x2630),pm(0x2630).add(2),true);
   currentProgram.getProgramContext().setValue(mode,pm(0x2630),pm(0x2630),BigInteger.ONE);
   var command=new DisassembleCommand(new AddressSet(pm(0x2630),pm(0x2630).add(2)),null,true);
   command.enableCodeAnalysis(false);
   need(command.applyTo(currentProgram,monitor),"Native re-decode failed: "+command.getStatusMsg());
   Instruction after=ins(0x2630,"1a63a3","IF LE JUMP 0x263a");
   need(codeCount(after,PcodeOp.CBRANCH)==0&&codeCount(after,PcodeOp.BRANCH)==1,"Native conditional was not proved as direct transfer");
   need(IMAGE.equals(wholeNativeSHA())&&currentProgram.getFunctionManager().getFunctionCount()==166,"Firmware or function count changed");
   int now=warnings(c(owner));println("PROVEN_LE_C_DIFF owner=PM:25dc warnings="+old+"->"+now);
   need(now==0,"No warning reduction, rollback candidate");
   accepted=true;
  }finally{
   currentProgram.endTransaction(tx,accepted);
   println("PROVEN_LE_TRANSACTION="+(accepted?"COMMITTED_LOCAL":"ROLLED_BACK"));
  }
  need(accepted,"Native branch candidate not accepted");
  println("PROVEN_LE_APPLY_PASS owner=PM:25dc warning_lines=3->0 native_bytes_unchanged=true");
 }
}
