//@category Sunplus/Architecture
// Isolated native program proof for two IF predicate branches known false.
// Native machine words and full function boundary table remain intact.
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

public class Rush26NativeProvenFalseBranchRecovery extends GhidraScript {
 private static final String SHA="d0a391f61b271c3faac77101271df62729bd643862264fa435421f03365b0c3a";
 private void need(boolean yes,String msg){if(!yes)throw new IllegalStateException(msg);}
 private Address pm(int word){return toAddr("PM:"+Integer.toHexString(word));}
 private Instruction nativeIns(int word,String hex,String text,int ownerWord)throws Exception{
  Instruction i=currentProgram.getListing().getInstructionAt(pm(word));
  need(i!=null&&i.getLength()==3&&HexFormat.of().formatHex(i.getBytes()).equals(hex)&&i.toString().trim().equals(text.trim()),"Native instruction mismatch at "+pm(word));
  Function f=currentProgram.getFunctionManager().getFunctionContaining(pm(word));
  need(f!=null&&f.getEntryPoint().equals(pm(ownerWord)),"Native function owner mismatch "+pm(word));
  return i;
 }
 private int opcode(Instruction i,int code){int n=0;for(PcodeOp op:i.getPcode())if(op.getOpcode()==code)n++;return n;}
 private void proveNoForeignEntry(int start,int finish){
  for(int w=start+1;w<=finish;w++){
   for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(pm(w)))
    if(ref.getReferenceType().isFlow()&&!ref.getFromAddress().equals(pm(w-1)))
     throw new IllegalStateException("Flow enters middle of native proof: "+ref);
  }
 }
 private String nativeHash()throws Exception{
  var block=currentProgram.getMemory().getBlock(pm(0));
  need(block!=null&&block.isInitialized()&&block.getStart().equals(pm(0)),"Missing source PM image");
  byte[] bytes=new byte[(int)block.getSize()];need(currentProgram.getMemory().getBytes(block.getStart(),bytes)==bytes.length,"Native memory short read");
  return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
 }
 private String c(Function f)throws Exception{
  var d=new DecompInterface();d.toggleCCode(true);d.setSimplificationStyle("decompile");
  need(d.openProgram(currentProgram),"Native C unavailable");
  try{var r=d.decompileFunction(f,70,monitor);need(r.decompileCompleted()&&r.getDecompiledFunction()!=null,"Native C failed "+f.getEntryPoint()+" "+r.getErrorMessage());return r.getDecompiledFunction().getC();}
  finally{d.dispose();}
 }
 private int warns(Function f)throws Exception{return c(f).split("WARNING:",-1).length-1;}
 public void run()throws Exception {
  String[] args=getScriptArgs();need(args.length==1&&List.of("audit","apply","readback").contains(args[0]),"Expected audit/apply/readback");
  String root=System.getenv("GHIDRA_MCP_PROJECT_ROOT");
  need(root!=null&&root.endsWith("/ac3-proven-false-branch-candidate/projects"),"Never operate outside the isolated local Ghidra");
  need(SHA.equals(currentProgram.getExecutableSHA256())&&SHA.equals(nativeHash()),"Wrong program/image SHA256");
  need(currentProgram.getFunctionManager().getFunctionCount()==166,"Native function inventory changed");
  var fm=currentProgram.getFunctionManager();Function first=fm.getFunctionAt(pm(0x0781)),second=fm.getFunctionAt(pm(0x1051)),previous=fm.getFunctionAt(pm(0x25dc));
  need(first!=null&&second!=null&&previous!=null,"Original warning owners absent");
  nativeIns(0x07be,"400070","LDI AX0,0x7",0x0781);
  nativeIns(0x07bf,"0d0410","I1 = AX0",0x0781);
  nativeIns(0x07c0,"23301f","AR = 0x0100 - AX0",0x0781);
  Instruction notLe=nativeIns(0x07c1,"1ab383","IF LE JUMP 0x2b38",0x0781);
  nativeIns(0x10f3,"4ffe99","LDI SE,0xffe9",0x1051);
  nativeIns(0x10f4,"0e120f","SR = LSHIFT AR (LO)",0x1051);
  nativeIns(0x10f5,"23861f","AR = SR0 AND 0x0001",0x1051);
  Instruction notNe=nativeIns(0x10f6,"191111","IF NE JUMP 0x1111",0x1051);
  proveNoForeignEntry(0x07be,0x07c1);proveNoForeignEntry(0x10f3,0x10f6);
  need(0x100-7>0&&((0xffff>>>23)&1)==0,"Static branch proof failed");
  need(Arrays.asList(notLe.getFlows()).contains(pm(0x2b38))||args[0].equals("readback"),"Native LE destination mismatch");
  Register flag=currentProgram.getProgramContext().getRegister("codec_branch_proven_not_taken");
  Register positive=currentProgram.getProgramContext().getRegister("codec_le_proven_taken");
  need(flag!=null&&positive!=null,"Candidate architecture context is unavailable");
  need(BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(positive,pm(0x2630),false)),"Previously accepted AC-3 LE specialization lost");
  var ctx=currentProgram.getProgramContext();
  if(args[0].equals("readback")) {
   for(int w:new int[]{0x07c1,0x10f6}) {
    need(BigInteger.ONE.equals(ctx.getValue(flag,pm(w),false)),"Saved context absent "+pm(w));
    Instruction i=currentProgram.getListing().getInstructionAt(pm(w));
    need(opcode(i,PcodeOp.CBRANCH)==0&&opcode(i,PcodeOp.BRANCH)==0,"Saved false branch emits control flow "+pm(w));
   }
   need(warns(first)==0&&warns(second)==0&&warns(previous)==0,"Native C readback contains formerly corrected warnings");
   println("FALSE_BRANCH_READBACK_PASS owners=PM:0781,PM:1051 warnings=0,0 plus_PM25dc=0 native_bytes_unchanged=true");
   return;
  }
  int initialFirst=warns(first),initialSecond=warns(second);
  need(initialFirst==1&&initialSecond==1&&warns(previous)==0,"Unexpected baseline C diagnostics or prior repair lost");
  need(opcode(notLe,PcodeOp.CBRANCH)>0&&opcode(notNe,PcodeOp.CBRANCH)>0,"Conditional sites already modified");
  println("FALSE_BRANCH_BASELINE warning_lines_0781="+initialFirst+" warning_lines_1051="+initialSecond+" original_C=166/166");
  if(args[0].equals("audit")){println("FALSE_BRANCH_AUDIT_PASS modified=false");return;}
  need(!currentProgram.isChanged(),"Existing unsaved edits forbid apply");
  int tx=currentProgram.startTransaction("Bounded native constant false branch instruction specialization");boolean accept=false;
  try{
   for(int at:new int[]{0x07c1,0x10f6}) {
    currentProgram.getListing().clearCodeUnits(pm(at),pm(at).add(2),true);
    ctx.setValue(flag,pm(at),pm(at),BigInteger.ONE);
    var cmd=new DisassembleCommand(new AddressSet(pm(at),pm(at).add(2)),null,true);
    cmd.enableCodeAnalysis(false);need(cmd.applyTo(currentProgram,monitor),"Proven-false native decode failed "+pm(at));
    Instruction i=currentProgram.getListing().getInstructionAt(pm(at));
    need(i!=null&&opcode(i,PcodeOp.CBRANCH)==0&&opcode(i,PcodeOp.BRANCH)==0,"False native branch was not eliminated in Pcode "+pm(at));
   }
   need(SHA.equals(nativeHash())&&fm.getFunctionCount()==166,"Original bytes/owner count changed");
   int nowFirst=warns(first),nowSecond=warns(second);
   println("FALSE_BRANCH_C_DIFF owner_PM0781="+initialFirst+"->"+nowFirst+" owner_PM1051="+initialSecond+"->"+nowSecond);
   need(nowFirst==0&&nowSecond==0,"Both raw warnings must fall or transaction will rollback");
   need(warns(previous)==0,"Already confirmed native LE repair regressed");
   accept=true;
  }finally{currentProgram.endTransaction(tx,accept);println("FALSE_BRANCH_TRANSACTION="+(accept?"COMMITTED_LOCAL":"ROLLED_BACK"));}
  need(accept,"No proved warning improvement");
  println("FALSE_BRANCH_APPLY_PASS owners=PM:0781,PM:1051 warning_lines=2->0 source_bytes_unchanged=true");
 }
}
