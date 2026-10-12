// Read-only default; pass "apply" only after a verified backup.
// Scoped to PCM PM:07A6..07B2. Does not rebuild the whole program.
//@category Sunplus/RUSH
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.TreeMap;
import java.util.Arrays;
import java.security.MessageDigest;
import java.util.Map;
import java.util.TreeSet;

public class SunplusPcmSequentialCePersistMigration extends GhidraScript {
    private final long FIRST=0x07a6, LAST=0x07b2, ENTRY=0x0753;
    private Address pm(long word) {
        return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",word));
    }
    private String hex(byte[] input) {
        StringBuilder sb=new StringBuilder();
        for(byte b:input)sb.append(String.format("%02x", b & 255));
        return sb.toString();
    }
    private int conditional(Address a) {
        Instruction i=currentProgram.getListing().getInstructionAt(a);
        if(i==null)return -1;
        int count=0;
        for(PcodeOp op:i.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)count++;
        return count;
    }
    private String refs(Address a) {
        TreeSet<String> target=new TreeSet<>();
        for(Reference r:currentProgram.getReferenceManager().getReferencesFrom(a))
            target.add(r.getToAddress().toString()+":"+r.getReferenceType().toString());
        return target.toString();
    }
    private String c(Function f) {
        DecompInterface ifc=new DecompInterface();
        try {
            if(!ifc.openProgram(currentProgram))throw new IllegalStateException("decompiler open");
            DecompileResults res=ifc.decompileFunction(f,45,monitor);
            if(!res.decompileCompleted() || res.getDecompiledFunction()==null)
                throw new IllegalStateException("decompiler: "+res.getErrorMessage());
            return res.getDecompiledFunction().getC();
        } finally { ifc.dispose(); }
    }
    private int countLoops(String c) {
        int loops=0;
        java.util.regex.Matcher m=java.util.regex.Pattern.compile("\\bdo\\s*\\{").matcher(c);
        while(m.find())loops++;
        return loops;
    }
    private String programBytesSha256() throws Exception {
        byte[] image = new byte[25052];
        int read=currentProgram.getMemory().getBytes(pm(0),image);
        must(read==image.length,"PM image shorter than expected");
        return hex(MessageDigest.getInstance("SHA-256").digest(image));
    }
    private Map<String,String> savedFunctionInventory() {
        Map<String,String> m=new TreeMap<>();
        for(Function f: currentProgram.getFunctionManager().getFunctions(true)) {
            m.put(f.getEntryPoint().toString(),f.getName()+"|"+f.getBody().getNumAddresses());
        }
        return m;
    }
    private void must(boolean value,String error) {
        if(!value)throw new IllegalStateException(error);
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        String mode=args.length==0?"audit":args[0];
        must(mode.equals("audit") || mode.equals("apply"),"mode must be audit|apply");
        must("pcm-profile.bin".equals(currentProgram.getName()),"unexpected program name");
        must("SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().toString()),"unexpected language");
        must(currentProgram.getFunctionManager().getFunctionCount()==115,"function inventory changed");
        Function owner=currentProgram.getFunctionManager().getFunctionAt(pm(ENTRY));
        must(owner!=null && owner.getBody().contains(pm(FIRST)) && owner.getBody().contains(pm(LAST)),"function boundary mismatch");
        Instruction first=currentProgram.getListing().getInstructionAt(pm(FIRST));
        Instruction second=currentProgram.getListing().getInstructionAt(pm(0x07ad));
        must(first!=null && second!=null && first.toString().contains("DO") && second.toString().contains("DO"),"unexpected native DO sites");
        must(first.toString().contains("CE") && second.toString().contains("CE"),"wrong loop terminator");
        Register endReg=currentProgram.getLanguage().getRegister("codec_ce_loop_end");
        Register nestedReg=currentProgram.getLanguage().getRegister("codec_ce_nested_mode");
        Register directReg=currentProgram.getLanguage().getRegister("codec_ce_direct_backedge");
        Register backReg=currentProgram.getLanguage().getRegister("codec_ce_direct_start");
        must(endReg!=null && nestedReg!=null && directReg!=null && backReg!=null,
             "missing direct CE context in current SLEIGH");
        Map<Long,String> original=new LinkedHashMap<>();
        Map<Long,String> refMap=new LinkedHashMap<>();
        for(long n=FIRST;n<=LAST;n++) {
            Address addr=pm(n);
            Instruction ins=currentProgram.getListing().getInstructionAt(addr);
            must(ins!=null && ins.getBytes().length==3,"unexpected instruction or width "+addr);
            original.put(n,hex(ins.getBytes()));
            refMap.put(n,refs(addr));
            for(CommentType type:CommentType.values()) {
                String comment=ins.getComment(type);
                must(comment==null || comment.isBlank(),"comment in target range: "+addr);
            }
        }
        String rawHash=programBytesSha256();
        Map<String,String> functions=savedFunctionInventory();
        Function gm5=currentProgram.getFunctionManager().getFunctionAt(pm(0x12a3));
        Function kernel=currentProgram.getFunctionManager().getFunctionAt(pm(0x06a2));
        must(gm5!=null && kernel!=null,"GM5/kernel entry missing");
        String gm5C=c(gm5),kernelC=c(kernel);
        println("PCM_CE_PRECHECK GM5 total_loops="+countLoops(gm5C)+
            " do_loops="+(gm5C.split(java.util.regex.Pattern.quote("do {"),-1).length-1)+
            " warnings="+(gm5C.split("WARNING: Removing unreachable block",-1).length-1)+
            " kernel_warnings="+(kernelC.split("WARNING: Removing unreachable block",-1).length-1));
        must(countLoops(gm5C)==8 && !gm5C.contains("WARNING: Removing unreachable block"),
             "GM5 known-good acceptance broken");
        must(!kernelC.contains("WARNING: Removing unreachable block"),
             "PCM kernel known-good acceptance broken");
        int a=conditional(pm(0x07a7)),b=conditional(pm(0x07b2));
        println("PCM_CE_BASELINE first="+a+" second="+b+" functions=115 range=PM:07A6..07B2 bytes="+original.size()*3);
        for(long n:new long[]{0x07a6,0x07a7,0x07ad,0x07b2}) {
            Address at=pm(n);
            println("PCM_CE_CONTEXT "+at+" end="+currentProgram.getProgramContext().getValue(endReg,at,false)+
              " nested="+currentProgram.getProgramContext().getValue(nestedReg,at,false));
        }
        if(mode.equals("audit")){println("PCM_CE_AUDIT=PASS (no changes)");return;}
        must(a==0 && b==0,"existing back-edge detected; refuse duplicate repair");
        int transaction=currentProgram.startTransaction("Targeted PCM CE decode PM:07A6..07B2");
        boolean commit=false;
        try {
            AddressSet range=new AddressSet(pm(FIRST),pm(LAST));
            currentProgram.getListing().clearCodeUnits(pm(FIRST),pm(LAST),true);
            currentProgram.getProgramContext().setValue(nestedReg,pm(FIRST),pm(LAST),BigInteger.ZERO);
            // Set a proven END flag only at native DO targets; no guessed nesting.
            currentProgram.getProgramContext().setValue(endReg,pm(0x07a7),pm(0x07a7),BigInteger.ONE);
            currentProgram.getProgramContext().setValue(endReg,pm(0x07b2),pm(0x07b2),BigInteger.ONE);
            // Source DO targets and fallthrough proved in the native PM stream.
            currentProgram.getProgramContext().setValue(directReg,pm(0x07a7),pm(0x07a7),BigInteger.ONE);
            currentProgram.getProgramContext().setValue(directReg,pm(0x07b2),pm(0x07b2),BigInteger.ONE);
            currentProgram.getProgramContext().setValue(backReg,pm(0x07a7),pm(0x07a7),BigInteger.valueOf(0x07a7));
            currentProgram.getProgramContext().setValue(backReg,pm(0x07b2),pm(0x07b2),BigInteger.valueOf(0x07ae));
            DisassembleCommand cmd=new DisassembleCommand(pm(FIRST),range,true);
            cmd.enableCodeAnalysis(false);
            must(cmd.applyTo(currentProgram,monitor),"disassembly failed: "+cmd.getStatusMsg());
            for(long n=FIRST;n<=LAST;n++) {
                Instruction ins=currentProgram.getListing().getInstructionAt(pm(n));
                must(ins!=null && original.get(n).equals(hex(ins.getBytes())),"decoded bytes/instruction mismatch PM:"+Long.toHexString(n));
                if(!refMap.get(n).equals(refs(pm(n)))) {
                    String oldRefs=refMap.get(n), newRefs=refs(pm(n));
                    String target=n==0x07a6?"PM:07a7":n==0x07ad?"PM:07b2":"";
                    boolean reclassified=(n==0x07a6 || n==0x07ad) &&
                        oldRefs.equals("["+target+":READ]") &&
                        newRefs.equals("["+target+":DATA]");
                    String backwardTarget=n==0x07a7?"PM:07a7":n==0x07b2?"PM:07ae":"";
                    boolean directBackEdge=(n==0x07a7 || n==0x07b2) &&
                        oldRefs.equals("[]") &&
                        newRefs.equals("["+backwardTarget+":CONDITIONAL_JUMP]");
                    must(reclassified || directBackEdge,
                        "unexpected reference delta PM:"+Long.toHexString(n)+" "+oldRefs+" -> "+newRefs);
                    println("PCM_CE_ALLOWED_REF_DELTA PM:"+Long.toHexString(n)+
                        " "+oldRefs+" -> "+newRefs);
                }
            }
            must(conditional(pm(0x07a7))>=1 && conditional(pm(0x07b2))>=1,"missing CE P-code back edges");
            must(currentProgram.getFunctionManager().getFunctionCount()==115,"function count changed");
            Function after=currentProgram.getFunctionManager().getFunctionAt(pm(ENTRY));
            must(after!=null && after.getBody().contains(pm(LAST)) && after.getName().equals(owner.getName()),"function annotation/body changed");
            String pcmAfterC=c(after);
            int loops=countLoops(pcmAfterC);
            println("PCM_CE_C_AFTER_BEGIN\n"+pcmAfterC+"\nPCM_CE_C_AFTER_END");
            must(loops==2,"decompiled C did not recover exactly two loops; loops="+loops);
            must(rawHash.equals(programBytesSha256()),"PM bytes changed");
            must(functions.equals(savedFunctionInventory()),"saved functions/names/bodies changed");
            String gm5After=c(currentProgram.getFunctionManager().getFunctionAt(pm(0x12a3)));
            String kernelAfter=c(currentProgram.getFunctionManager().getFunctionAt(pm(0x06a2)));
            must(countLoops(gm5After)==8 && !gm5After.contains("WARNING: Removing unreachable block"),"GM5 regression");
            must(!kernelAfter.contains("WARNING: Removing unreachable block"),"PCM kernel regression");
            println("PCM_CE_REPAIR_ACCEPTANCE=PASS c_loops="+loops+" Pcode=2/2 bytes_unchanged=13 reference_targets_preserved=13 functions=115 GM5_loops=8 image_sha256="+rawHash);
            commit=true;
        } finally {
            currentProgram.endTransaction(transaction,commit);
            println("PCM_CE_REPAIR_COMMITTED="+commit);
        }
    }
}
