package com.xebyte.sunplus;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-derived constant-false native DSP IF-NE / IF-LE / IF-EQ control flow.
 *
 * Contracts: (1) signed SE<-15 shifts zero-extended AR (LO) right by >=16,
 * then AND SR0,1 leaves AZF true; (2) an immediate logical AR (HI) shift
 * right by >=16 leaves SR1 zero, followed by AF=SR1+0; (3) AX0 in [0,255]
 * makes 0x100-AX0 positive and IF LE false. All require an unbranched
 * instruction chain with no incoming control edge bypassing the source
 * operations. No firmware address or function name exemptions.
 *
 * Native P-code must become a fallthrough on the exact original instruction;
 * executable bytes, function identities, and original code/loop coverage
 * are preserved. Hardware execution equivalence remains unproven.
 */
public final class SunplusNativeFalseBranchFlowRecovery {
    private static final Pattern SE=Pattern.compile("^LDI SE,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final Pattern AX=Pattern.compile("^LDI AX0,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final Pattern SHIFT=Pattern.compile(
       "^SR = LSHIFT AR BY -0x([0-9a-f]+) \\(HI\\)$",Pattern.CASE_INSENSITIVE);
    private static final Pattern DM_WRITE=Pattern.compile(
        "^DMWRITE\\s+0x([0-9a-f]+),AR$",Pattern.CASE_INSENSITIVE);
    private static final Pattern DM_READ=Pattern.compile(
        "^DMREAD\\s+AR,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final Pattern LDI_AR=Pattern.compile(
        "^LDI AR,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final int MAX_PROOFS=80;
    private record Proof(Instruction branch,Function owner,Address first,
                         byte[] original,String mnemonic,String kind) {}
    private SunplusNativeFalseBranchFlowRecovery() {}
    private static boolean nativeInsn(Instruction ins){
        return ins!=null&&ins.getLength()==3&&
          "PM".equals(ins.getAddress().getAddressSpace().getName());
    }
    private static int pcode(Instruction i,int opcode){
        int n=0;for(var x:i.getPcode())if(x.getOpcode()==opcode)n++;return n;
    }
    private static boolean foreignEntry(Program p,Address first,Address branch){
        for(Address at=first.add(3);at.compareTo(branch)<=0;at=at.add(3))
            for(Reference r:p.getReferenceManager().getReferencesTo(at))
                if(r.getReferenceType().isFlow()&&
                    !r.getFromAddress().equals(at.subtract(3)))return true;
        return false;
    }
    // Exact native DM roundtrip: a nonzero immediate is stored in an
    // ordinary, nonvolatile DM word and then read back without any call,
    // alternate entry, indirect store, or aliased write. AR+0 sets AZF from
    // that same value. Thus IF EQ is structurally false in the STATIC
    // execution model; asynchronous hardware writes remain UNKNOWN.
    private static Address nonzeroDMRoundtrip(Program p,Listing listing,
            Function owner,Instruction branch,TaskMonitor monitor)
            throws CancelledException {
        Address at=branch.getAddress();
        Instruction flags=listing.getInstructionAt(at.subtract(3));
        Instruction read=listing.getInstructionAt(at.subtract(6));
        if(!nativeInsn(flags)||!nativeInsn(read)||
            !"AR = AR + 0".equals(flags.toString().trim())||
            p.getFunctionManager().getFunctionContaining(flags.getAddress())!=owner||
            p.getFunctionManager().getFunctionContaining(read.getAddress())!=owner)
            return null;
        Matcher r=DM_READ.matcher(read.toString().trim());
        if(!r.matches())return null;
        int target=Integer.parseInt(r.group(1),16);
        Address cell=p.getAddressFactory().getAddress(
            String.format("DM:%04x",target));
        MemoryBlock region=p.getMemory().getBlock(cell);
        if(region==null||region.isVolatile()||!region.isRead()||!region.isWrite())
            return null;
        for(int offset=3;offset<=12;offset++){
            monitor.checkCancelled();
            Address candidateAt=at.subtract(3L*offset);
            Instruction write=listing.getInstructionAt(candidateAt);
            if(!nativeInsn(write)||!owner.getBody().contains(candidateAt))return null;
            Matcher dst=DM_WRITE.matcher(write.toString().trim());
            if(!dst.matches()||Integer.parseInt(dst.group(1),16)!=target)continue;
            Instruction constant=listing.getInstructionAt(candidateAt.subtract(3));
            if(!nativeInsn(constant)||!owner.getBody().contains(constant.getAddress()))
                return null;
            Matcher immediate=LDI_AR.matcher(constant.toString().trim());
            if(!immediate.matches()||Integer.parseInt(immediate.group(1),16)==0)
                return null;
            if(foreignEntry(p,constant.getAddress(),branch.getAddress()))
                return null;
            // From the write up to the matching read, all native control
            // steps must be straight-line. P-code STORE destinations must
            // be absolute addresses other than the source DM word.
            for(Address cursor=candidateAt.add(3);
                    cursor.compareTo(read.getAddress())<0;cursor=cursor.add(3)) {
                Instruction intermediate=listing.getInstructionAt(cursor);
                if(!nativeInsn(intermediate)||!intermediate.getFlowType().isFallthrough()||
                   p.getFunctionManager().getFunctionContaining(cursor)!=owner)return null;
                for(var op:intermediate.getPcode()) {
                    if(op.getOpcode()==PcodeOp.CALLOTHER)return null;
                    if(op.getOpcode()==PcodeOp.STORE) {
                        var ptr=op.getInput(1);
                        if(!ptr.isConstant()||ptr.getOffset()==target)
                            return null;
                    }
                }
            }
            return constant.getAddress();
        }
        return null;
    }

    private static List<Proof> plan(Program p,TaskMonitor monitor)throws Exception {
        Listing listing=p.getListing();var fm=p.getFunctionManager();
        List<Proof> found=new ArrayList<>();
        for(Instruction branch:listing.getInstructions(true)){
            monitor.checkCancelled();if(!nativeInsn(branch)||
                !branch.getFlowType().isConditional()||
                pcode(branch,PcodeOp.CBRANCH)!=1||branch.getFlows().length!=1)
                continue;
            String text=branch.toString().trim();
            boolean ne=text.startsWith("IF NE JUMP ");
            boolean le=text.startsWith("IF LE JUMP ");
            boolean eq=text.startsWith("IF EQ JUMP ");
            if(!ne&&!le&&!eq||
                branch.getAddress().getAddressableWordOffset()<3)continue;
            Address b=branch.getAddress();
            Function owner=fm.getFunctionContaining(b);if(owner==null||owner.isExternal())continue;
            Instruction previous=listing.getInstructionAt(b.subtract(3));
            Instruction before=listing.getInstructionAt(b.subtract(6));
            Instruction first=listing.getInstructionAt(b.subtract(9));
            if(!nativeInsn(previous)||!nativeInsn(before)||!nativeInsn(first)||
                fm.getFunctionContaining(previous.getAddress())!=owner||
                fm.getFunctionContaining(before.getAddress())!=owner||
                fm.getFunctionContaining(first.getAddress())!=owner||
                foreignEntry(p,first.getAddress(),b))continue;
            String kind=null;
            if(ne) {
                Matcher shift=SE.matcher(first.toString().trim());
                if(shift.matches()&&
                   "SR = LSHIFT AR (LO)".equals(before.toString().trim())&&
                   "AR = SR0 AND 0x0001".equals(previous.toString().trim())) {
                    int amount=(short)Integer.parseInt(shift.group(1),16);
                    if(amount<=-16)kind="ZERO_LO_BY_NEGATIVE_SE";
                }
                if(kind==null && "AF = SR1 + 0".equals(previous.toString().trim())) {
                    Matcher right=SHIFT.matcher(before.toString().trim());
                    // The immediate HI logical shift alone dominates the
                    // following flag calculation, even when the instruction
                    // just before the shift is a conditional branch. It is
                    // not part of the proof chain; only before -> previous
                    // -> branch must be protected from side entrances.
                    if(right.matches()&&Integer.parseInt(right.group(1),16)>=16&&
                       !foreignEntry(p,before.getAddress(),b))
                        kind="ZERO_HI_OF_RIGHT_16_PLUS";
                }
            }
            if(le){
                Matcher ax=AX.matcher(first.toString().trim());
                if(ax.matches()&&Integer.parseInt(ax.group(1),16)<0x100&&
                    "I1 = AX0".equals(before.toString().trim())&&
                    "AR = 0x0100 - AX0".equals(previous.toString().trim()))
                    kind="POSITIVE_0100_MINUS_AX0";
            }
            Address memoryProof=null;
            if(eq){
                memoryProof=nonzeroDMRoundtrip(p,listing,owner,branch,monitor);
                if(memoryProof!=null)kind="NONZERO_DIRECT_DM_ROUNDTRIP";
            }
            if(kind==null)continue;
            Address proofStart=memoryProof!=null?memoryProof:
                "ZERO_HI_OF_RIGHT_16_PLUS".equals(kind)?
                before.getAddress():first.getAddress();
            found.add(new Proof(branch,owner,proofStart,branch.getBytes(),text,kind));
            if(found.size()>MAX_PROOFS)return List.of();
        }
        return found;
    }
    private static byte[] original(Program p,TaskMonitor monitor)throws Exception {
        MessageDigest h=MessageDigest.getInstance("SHA-256");byte[] b=new byte[8192];
        for(MemoryBlock block:p.getMemory().getBlocks())if(block.isInitialized()){
            Address at=block.getStart();long left=block.getSize();
            while(left>0){
                monitor.checkCancelled();int n=(int)Math.min(left,b.length);
                if(p.getMemory().getBytes(at,b,0,n)!=n)
                    throw new IllegalStateException("Executable/source hash read failed");
                h.update(b,0,n);left-=n;at=at.add(n);
            }
        }
        return h.digest();
    }
    private static String functions(Program p){
        StringBuilder s=new StringBuilder();
        for(Function f:p.getFunctionManager().getFunctions(true))
            s.append(f.getEntryPoint()).append(':').append(f.getName())
             .append(':').append(f.getBody()).append(':').append(f.isThunk()).append('\n');
        return s.toString();
    }
    private static int warnings(String s){return s.split("WARNING:",-1).length-1;}
    private static int loops(String s){return s.split("do \\{",-1).length-1;}
    private static String c(DecompInterface dc,Function f,TaskMonitor monitor)throws Exception {
        DecompileResults r=dc.decompileFunction(f,40,monitor);
        if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
            throw new IllegalStateException("Native C unavailable "+f.getEntryPoint());
        String code=r.getDecompiledFunction().getC();
        if(code.isBlank()||code.contains("halt_baddata"))
            throw new IllegalStateException("Unacceptable native C "+f.getEntryPoint());
        return code;
    }
    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,MessageLog log)
            throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
             p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return run(p,monitor,log);}
        catch(CancelledException cancelled){throw cancelled;}
        catch(Exception failure){
            log.appendMsg("Sunplus native false branch",failure.toString());return false;
        }
    }
    private static boolean run(Program p,TaskMonitor monitor,MessageLog log)throws Exception {
        Register mode=p.getRegister("codec_branch_proven_not_taken");
        if(mode==null)return true;
        List<Proof> selected=plan(p,monitor);
        if(selected.isEmpty())return true;
        byte[] sha=original(p,monitor);String nativeFunctions=functions(p);
        int n=p.getFunctionManager().getFunctionCount();
        int accepted=0,deletedWarnings=0;
        Listing listing=p.getListing();
        for(Proof candidate:selected){
            monitor.checkCancelled();
            Address at=candidate.branch().getAddress();
            BigInteger prior=p.getProgramContext().getValue(mode,at,false);
            if(BigInteger.ONE.equals(prior)||prior!=null&&prior.signum()!=0)continue;
            Function owner=candidate.owner();
            DecompInterface before=new DecompInterface();
            if(!before.openProgram(p))throw new IllegalStateException("Native C engine missing");
            String sourceC;
            try{sourceC=c(before,owner,monitor);}finally{before.dispose();}
            if(warnings(sourceC)==0)continue;
            int tx=p.startTransaction("Native proven false conditional branch");
            boolean commit=false;
            try{
                Instruction source=listing.getInstructionAt(at);
                if(source==null||!Arrays.equals(source.getBytes(),candidate.original())||
                    !candidate.mnemonic().equals(source.toString().trim())||
                    foreignEntry(p,candidate.first(),at))
                    throw new IllegalStateException("Lost source proof "+at);
                CommentType[] types={CommentType.EOL,CommentType.PRE,CommentType.POST,
                                     CommentType.PLATE,CommentType.REPEATABLE};
                String[] comments=new String[types.length];
                for(int i=0;i<types.length;i++)comments[i]=listing.getComment(types[i],at);
                listing.clearCodeUnits(at,at.add(2),true);
                p.getProgramContext().setValue(mode,at,at,BigInteger.ONE);
                DisassembleCommand recode=new DisassembleCommand(
                    new AddressSet(at,at.add(2)),null,true);
                recode.enableCodeAnalysis(false);
                if(!recode.applyTo(p,monitor))throw new IllegalStateException("Branch re-decode failed "+at);
                Instruction after=listing.getInstructionAt(at);
                if(after==null||!Arrays.equals(after.getBytes(),candidate.original())||
                   !candidate.mnemonic().equals(after.toString().trim())||
                   pcode(after,PcodeOp.CBRANCH)!=0||pcode(after,PcodeOp.BRANCH)!=0||
                   !after.getFlowType().isFallthrough())
                    throw new IllegalStateException("Expected source native fallthrough "+at);
                for(int i=0;i<types.length;i++)
                    if(comments[i]!=null)listing.setComment(at,types[i],comments[i]);
                if(!Arrays.equals(sha,original(p,monitor))||
                    !nativeFunctions.equals(functions(p))||
                    p.getFunctionManager().getFunctionCount()!=n)
                    throw new IllegalStateException("Source program identity changed");
                DecompInterface result=new DecompInterface();
                try{
                    if(!result.openProgram(p))throw new IllegalStateException("C generator gone");
                    String generated=c(result,owner,monitor);
                    int delta=warnings(sourceC)-warnings(generated);
                    commit=delta>0&&loops(generated)>=loops(sourceC);
                    if(commit){accepted++;deletedWarnings+=delta;}
                }finally{result.dispose();}
            }catch(Exception rejection){
                log.appendMsg("Sunplus native false branch",
                    "Rejected "+candidate.kind()+" at "+at+": "+rejection);
            }finally{p.endTransaction(tx,commit);}
        }
        log.appendMsg("Sunplus native false branch",
           "Native proven-false transitions="+accepted+
           " C warnings removed="+deletedWarnings+
           " source and function identities preserved; hardware status UNKNOWN");
        return true;
    }
}
