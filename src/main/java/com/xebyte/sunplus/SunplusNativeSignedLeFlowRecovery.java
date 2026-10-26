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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Resolve only machine-proven unconditional signed-LE control flow.
 *
 * <p>Native evidence is a straight-line, single-owner quartet:
 * LDI AR,lhs; LDI AY0,rhs; AF=AR-AY0; flag-preserving LDI AX0,imm;
 * IF LE JUMP target. When 0<=lhs<=rhs<=0x7fff, subtraction cannot
 * overflow and the LE edge must be taken for every machine state.
 *
 * <p>Never infer branch direction from generated C, invented metadata,
 * hard-coded executable addresses, or unconfirmed program input. The
 * processor's native byte identity, flags, source function inventory, and
 * other control-flow entrances are protected. Static equivalence is not a
 * claim of hardware timing or broader firmware semantic completeness.
 */
public final class SunplusNativeSignedLeFlowRecovery {
    private static final Pattern AR=Pattern.compile("^LDI AR,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final Pattern AY=Pattern.compile("^LDI AY0,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final Pattern AX=Pattern.compile("^LDI AX0,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final int MAX_PROOFS=64;
    private record Proof(Instruction conditional,Function owner,byte[] sourceBytes,
                         String sourceText,int lhs,int rhs) {}
    private SunplusNativeSignedLeFlowRecovery() {}

    private static int pcode(Instruction i,int op){
        int n=0;for(var code:i.getPcode())if(code.getOpcode()==op)n++;return n;
    }
    private static boolean nativePM(Instruction ins){
        return ins!=null&&ins.getLength()==3&&"PM".equals(ins.getAddress().getAddressSpace().getName());
    }
    private static byte[] sourceImage(Program p,TaskMonitor monitor)throws Exception {
        MessageDigest h=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
        for(MemoryBlock block:p.getMemory().getBlocks())if(block.isInitialized()){
            Address at=block.getStart();long left=block.getSize();
            while(left>0){
                monitor.checkCancelled();int size=(int)Math.min(left,buf.length);
                if(p.getMemory().getBytes(at,buf,0,size)!=size)
                    throw new IllegalStateException("Source image cannot be read at "+at);
                h.update(buf,0,size);at=at.add(size);left-=size;
            }
        }
        return h.digest();
    }
    private static String inventory(Program p){
        StringBuilder out=new StringBuilder();
        for(Function f:p.getFunctionManager().getFunctions(true))
            out.append(f.getEntryPoint()).append('|').append(f.getName())
               .append('|').append(f.getBody()).append('|').append(f.isThunk())
               .append('|').append(f.hasNoReturn()).append('\n');
        return out.toString();
    }
    private static int warnings(String s){return s.split("WARNING:",-1).length-1;}
    private static int loops(String s){return s.split("do \\{",-1).length-1;}
    private static String generatedC(DecompInterface dc,Function f,TaskMonitor monitor)
            throws Exception {
        DecompileResults result=dc.decompileFunction(f,35,monitor);
        if(!result.decompileCompleted()||result.getDecompiledFunction()==null)
            throw new IllegalStateException("No C for "+f.getEntryPoint());
        String c=result.getDecompiledFunction().getC();
        if(c.isBlank()||c.contains("halt_baddata"))
            throw new IllegalStateException("Unsupported native C at "+f.getEntryPoint());
        return c;
    }
    private static boolean unexpectedInflow(Program p,Address first,Address branch){
        for(Address at=first.add(3);at.compareTo(branch)<=0;at=at.add(3)){
            for(Reference ref:p.getReferenceManager().getReferencesTo(at)){
                if(ref.getReferenceType().isFlow()&&
                   !ref.getFromAddress().equals(at.subtract(3)))return true;
            }
        }
        return false;
    }
    private static List<Proof> candidates(Program p,TaskMonitor monitor)throws Exception {
        Listing listing=p.getListing();var functions=p.getFunctionManager();
        List<Proof> selected=new ArrayList<>();
        for(Instruction branch:listing.getInstructions(true)){
            monitor.checkCancelled();
            if(!nativePM(branch)||!branch.toString().trim().startsWith("IF LE JUMP ")||
                pcode(branch,PcodeOp.CBRANCH)!=1||branch.getFlows().length!=1)continue;
            Address at=branch.getAddress();
            if(at.getAddressableWordOffset()<4)continue;
            Instruction loadAr=listing.getInstructionAt(at.subtract(12));
            Instruction loadAy=listing.getInstructionAt(at.subtract(9));
            Instruction difference=listing.getInstructionAt(at.subtract(6));
            Instruction loadAx=listing.getInstructionAt(at.subtract(3));
            if(!nativePM(loadAr)||!nativePM(loadAy)||!nativePM(difference)||
                !nativePM(loadAx))continue;
            Matcher lhs=AR.matcher(loadAr.toString().trim()),
                    rhs=AY.matcher(loadAy.toString().trim()),
                    extra=AX.matcher(loadAx.toString().trim());
            if(!lhs.matches()||!rhs.matches()||!extra.matches()||
               !"AF = AR - AY0".equals(difference.toString().trim()))continue;
            int a=Integer.parseInt(lhs.group(1),16),b=Integer.parseInt(rhs.group(1),16);
            if(a>0x7fff||b>0x7fff||a>b)continue;
            Function owner=functions.getFunctionContaining(at);
            if(owner==null||owner.isExternal()||
               functions.getFunctionContaining(loadAr.getAddress())!=owner||
               functions.getFunctionContaining(loadAy.getAddress())!=owner||
               functions.getFunctionContaining(difference.getAddress())!=owner||
               functions.getFunctionContaining(loadAx.getAddress())!=owner||
               unexpectedInflow(p,loadAr.getAddress(),at))continue;
            // The fourth load MUST leave the ALU condition latches alone.
            boolean preserves=true;
            for(PcodeOp op:loadAx.getPcode()){
                var out=op.getOutput();
                if(out==null||!out.isRegister())continue;
                for(String flag:new String[]{"AZF","ANF","AVF","ACF"}){
                    Register r=p.getRegister(flag);
                    if(r!=null&&r.getAddress().equals(out.getAddress()))preserves=false;
                }
            }
            if(!preserves)continue;
            selected.add(new Proof(branch,owner,branch.getBytes(),
                branch.toString().trim(),a,b));
            if(selected.size()>MAX_PROOFS)return List.of();
        }
        return selected;
    }
    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,MessageLog log)
            throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
            p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return run(p,monitor,log);}
        catch(CancelledException cancel){throw cancel;}
        catch(Exception failure){log.appendMsg("Sunplus signed native branch",failure.toString());return false;}
    }
    private static boolean run(Program p,TaskMonitor monitor,MessageLog log)throws Exception {
        Register flag=p.getRegister("codec_le_proven_taken");if(flag==null)return true;
        List<Proof> proofs=candidates(p,monitor);if(proofs.isEmpty())return true;
        byte[] original=sourceImage(p,monitor);String functionInventory=inventory(p);
        int nativeFunctions=p.getFunctionManager().getFunctionCount();
        Listing listing=p.getListing();int accepted=0,removed=0;
        for(Proof evidence:proofs){
            monitor.checkCancelled();
            BigInteger previous=p.getProgramContext().getValue(flag,evidence.conditional().getAddress(),false);
            if(BigInteger.ONE.equals(previous))continue;
            if(previous!=null&&previous.signum()!=0)continue;
            Function f=evidence.owner();
            DecompInterface baseline=new DecompInterface();
            if(!baseline.openProgram(p))throw new IllegalStateException("Native C generator unavailable");
            String before;
            try{before=generatedC(baseline,f,monitor);}finally{baseline.dispose();}
            if(warnings(before)==0)continue;
            int tx=p.startTransaction("Source-native proven true signed LE transition");
            boolean commit=false;
            try{
                Address at=evidence.conditional().getAddress();
                Instruction current=listing.getInstructionAt(at);
                if(current==null||!Arrays.equals(current.getBytes(),evidence.sourceBytes())||
                   !current.toString().trim().equals(evidence.sourceText()))
                    throw new IllegalStateException("Native branch source changed at "+at);
                CommentType[] commentTypes={CommentType.EOL,CommentType.PRE,
                    CommentType.POST,CommentType.PLATE,CommentType.REPEATABLE};
                String[] comments=new String[commentTypes.length];
                for(int i=0;i<commentTypes.length;i++)
                    comments[i]=listing.getComment(commentTypes[i],at);
                listing.clearCodeUnits(at,at.add(2),true);
                p.getProgramContext().setValue(flag,at,at,BigInteger.ONE);
                DisassembleCommand cmd=new DisassembleCommand(
                    new AddressSet(at,at.add(2)),null,true);
                cmd.enableCodeAnalysis(false);
                if(!cmd.applyTo(p,monitor))throw new IllegalStateException("Native branch recode rejected "+at);
                Instruction updated=listing.getInstructionAt(at);
                if(updated==null||!Arrays.equals(updated.getBytes(),evidence.sourceBytes())||
                   !updated.toString().trim().equals(evidence.sourceText())||
                   pcode(updated,PcodeOp.CBRANCH)!=0||pcode(updated,PcodeOp.BRANCH)!=1)
                    throw new IllegalStateException("Native branch is not a proven direct transfer "+at);
                for(int i=0;i<comments.length;i++)
                    if(comments[i]!=null)listing.setComment(at,commentTypes[i],comments[i]);
                if(!Arrays.equals(original,sourceImage(p,monitor))||
                   !functionInventory.equals(inventory(p))||
                   p.getFunctionManager().getFunctionCount()!=nativeFunctions)
                    throw new IllegalStateException("Original image or function inventory changed");
                DecompInterface after=new DecompInterface();
                try{
                    if(!after.openProgram(p))throw new IllegalStateException("Updated C unavailable");
                    String now=generatedC(after,f,monitor);
                    int gain=warnings(before)-warnings(now);
                    commit=gain>0&&loops(now)>=loops(before);
                    if(commit){accepted++;removed+=gain;}
                }finally{after.dispose();}
            }catch(Exception unsafe){
                log.appendMsg("Sunplus signed native branch",
                    "Rejected ambiguous source "+evidence.conditional().getAddress()+": "+unsafe);
            }finally{p.endTransaction(tx,commit);}
        }
        log.appendMsg("Sunplus signed native branch",
            "Proven true signed LE transitions="+accepted+
            " native C warnings removed="+removed+
            " machine image/function inventory unchanged; hardware proof UNKNOWN");
        return true;
    }
}
