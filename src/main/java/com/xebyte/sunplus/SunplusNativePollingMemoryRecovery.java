package com.xebyte.sunplus;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Recover missing observable DM reads/writes in source-backed native polling
 * loops, without changing executable bytes or guessing a physical MMIO map.
 *
 * A constant-address DM word receives volatile analysis semantics only when
 * the original decoded ISA demonstrates a same-function backward loop that
 * repeatedly reads the word (and optionally writes it). A recognized
 * conditional read-only poll has an exit dependent on changing external
 * state; an unconditional read-modify-write loop has observable writes.
 * Every changed region must already be a sparse DM16 region installed by our
 * native P-code normalizer. This is a static C-effect recovery contract;
 * silicon ownership and peripheral register identity remain UNKNOWN.
 */
public final class SunplusNativePollingMemoryRecovery {
    private static final int MAX_BACKEDGE_WORDS = 64;
    private static final int MAX_CANDIDATES_PER_OWNER = 32;
    private static final int MAX_OWNER_CHANGES = 32;
    private SunplusNativePollingMemoryRecovery() {}

    private static byte[] originalImage(Program p,TaskMonitor monitor)throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        byte[] data=new byte[4096];
        for(MemoryBlock b:p.getMemory().getBlocks()) {
            if(!b.isInitialized())continue;
            Address at=b.getStart();long remaining=b.getSize();
            while(remaining>0) {
                monitor.checkCancelled();int n=(int)Math.min(remaining,data.length);
                if(p.getMemory().getBytes(at,data,0,n)!=n)
                    throw new IllegalStateException("Initialized native image read failed");
                digest.update(data,0,n);at=at.add(n);remaining-=n;
            }
        }
        return digest.digest();
    }
    private static String c(DecompInterface dc,Function f,TaskMonitor monitor)
            throws Exception {
        DecompileResults r=dc.decompileFunction(f,40,monitor);
        if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
            throw new IllegalStateException("Native C unavailable at "+f.getEntryPoint());
        String out=r.getDecompiledFunction().getC();
        if(out.isBlank()||out.contains("halt_baddata"))
            throw new IllegalStateException("Unsupported source-native C at "+f.getEntryPoint());
        return out;
    }
    private static int warnings(String c) {
        return c.split("WARNING:",-1).length-1;
    }
    private static int loops(String c) {
        return c.split("do \\{",-1).length-1;
    }
    private static String nativeNoopOrDeadC(String c) {
        if(c.contains("Do nothing block with infinite loop"))return "INFINITE_EMPTY_POLL";
        if(c.contains("Removing unreachable block"))return "MISSING_OBSERVABLE_BRANCH_EFFECT";
        return "";
    }
    private static boolean nativeWord(Instruction ins) {
        return ins!=null && ins.getLength()==3 &&
            "PM".equals(ins.getAddress().getAddressSpace().getName());
    }
    private static Map<Integer,int[]> dmOps(Instruction ins,int dmId) {
        Map<Integer,int[]> found=new LinkedHashMap<>();
        for(PcodeOp op:ins.getPcode()) {
            int operation=op.getOpcode();
            if(operation!=PcodeOp.LOAD&&operation!=PcodeOp.STORE)continue;
            if(op.getNumInputs()<2||!op.getInput(0).isConstant()||
                op.getInput(0).getOffset()!=dmId||!op.getInput(1).isConstant())continue;
            int width=operation==PcodeOp.LOAD ?
                (op.getOutput()==null?0:op.getOutput().getSize()) :
                (op.getNumInputs()>=3?op.getInput(2).getSize():0);
            if(width!=2)continue;
            long value=op.getInput(1).getOffset();
            if(value<0||value>0xffff)continue;
            int[] effects=found.computeIfAbsent((int)value,k->new int[2]);
            effects[operation==PcodeOp.LOAD?0:1]++;
        }
        return found;
    }
    private static Set<Integer> candidatePollingWords(Program p,Function owner,
            AddressSpace dm,TaskMonitor monitor) throws CancelledException {
        Listing listing=p.getListing();
        TreeSet<Integer> results=new TreeSet<>();
        for(Instruction back:listing.getInstructions(owner.getBody(),true)) {
            monitor.checkCancelled();if(!nativeWord(back)||
                !back.getFlowType().isJump()||back.getFlowType().isComputed()||
                back.getFlowType().isCall())continue;
            boolean conditional=back.getFlowType().isConditional();
            for(Address target:back.getFlows()) {
                if(!"PM".equals(target.getAddressSpace().getName())||
                    !owner.getBody().contains(target))continue;
                long n=back.getAddress().getAddressableWordOffset()-
                    target.getAddressableWordOffset();
                if(n<1||n>MAX_BACKEDGE_WORDS)continue;
                Map<Integer,int[]> access=new LinkedHashMap<>();
                boolean complete=true;
                Address at=target;
                for(int i=0;i<=n;i++,at=at.add(3)) {
                    Instruction ins=listing.getInstructionAt(at);
                    if(!nativeWord(ins)||!owner.getBody().contains(at)){
                        complete=false;break;
                    }
                    for(var op:dmOps(ins,dm.getSpaceID()).entrySet()) {
                        int[] counts=access.computeIfAbsent(op.getKey(),unused->new int[2]);
                        counts[0]+=op.getValue()[0];counts[1]+=op.getValue()[1];
                    }
                }
                if(!complete)continue;
                for(var entry:access.entrySet()) {
                    int[] counts=entry.getValue();
                    // Both forms depend on the observable current DM word.
                    // Conditional polling requires no local writer: otherwise
                    // the observed change may be exclusively internal.
                    if(counts[0]>0&&(conditional?counts[1]==0:counts[1]>0))
                        results.add(entry.getKey());
                }
            }
        }
        return results.size()>MAX_CANDIDATES_PER_OWNER?Set.of():results;
    }
    // An original native STORE to a 16-bit DM word followed by an explicit
    // native LOAD of that word and a flag-dependent conditional branch is a
    // new, observable memory read. It must not be silently replaced by the
    // previous write when asynchronous DM writers have not been excluded.
    // This is a conservative C visibility contract, NOT an assertion that
    // the selected word is an MMIO register or has a known hardware owner.
    // The transaction/whole-owner C gate below admits it only when it removes
    // a real source optimizer warning without losing any other C/DO flow.
    private static Set<Integer> candidateSharedConditionalWords(Program p,
            Function owner,AddressSpace dm,TaskMonitor monitor)
            throws CancelledException {
        Listing listing=p.getListing();TreeSet<Integer> result=new TreeSet<>();
        for(Instruction branch:listing.getInstructions(owner.getBody(),true)){
            monitor.checkCancelled();if(!nativeWord(branch)||
               !branch.getFlowType().isConditional()||
               !branch.getFlowType().isJump()||branch.getFlows().length!=1)
                continue;
            String name=branch.toString().trim();
            if(!name.startsWith("IF EQ JUMP ")&&
               !name.startsWith("IF NE JUMP "))continue;
            if(branch.getAddress().getAddressableWordOffset()<3)continue;
            Instruction flags=listing.getInstructionAt(branch.getAddress().subtract(3));
            Instruction load=listing.getInstructionAt(branch.getAddress().subtract(6));
            if(!nativeWord(flags)||!nativeWord(load)||
               !owner.getBody().contains(flags.getAddress())||
               !owner.getBody().contains(load.getAddress())||
               !"AR = AR + 0".equals(flags.toString().trim())||
               !load.toString().trim().startsWith("DMREAD AR,0x"))continue;
            for(var read:dmOps(load,dm.getSpaceID()).entrySet()) {
                if(read.getValue()[0]<1)continue;
                int word=read.getKey();
                boolean nativeWriter=false;
                for(int delta=1;delta<=16;delta++) {
                    long at=load.getAddress().getAddressableWordOffset()-delta;
                    if(at<0)break;
                    Address where=p.getAddressFactory().getAddress(String.format("PM:%04x",at));
                    Instruction ins=listing.getInstructionAt(where);
                    if(!nativeWord(ins)||!owner.getBody().contains(where)||
                       ins.getFlowType().isCall()||ins.getFlowType().isJump()||
                       ins.getFlowType().isTerminal()||
                       ins.toString().trim().startsWith("DO "))break;
                    int[] effects=dmOps(ins,dm.getSpaceID()).get(word);
                    if(effects!=null&&effects[1]>0){nativeWriter=true;break;}
                }
                if(nativeWriter)result.add(word);
            }
        }
        return result.size()>MAX_CANDIDATES_PER_OWNER?Set.of():result;
    }

    private static boolean eligibleDm(Program p,Address at,MemoryBlock b) {
        if(b==null||b.isVolatile()||b.isInitialized()||!b.isRead()||!b.isWrite()||
            !b.getName().startsWith("SUNPLUS_DM16_"))return false;
        var data=p.getListing().getDataContaining(at);
        if(data==null||!data.getAddress().equals(at)||data.getLength()!=2||
            !"undefined2".equals(data.getDataType().getName()))return false;
        Symbol sym=p.getSymbolTable().getPrimarySymbol(at);
        return sym==null||sym.getSource()!=SourceType.USER_DEFINED;
    }
    private static void makeOneWordVolatile(Program p,Address address)throws Exception {
        Memory memory=p.getMemory();MemoryBlock block=memory.getBlock(address);
        if(!eligibleDm(p,address,block))throw new IllegalStateException("DM word no longer eligible "+address);
        // Ghidra applies volatility to memory blocks, not individual words.
        // Split exactly at the native DM-word boundary to protect neighbors.
        if(!block.getStart().equals(address))memory.split(block,address);
        block=memory.getBlock(address);
        Address after=address.add(2);
        if(block.getEnd().compareTo(after)>=0)memory.split(block,after);
        block=memory.getBlock(address);
        if(!block.getStart().equals(address)||block.getSize()!=2)
            throw new IllegalStateException("Native DM word isolation failed "+address);
        block.setVolatile(true);
    }

    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,MessageLog log)
            throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
                p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try {
            return run(p,monitor,log);
        }catch(CancelledException cancelled){throw cancelled;}
        catch(Exception problem){
            log.appendMsg("Sunplus native observable DM",problem.toString());
            return false;
        }
    }
    private static boolean run(Program p,TaskMonitor monitor,MessageLog log)throws Exception {
        AddressSpace dm=p.getAddressFactory().getAddressSpace("DM");
        if(dm==null||dm.getAddressableUnitSize()!=2)return true;
        Map<Function,String> baseline=new LinkedHashMap<>();
        Map<Function,Set<Integer>> candidates=new LinkedHashMap<>();
        DecompInterface dc=new DecompInterface();
        try {
            if(!dc.openProgram(p))throw new IllegalStateException("Native C generator unavailable");
            for(Function f:p.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();if(f.isExternal())continue;
                String current=c(dc,f,monitor);
                if(nativeNoopOrDeadC(current).isEmpty())continue;
                Set<Integer> source=new TreeSet<>(candidatePollingWords(p,f,dm,monitor));
                source.addAll(candidateSharedConditionalWords(p,f,dm,monitor));
                Set<Integer> words=new LinkedHashSet<>();
                for(int word:source){
                    Address address=dm.getAddress((long)word*2);
                    if(eligibleDm(p,address,p.getMemory().getBlock(address)))words.add(word);
                }
                if(!words.isEmpty()){
                    baseline.put(f,current);candidates.put(f,words);
                }
                if(candidates.size()>MAX_OWNER_CHANGES)return true;
            }
        }finally{dc.dispose();}
        if(candidates.isEmpty())return true;
        byte[] hash=originalImage(p,monitor);
        int originalNativeCount=p.getFunctionManager().getFunctionCount();
        int restoredOwners=0,restoredWords=0,removedWarnings=0;
        for(var entry:candidates.entrySet()) {
            monitor.checkCancelled();Function owner=entry.getKey();
            String before=baseline.get(owner);
            int tx=p.startTransaction("Source-proven observable DM polling memory");
            boolean accepted=false;
            try {
                int activated=0;
                for(int word:entry.getValue()) {
                    Address address=dm.getAddress((long)word*2);
                    if(!eligibleDm(p,address,p.getMemory().getBlock(address)))continue;
                    makeOneWordVolatile(p,address);activated++;
                }
                if(activated==0)continue;
                DecompInterface after=new DecompInterface();
                try {
                    if(!after.openProgram(p))throw new IllegalStateException("No native C generator");
                    String updated=c(after,owner,monitor);
                    int reduction=warnings(before)-warnings(updated);
                    accepted=reduction>0&&loops(updated)>=loops(before)&&
                        !Arrays.equals(new byte[0],hash)&&
                        p.getFunctionManager().getFunctionCount()==originalNativeCount&&
                        Arrays.equals(hash,originalImage(p,monitor));
                    if(accepted) {
                        restoredOwners++;restoredWords+=activated;removedWarnings+=reduction;
                    }
                }finally{after.dispose();}
            }catch(Exception fail){
                log.appendMsg("Sunplus native observable DM", "Skip unsafe source poll "+
                    owner.getEntryPoint()+": "+fail.getMessage());
            }finally{p.endTransaction(tx,accepted);}
        }
        log.appendMsg("Sunplus native observable DM",
            "Source-backed observable DM restored functions="+restoredOwners+
            " volatile_words="+restoredWords+" C_warnings_removed="+removedWarnings+
            " original_source_unchanged=true; hardware MMIO identity UNKNOWN");
        return true;
    }
}
