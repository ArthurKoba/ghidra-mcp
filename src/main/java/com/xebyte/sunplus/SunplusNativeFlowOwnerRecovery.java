package com.xebyte.sunplus;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Recover already decoded PM instructions lost from a function's body when
 * native source control flow enters an unowned island. This is an ownership
 * and native-C repair, not an executable-byte decoder or heuristic function
 * merger. Every new owner is anchored by an existing function's native flow.
 * Unknown/indirect branches are not treated as evidence of new references.
 */
public final class SunplusNativeFlowOwnerRecovery {
    private static final int MAX_ROOTS = 100;
    private static final int MAX_WORDS_PER_OWNER = 400;
    private SunplusNativeFlowOwnerRecovery() {}

    private static boolean nativeCall(Instruction ins) {
        String s=ins.toString().trim();
        return s.startsWith("CALL ")||s.matches("IF\\s+\\w+\\s+CALL\\s+.*");
    }
    private static boolean nativeJump(Instruction ins) {
        String s=ins.toString().trim();
        return s.startsWith("JUMP ")||s.matches("IF\\s+\\w+\\s+JUMP\\s+.*");
    }
    private static boolean conditionalRts(Instruction ins) {
        String s=ins.toString().trim();
        return s.startsWith("IF ")&&s.endsWith(" RTS");
    }
    private static boolean isPmCode(Instruction ins) {
        return ins!=null&&ins.getLength()==3&&
            "PM".equals(ins.getAddress().getAddressSpace().getName());
    }
    private static Address next(Instruction ins) {
        return ins.getAddress().add(3);
    }
    private static int cWarnings(String text) {
        return text.split("WARNING:",-1).length-1;
    }
    private static int cLoops(String text) {
        return text.split("do \\{",-1).length-1;
    }
    private static String c(DecompInterface dc,Function f,TaskMonitor monitor) throws Exception {
        DecompileResults result=dc.decompileFunction(f,40,monitor);
        if(!result.decompileCompleted()||result.getDecompiledFunction()==null)
            throw new IllegalStateException("Native C unavailable "+f.getEntryPoint());
        String source=result.getDecompiledFunction().getC();
        if(source.isBlank()||source.contains("halt_baddata"))
            throw new IllegalStateException("Native C incomplete "+f.getEntryPoint());
        return source;
    }
    // An already decoded, source-native counted CE has a known fallthrough
    // even when Ghidra calls it a conditional computed jump. The source DO
    // must encode the exact endpoint and the CE must retain its P-code shape.
    private static Map<Address,Address> ceSuccessors(Program p,TaskMonitor monitor)
            throws CancelledException {
        Map<Address,Address> ends=new LinkedHashMap<>();
        Listing listing=p.getListing();
        for(Instruction ins:listing.getInstructions(true)) {
            monitor.checkCancelled();
            if(!isPmCode(ins)||!ins.toString().trim().startsWith("DO "))continue;
            try {
                byte[] raw=ins.getBytes();
                int bits=(raw[0]&255)<<16|(raw[1]&255)<<8|(raw[2]&255);
                if(bits>>>18!=5||(bits&15)!=14)continue;
                int end=(bits>>>4)&0x3fff;
                Address dst=p.getAddressFactory().getAddress(String.format("PM:%04x",end));
                Instruction ending=listing.getInstructionAt(dst);
                if(!isPmCode(ending))continue;
                boolean ce=false;
                for(PcodeOp op:ending.getPcode())if(op.getOpcode()==PcodeOp.CBRANCH)ce=true;
                if(ce)ends.putIfAbsent(dst,next(ins));
            } catch(ghidra.program.model.mem.MemoryAccessException ignored) {
                // Unknown source byte: not a candidate.
            }
        }
        return ends;
    }
    private static boolean containsReturn(Function f,Listing listing) {
        if(f==null||f.isExternal())return false;
        for(Instruction ins:listing.getInstructions(f.getBody(),true)) {
            if(ins.toString().trim().equals("RTS"))return true;
        }
        return false;
    }
    // A native subroutine can return through an unconditional JUMP to a
    // source-proven shared RTS tail outside its local Ghidra function body.
    // Requiring an RTS *inside* the initial function loses every source CALL
    // continuation after such helpers. This bounded whole-path trace admits
    // only decoded direct source jump/fallthrough edges; it never fabricates
    // CALL/XREF relationships or assumes computed indirect return targets.
    private static boolean sourceProvenReturnThroughTail(Function callee,
            Listing listing) {
        if(callee==null||callee.isExternal())return false;
        ArrayDeque<Address> frontier=new ArrayDeque<>();
        Set<Address> visited=new LinkedHashSet<>();
        boolean reachesNativeRts=false;
        frontier.add(callee.getEntryPoint());
        while(!frontier.isEmpty()) {
            Address at=frontier.removeFirst();
            if(visited.contains(at))continue;
            Instruction ins=listing.getInstructionAt(at);
            if(!isPmCode(ins)||!visited.add(at)||visited.size()>256)return false;
            String nativeText=ins.toString().trim();
            if(nativeText.equals("RTS")){reachesNativeRts=true;continue;}
            if(nativeText.equals("RTI")||nativeText.startsWith("DO ")||
               nativeText.startsWith("POP PC")||nativeCall(ins))return false;
            if(nativeJump(ins)) {
                Address[] targets=ins.getFlows();
                if(targets.length!=1||
                   !"PM".equals(targets[0].getAddressSpace().getName()))return false;
                // A recurrent backwards edge could be a nonterminating loop;
                // do not claim a guaranteed return without a count proof.
                if(targets[0].compareTo(at)<=0)return false;
                frontier.add(targets[0]);
                if(ins.getFlowType().isConditional()) {
                    Address fall=ins.getFallThrough();
                    if(fall==null||!fall.equals(next(ins)))return false;
                    frontier.add(fall);
                }
            }else if(conditionalRts(ins)) {
                reachesNativeRts=true;
                Address fall=ins.getFallThrough();
                if(fall==null||!fall.equals(next(ins)))return false;
                frontier.add(fall);
            }else {
                if(ins.getFlowType().isTerminal()||
                   ins.getFlowType().isComputed()||
                   ins.getFlowType().isCall()||
                   ins.getFlowType().isJump())return false;
                Address fall=ins.getFallThrough();
                if(fall==null||!fall.equals(next(ins)))return false;
                frontier.add(fall);
            }
        }
        return reachesNativeRts;
    }

    private static Set<Address> successors(Instruction ins, Listing listing,
            FunctionManager fm,Map<Address,Address> ce,boolean verifyCall)
            throws CancelledException {
        Set<Address> out=new LinkedHashSet<>();
        String text=ins.toString().trim();
        if(text.equals("RTS")||text.equals("RTI")||text.startsWith("POP PC"))return out;
        if(nativeCall(ins)) {
            Address[] flows=ins.getFlows();
            if(verifyCall && (flows.length!=1 ||
                !(containsReturn(fm.getFunctionAt(flows[0]),listing)||
                  sourceProvenReturnThroughTail(fm.getFunctionAt(flows[0]),listing))))return out;
            if(listing.getInstructionAt(next(ins))!=null)out.add(next(ins));
            return out;
        }
        if(conditionalRts(ins)) {
            if(listing.getInstructionAt(next(ins))!=null)out.add(next(ins));
            return out;
        }
        if(ins.getFallThrough()!=null)out.add(ins.getFallThrough());
        if(nativeJump(ins))out.addAll(Arrays.asList(ins.getFlows()));
        else if(!ins.getFlowType().isComputed())out.addAll(Arrays.asList(ins.getFlows()));
        Address fromDo=ce.get(ins.getAddress());
        if(fromDo!=null) {
            out.add(fromDo);
            if(listing.getInstructionAt(next(ins))!=null)out.add(next(ins));
        }
        return out;
    }
    private static Set<Address> reachableUnowned(Program p,Function source,
            Set<Address> roots,Map<Address,Address> ce,TaskMonitor monitor)
            throws CancelledException {
        Listing listing=p.getListing();FunctionManager fm=p.getFunctionManager();
        ArrayDeque<Address> frontier=new ArrayDeque<>(roots);
        Set<Address> accepted=new LinkedHashSet<>();
        while(!frontier.isEmpty()) {
            monitor.checkCancelled();
            Address at=frontier.removeFirst();
            Function claimed=fm.getFunctionContaining(at);
            if(claimed!=null)continue;
            Instruction ins=listing.getInstructionAt(at);
            if(!isPmCode(ins))continue;
            if(!accepted.add(at))continue;
            if(accepted.size()>MAX_WORDS_PER_OWNER)return Set.of();
            for(Address to:successors(ins,listing,fm,ce,true)) {
                if(!"PM".equals(to.getAddressSpace().getName()))continue;
                if(listing.getInstructionAt(to)!=null)frontier.add(to);
            }
        }
        return accepted;
    }

    /** Only a saved program; the caller persists accepted mutations before CE. */
    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,MessageLog log)
            throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
                p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try {
            Listing listing=p.getListing();FunctionManager fm=p.getFunctionManager();
            Map<Address,Address> ce=ceSuccessors(p,monitor);
            Map<Function,Set<Address>> roots=new LinkedHashMap<>();
            int nativeCount=0;
            int originalFunctionCount=fm.getFunctionCount();
            for(Instruction ins:listing.getInstructions(true)) {
                monitor.checkCancelled();
                if(!isPmCode(ins))continue;
                nativeCount++;
                Function from=fm.getFunctionContaining(ins.getAddress());
                if(from==null||from.isExternal())continue;
                for(Address to:successors(ins,listing,fm,ce,true)) {
                    if(!"PM".equals(to.getAddressSpace().getName())||
                       !isPmCode(listing.getInstructionAt(to))||
                       fm.getFunctionContaining(to)!=null)continue;
                    roots.computeIfAbsent(from,k->new LinkedHashSet<>()).add(to);
                }
            }
            if(roots.size()>MAX_ROOTS)return false;
            Map<Function,Set<Address>> proposed=new LinkedHashMap<>();
            Map<Address,Set<Function>> sourceConsumers=new LinkedHashMap<>();
            for(var entry:roots.entrySet()) {
                Set<Address> island=reachableUnowned(p,entry.getKey(),entry.getValue(),ce,monitor);
                if(island.isEmpty())continue;
                proposed.put(entry.getKey(),island);
                for(Address at:island)
                    sourceConsumers.computeIfAbsent(at,k->new LinkedHashSet<>()).add(entry.getKey());
            }
            // Multi-owner access to ONE common handler is not evidence that
            // ALL code from each consumer is ambiguous. Resolve ownership per
            // native instruction, not per function. In particular, a unique
            // conditional leg may lead into a shared postlude reached by a
            // second caller; rejecting the entire first function loses the
            // uniquely owned leg and creates spurious coverage holes.
            int disputedWords=0;
            for(Set<Function> sources:sourceConsumers.values())
                if(sources.size()>1)disputedWords++;
            int improved=0,owners=0,refused=0;
            for(var entry:proposed.entrySet()) {
                monitor.checkCancelled();
                Function f=entry.getKey();
                Set<Address> nativeWords=new LinkedHashSet<>();
                for(Address at:entry.getValue())
                    if(sourceConsumers.get(at).size()==1)nativeWords.add(at);
                if(nativeWords.isEmpty()){refused++;continue;}
                String baseline;
                DecompInterface old=new DecompInterface();
                try {
                    if(!old.openProgram(p))return false;
                    baseline=c(old,f,monitor);
                } finally { old.dispose(); }
                AddressSet original=new AddressSet(f.getBody());
                int tx=p.startTransaction("Source-native function flow ownership recovery");
                boolean accepted=false;
                try {
                    AddressSet updated=new AddressSet(original);
                    for(Address at:nativeWords) {
                        if(fm.getFunctionContaining(at)!=null||
                           !isPmCode(listing.getInstructionAt(at)))
                            throw new IllegalStateException("Overlapping native owner "+at);
                        updated.add(at,at.add(2));
                    }
                    f.setBody(updated);
                    for(Address at:nativeWords)
                        if(fm.getFunctionContaining(at)!=f)
                            throw new IllegalStateException("Failed PM function ownership "+at);
                    if(fm.getFunctionCount()!=originalFunctionCount)
                        throw new IllegalStateException("Native function inventory changed");
                    DecompInterface dc=new DecompInterface();
                    try {
                        if(!dc.openProgram(p))throw new IllegalStateException("No native C generator");
                        String generated=c(dc,f,monitor);
                        accepted=cWarnings(generated)<=cWarnings(baseline)&&
                            cLoops(generated)>=cLoops(baseline);
                    } finally {dc.dispose();}
                } catch(Exception noProof) {
                    log.appendMsg("Sunplus source native ownership",
                        "Conservative rollback at "+f.getEntryPoint()+": "+noProof.getMessage());
                } finally {p.endTransaction(tx,accepted);}
                if(accepted) {improved+=nativeWords.size();owners++;}
                else refused++;
            }
            int readback=0;
            for(Instruction i:listing.getInstructions(true))if(isPmCode(i))readback++;
            if(readback!=nativeCount)
                throw new IllegalStateException("Native instruction inventory changed "+
                    nativeCount+" -> "+readback);
            log.appendMsg("Sunplus native flow ownership",
                "Source-flow recovered "+improved+" decoded PM words in "+owners+
                " functions; unresolved owners="+refused+"; shared owner-conflict words="+
                disputedWords+" (unassigned); native PM inventory preserved");
            return true;
        } catch(CancelledException cancel) {throw cancel;}
        catch(Exception failure) {
            log.appendMsg("Sunplus native flow ownership",failure.toString());
            return false;
        }
    }
}
