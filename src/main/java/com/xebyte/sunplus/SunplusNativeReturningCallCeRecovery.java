package com.xebyte.sunplus;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-native CALL/CE atomic control recovery.
 *
 * Ghidra can infer CALL_RETURN from a stale no-return callee even when native
 * RTS is reachable. Releasing the false override alone can make native C
 * worse; the next source-encoded CE must be reinterpreted in the SAME
 * transaction. This production pass admits only a non-overlapping, uniquely
 * owned original DO whose encoded CE is immediately after a native returning
 * CALL. Every target comes from original bytes/P-code, never a profile or
 * hardcoded program address. Indirect/ambiguous paths remain UNSUPPORTED.
 */
public final class SunplusNativeReturningCallCeRecovery {
    private SunplusNativeReturningCallCeRecovery() {}
    private static final int MAX_CANDIDATES = 64;
    private static final int MAX_NATIVE_RETURN_SCAN = 512;
    private static final Pattern DO = Pattern.compile(
        "^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
    private record Loop(int first,int end,Function owner,Instruction doInst) {}
    private record Candidate(Loop loop,Instruction call,Instruction ce,
                             Function provider,byte[] callBytes,byte[] ceBytes) {}
    private static boolean pm(Instruction i) {
        return i!=null&&i.getLength()==3 &&
            "PM".equals(i.getAddress().getAddressSpace().getName());
    }
    private static Address word(Program p,int w) {
        return p.getAddressFactory().getAddress(String.format("PM:%04x",w));
    }
    private static int opcode(Instruction i,int type) {
        int count=0;
        for(PcodeOp op:i.getPcode())if(op.getOpcode()==type)count++;
        return count;
    }
    private static int countWarnings(String c) {
        return c.split("WARNING:",-1).length-1;
    }
    private static int countLoops(String c) {
        return c.split("do \\{",-1).length-1;
    }
    private static String c(DecompInterface d,Function f,TaskMonitor monitor)
            throws Exception {
        d.flushCache();
        DecompileResults r=d.decompileFunction(f,35,monitor);
        if(r==null||!r.decompileCompleted()||r.getDecompiledFunction()==null)
            throw new IllegalStateException("UNSUPPORTED original Analyzer C "+f.getEntryPoint());
        String code=r.getDecompiledFunction().getC();
        if(code.isBlank()||code.contains("halt_baddata"))
            throw new IllegalStateException("UNSUPPORTED incomplete native C "+f.getEntryPoint());
        return code;
    }
    private static boolean sourceReachableNativeRts(Function f,Listing listing,
            TaskMonitor monitor)throws CancelledException {
        if(f==null||f.isExternal())return false;
        ArrayDeque<Address> todo=new ArrayDeque<>();
        Set<Address> seen=new LinkedHashSet<>();
        todo.add(f.getEntryPoint());boolean found=false;
        int sourceDo=0,sourceDoStart=-1,sourceDoEnd=-1;
        while(!todo.isEmpty()){
            monitor.checkCancelled();
            Address addr=todo.removeFirst();
            if(!f.getBody().contains(addr))return false;
            if(!seen.add(addr))continue;
            if(seen.size()>MAX_NATIVE_RETURN_SCAN)return false;
            Instruction ins=listing.getInstructionAt(addr);
            if(!pm(ins))return false;
            String text=ins.toString().trim();
            if(text.equals("RTS")) {
                if(opcode(ins,PcodeOp.RETURN)<1)return false;
                found=true;continue;
            }
            if(text.startsWith("IF ")&&text.endsWith(" RTS")) {
                // IF-condition RTS returns on the taken path. Its untaken
                // path is a genuine native fallthrough, not a second CALL.
                // Preserve both paths; a single reachable native RETURN
                // disproves a Ghidra no-return attribute, but does NOT
                // prove that all execution paths terminate.
                Address fall=ins.getFallThrough();
                if(!ins.getFlowType().isConditional()||
                   opcode(ins,PcodeOp.RETURN)!=1||
                   fall==null||!f.getBody().contains(fall)||
                   !pm(listing.getInstructionAt(fall)))return false;
                found=true;
                todo.add(fall);
                continue;
            }
            // A returning provider can contain one native DO/CE loop.
            // Its source word gives the exact endpoint independently of
            // whether the current Analyzer has decoded the CE backedge.
            // The control search below still has to reach a native RTS;
            // nested/invalid DO frames are not inferred as guaranteed exits.
            Matcher counted=DO.matcher(text);
            if(counted.matches()) {
                if(++sourceDo>1)return false;
                byte[] raw;
                try {raw=ins.getBytes();}
                catch(ghidra.program.model.mem.MemoryAccessException bad){return false;}
                int bits=((raw[0]&255)<<16)|((raw[1]&255)<<8)|(raw[2]&255);
                int end=Integer.parseInt(counted.group(1),16);
                int start=(int)addr.getAddressableWordOffset();
                if(bits>>>18!=5||(bits&15)!=14||
                   ((bits>>>4)&0x3fff)!=end||end<=start||
                   end-start>1024||
                   !f.getBody().contains(word(f.getProgram(),end))||
                   !pm(listing.getInstructionAt(word(f.getProgram(),end))))
                    return false;
                sourceDoStart=start;
                sourceDoEnd=end;
            }
            // When the callee's source DO reaches its encoded CE end,
            // Analyzer may expose a computed BRANCHIND instead of an
            // explicit fallthrough. Validate the *source-native* counted
            // control shape and model BOTH machine successors: repeat and
            // CE-zero exit. This is a bounded reachability proof, never
            // an assertion that the original call always terminates.
            if(sourceDoEnd==(int)addr.getAddressableWordOffset()){
                if(text.equals("RTI")||text.equals("RTS")||
                   text.startsWith("DO ")||
                   ins.getFlowType().isCall()||
                   ins.getFlowType().isTerminal()||
                   opcode(ins,PcodeOp.CBRANCH)<1)return false;
                int indirect=opcode(ins,PcodeOp.BRANCHIND);
                int direct=0;
                Address repeated=word(f.getProgram(),sourceDoStart+1);
                for(PcodeOp op:ins.getPcode())
                    if(op.getOpcode()==PcodeOp.BRANCH&&
                       repeated.equals(op.getInput(0).getAddress()))direct++;
                if(!((indirect==1&&opcode(ins,PcodeOp.BRANCH)==0)||
                     (indirect==0&&direct==1&&opcode(ins,PcodeOp.BRANCH)==1)))
                    return false;
                Address successor=addr.add(3);
                if(!f.getBody().contains(successor)||
                   !f.getBody().contains(repeated)||
                   !pm(listing.getInstructionAt(successor))||
                   !pm(listing.getInstructionAt(repeated)))return false;
                todo.add(successor);
                todo.add(repeated);
                continue;
            }
            if(text.equals("RTI")||
               text.contains("POP PC")||text.contains("PUSH PC")||
               ins.getFlowType().isCall()||
               ins.getFlowType().isComputed()||
               ins.getFlowType().isTerminal())return false;
            Address fall=ins.getFallThrough();
            if(fall!=null)todo.add(fall);
            Address[] target=ins.getFlows();
            if(ins.getFlowType().isJump()&&target.length==0)return false;
            if(fall==null&&target.length==0)return false;
            for(Address t:target)todo.add(t);
        }
        return found;
    }
    private static List<Candidate> discover(Program p,TaskMonitor monitor)
            throws Exception {
        Listing listing=p.getListing();
        FunctionManager fm=p.getFunctionManager();
        List<Loop> loops=new ArrayList<>();
        for(Instruction i:listing.getInstructions(true)){
            monitor.checkCancelled();
            if(!pm(i))continue;
            Matcher m=DO.matcher(i.toString().trim());
            if(!m.matches())continue;
            byte[] raw=i.getBytes();
            int bits=((raw[0]&255)<<16)|((raw[1]&255)<<8)|(raw[2]&255);
            int end=Integer.parseInt(m.group(1),16);
            if(bits>>>18!=5||(bits&15)!=14||
               ((bits>>>4)&0x3fff)!=end)continue;
            loops.add(new Loop((int)i.getAddress().getAddressableWordOffset(),
                end,fm.getFunctionContaining(i.getAddress()),i));
        }
        List<Candidate> found=new ArrayList<>();
        Set<Address> seen=new LinkedHashSet<>();
        for(Loop l:loops) {
            if(l.owner==null||l.first>=l.end||l.end-l.first>1024)continue;
            boolean overlap=false;
            for(Loop other:loops)if(other!=l&&
                l.first<=other.end&&other.first<=l.end){overlap=true;break;}
            if(overlap)continue; // nested source frames have their own pass
            Instruction ce=listing.getInstructionAt(word(p,l.end));
            Instruction call=listing.getInstructionAt(word(p,l.end-1));
            if(!pm(ce)||!pm(call)||!l.owner.getBody().contains(ce.getAddress())||
               !l.owner.getBody().contains(call.getAddress())||
               !call.toString().trim().matches("(?i)^CALL\\s+0x[0-9a-f]+$")||
               call.getFlowOverride()!=FlowOverride.CALL_RETURN||
               !call.getFlowType().isCall()||call.getFlows().length!=1||
               call.getFallThrough()!=null||opcode(call,PcodeOp.CALL)!=1||
               opcode(ce,PcodeOp.CBRANCH)<1||opcode(ce,PcodeOp.BRANCHIND)!=1||
               opcode(ce,PcodeOp.BRANCH)!=0||
               !call.getAddress().add(3).equals(ce.getAddress()))continue;
            Address calleeAddress=call.getFlows()[0];
            boolean pcodeTarget=false;
            for(PcodeOp op:call.getPcode())if(op.getOpcode()==PcodeOp.CALL &&
                 op.getInput(0).getAddress().equals(calleeAddress))pcodeTarget=true;
            Function provider=fm.getFunctionAt(calleeAddress);
            if(!pcodeTarget||!sourceReachableNativeRts(provider,listing,monitor))continue;
            if(!seen.add(call.getAddress()))
                throw new IllegalStateException("Duplicate native CALL/CE proof");
            found.add(new Candidate(l,call,ce,provider,call.getBytes(),ce.getBytes()));
            if(found.size()>MAX_CANDIDATES)
                throw new IllegalStateException("Too many native CALL/CE candidates");
        }
        return found;
    }
    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,
            MessageLog log)throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
            p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return run(p,monitor,log);}
        catch(CancelledException cancelled){throw cancelled;}
        catch(Exception failure) {
            boolean clean=!p.isChanged();
            log.appendMsg("Sunplus native returning CALL+CE",
                "UNSUPPORTED: "+failure.getMessage()+" cleanAfterRollback="+clean);
            // Unknown/failed recovery is not an accepted architecture pass.
            return false;
        }
    }
    /**
     * Correct native CALL_RETURN metadata even where no source DO/CE needs
     * a paired change. Composite CALL/CE is ALWAYS left to the atomic
     * recovery above. This general source rule never invents an owner,
     * callee or fallthrough and never treats an unowned site as recovered.
     */
    public static boolean applyPlainReturningCallsAfterSavedAnalysis(Program p,
            TaskMonitor monitor,MessageLog log)throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
                p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return restorePlainReturningCalls(p,monitor,log);}
        catch(CancelledException c){throw c;}
        catch(Exception failure) {
            log.appendMsg("Sunplus source returning CALL metadata",
                "UNSUPPORTED: "+failure+" cleanAfterRollback="+!p.isChanged());
            return false;
        }
    }

    private static boolean restorePlainReturningCalls(Program p,TaskMonitor monitor,
            MessageLog log)throws Exception {
        Listing listing=p.getListing();
        FunctionManager fm=p.getFunctionManager();
        Set<Address> ceEnd=new LinkedHashSet<>();
        for(Instruction i:listing.getInstructions(true)) {
            monitor.checkCancelled();
            if(!pm(i))continue;
            Matcher m=DO.matcher(i.toString().trim());
            if(!m.matches())continue;
            byte[] b=i.getBytes();
            int bits=((b[0]&255)<<16)|((b[1]&255)<<8)|(b[2]&255);
            int end=Integer.parseInt(m.group(1),16);
            if(bits>>>18==5&&(bits&15)==14&&
               ((bits>>>4)&0x3fff)==end)
                ceEnd.add(word(p,end));
        }
        Map<Function,List<Instruction>> byOwner=new LinkedHashMap<>();
        Map<Address,Function> callProviders=new LinkedHashMap<>();
        int unresolved=0;
        for(Instruction i:listing.getInstructions(true)) {
            monitor.checkCancelled();
            if(!pm(i)||i.getFlowOverride()!=FlowOverride.CALL_RETURN||
               !i.toString().trim().matches("(?i)^CALL\\s+0x[0-9a-f]+$"))
                continue;
            Address next=i.getAddress().add(3);
            // A native CALL immediately followed by CE may need changes to
            // the loop backedge in the SAME transaction. Never split them.
            if(ceEnd.contains(next))continue;
            Function owner=fm.getFunctionContaining(i.getAddress());
            Instruction continuation=listing.getInstructionAt(next);
            Address[] flows=i.getFlows();
            Function provider=flows.length==1?fm.getFunctionAt(flows[0]):null;
            int calls=opcode(i,PcodeOp.CALL);
            if(owner==null||owner.isExternal()||
               !owner.getBody().contains(next)||
               !pm(continuation)||flows.length!=1||calls!=1||
               i.getFallThrough()!=null||provider==null||
               !sourceReachableNativeRts(provider,listing,monitor)) {
                unresolved++;
                continue;
            }
            byOwner.computeIfAbsent(owner,k->new ArrayList<>()).add(i);
            callProviders.put(i.getAddress(),provider);
        }
        int repaired=0,unsupported=0;
        for(var row:byOwner.entrySet()) {
            monitor.checkCancelled();
            Function owner=row.getKey();
            // Stale provider.hasNoReturn() metadata is one cause of native
            // CALL_RETURN overrides. Rejecting that attribute before checking
            // source RTS would make the recovery circular. Capture the C and
            // ABI identity of every direct consumer of a provider whose
            // metadata will change, not only the current CALL owner.
            Set<Function> providers=new LinkedHashSet<>();
            for(Instruction call:row.getValue())
                providers.add(callProviders.get(call.getAddress()));
            Set<Function> affected=new LinkedHashSet<>();
            affected.add(owner);
            affected.addAll(providers);
            for(Instruction candidate:listing.getInstructions(true)) {
                monitor.checkCancelled();
                if(!pm(candidate)||opcode(candidate,PcodeOp.CALL)==0)continue;
                Function called=null;
                Address[] targets=candidate.getFlows();
                if(targets.length==1)called=fm.getFunctionAt(targets[0]);
                if(called==null||!providers.contains(called))continue;
                Function caller=fm.getFunctionContaining(candidate.getAddress());
                if(caller!=null&&!caller.isExternal())affected.add(caller);
            }
            if(affected.size()>96) {
                unsupported+=row.getValue().size();
                log.appendMsg("Sunplus source returning CALL metadata",
                    "UNSUPPORTED too many affected caller functions for "+
                    owner.getEntryPoint()+" count="+affected.size());
                continue;
            }
            Map<Function,String> originalC=new LinkedHashMap<>();
            Map<Function,String> originalIdentities=new LinkedHashMap<>();
            Map<Function,Boolean> originalNoReturn=new LinkedHashMap<>();
            boolean baselineUnavailable=false;
            DecompInterface before=new DecompInterface();
            try {
                if(!before.openProgram(p))
                    throw new IllegalStateException("Original native C unavailable");
                for(Function affectedFunction:affected) {
                    monitor.checkCancelled();
                    originalC.put(affectedFunction,c(before,affectedFunction,monitor));
                    originalIdentities.put(affectedFunction,
                        affectedFunction.getName()+"|"+affectedFunction.getBody()+
                        "|"+affectedFunction.getComment());
                    originalNoReturn.put(affectedFunction,affectedFunction.hasNoReturn());
                }
            }catch(CancelledException cancelled){throw cancelled;}
            catch(Exception unavailable) {
                baselineUnavailable=true;
                log.appendMsg("Sunplus source returning CALL metadata",
                    "UNSUPPORTED original C "+owner.getEntryPoint()+
                    ": "+unavailable.getMessage());
            }finally{before.dispose();}
            if(baselineUnavailable) {
                unsupported+=row.getValue().size();
                continue;
            }
            int originalCount=fm.getFunctionCount();
            Map<Address,byte[]> originalBytes=new LinkedHashMap<>();
            for(Instruction ins:row.getValue())
                originalBytes.put(ins.getAddress(),ins.getBytes());
            int tx=p.startTransaction("Source-returning native CALL owner "+owner.getEntryPoint());
            boolean accepted=false;
            String rejectedReason=null;
            try {
                for(Function provider:providers) {
                    monitor.checkCancelled();
                    // Native RTS reachability was proved before this
                    // transaction. Keep correction of the false no-return
                    // metadata and caller continuation indivisible.
                    if(provider.hasNoReturn())provider.setNoReturn(false);
                }
                for(Instruction old:row.getValue()){
                    monitor.checkCancelled();
                    Address at=old.getAddress();
                    old.setFlowOverride(FlowOverride.NONE);
                    Instruction corrected=listing.getInstructionAt(at);
                    if(corrected==null||
                       corrected.getFlowOverride()!=FlowOverride.NONE||
                       !corrected.getAddress().add(3).equals(corrected.getFallThrough())||
                       !Arrays.equals(originalBytes.get(at),corrected.getBytes()))
                        throw new IllegalStateException("Native CALL source fallthrough absent "+at);
                }
                if(fm.getFunctionCount()!=originalCount)
                    throw new IllegalStateException("Native function count changed");
                for(Function affectedFunction:affected) {
                    String currentIdentity=affectedFunction.getName()+"|"+
                        affectedFunction.getBody()+"|"+affectedFunction.getComment();
                    if(!originalIdentities.get(affectedFunction).equals(currentIdentity)||
                       (!providers.contains(affectedFunction)&&
                        !originalNoReturn.get(affectedFunction).equals(
                            affectedFunction.hasNoReturn()))||
                       (providers.contains(affectedFunction)&&
                        affectedFunction.hasNoReturn()))
                        throw new IllegalStateException(
                            "Native CALL affected function identity changed "+
                            affectedFunction.getEntryPoint());
                }
                DecompInterface after=new DecompInterface();
                try {
                    if(!after.openProgram(p))
                        throw new IllegalStateException("Updated native C unavailable");
                    for(Function affectedFunction:affected) {
                        monitor.checkCancelled();
                        String updated=c(after,affectedFunction,monitor);
                        String previous=originalC.get(affectedFunction);
                        if(countWarnings(updated)>countWarnings(previous)||
                           countLoops(updated)<countLoops(previous))
                            throw new IllegalStateException(
                                "Native CALL consumer C regression "+
                                affectedFunction.getEntryPoint());
                    }
                }finally{after.dispose();}
                accepted=true;
            }catch(CancelledException c){throw c;}
            catch(Exception issue){rejectedReason=issue.toString();}
            finally{p.endTransaction(tx,accepted);}
            if(accepted)repaired+=row.getValue().size();
            else {
                // A source CALL may retain its three machine bytes while
                // a failed flow-override change still alters the CFG.
                // Reject a leaked override/owner mutation immediately.
                if(fm.getFunctionCount()!=originalCount)
                    throw new IllegalStateException(
                        "UNSUPPORTED returning CALL rollback leaked owner metadata");
                for(Function affectedFunction:affected) {
                    if(!originalIdentities.get(affectedFunction).equals(
                           affectedFunction.getName()+"|"+affectedFunction.getBody()+
                           "|"+affectedFunction.getComment())||
                       !originalNoReturn.get(affectedFunction).equals(
                           affectedFunction.hasNoReturn()))
                        throw new IllegalStateException(
                            "UNSUPPORTED returning CALL rollback leaked provider metadata "+
                            affectedFunction.getEntryPoint());
                }
                for(var nativeBefore:originalBytes.entrySet()) {
                    Instruction restored=listing.getInstructionAt(nativeBefore.getKey());
                    if(restored==null||
                       restored.getFlowOverride()!=FlowOverride.CALL_RETURN||
                       !Arrays.equals(nativeBefore.getValue(),restored.getBytes()))
                        throw new IllegalStateException(
                            "UNSUPPORTED returning CALL rollback leaked CFG at "+
                            nativeBefore.getKey());
                }
                unsupported+=row.getValue().size();
                log.appendMsg("Sunplus source returning CALL metadata",
                    "UNSUPPORTED owner "+owner.getEntryPoint()+
                    " reason="+rejectedReason);
            }
        }
        if(repaired!=0||unresolved!=0||unsupported!=0)
            log.appendMsg("Sunplus source returning CALL metadata",
                "CONFIRMED_STATIC repaired_CALL_RETURN="+repaired+
                " UNKNOWN_non_eligible="+unresolved+
                " UNSUPPORTED_C_gate="+unsupported+
                " native_source_bytes_preserved=true");
        return true;
    }

    private static boolean run(Program p,TaskMonitor monitor,MessageLog log)
            throws Exception {
        List<Candidate> candidates=discover(p,monitor);
        if(candidates.isEmpty()){
            int oldCallOverride=0;
            for(Instruction nativeInstruction:p.getListing().getInstructions(true)) {
                monitor.checkCancelled();
                if(pm(nativeInstruction) &&
                   nativeInstruction.getFlowOverride()==FlowOverride.CALL_RETURN &&
                   nativeInstruction.toString().trim().matches("(?i)^CALL\\s+0x[0-9a-f]+$"))
                    oldCallOverride++;
            }
            if(oldCallOverride!=0)
                log.appendMsg("Sunplus native returning CALL+CE",
                    "UNKNOWN unresolved_CALL_RETURN_sites="+oldCallOverride+
                    "; no source-proven adjacent atomic CE candidates");
            return true;
        }
        FunctionManager fm=p.getFunctionManager();
        Listing listing=p.getListing();
        Register ceContext=p.getRegister("codec_ce_loop_end");
        Register directContext=p.getRegister("codec_ce_direct_backedge");
        Register targetContext=p.getRegister("codec_ce_direct_start");
        if(ceContext==null||directContext==null||targetContext==null)
            throw new IllegalStateException("Native SLEIGH CE contexts absent");
        // Model changes affect each original CALL owner, its callee's ABI,
        // and every other direct caller of a provider whose no-return flag
        // may be disproved. Gate exactly that bounded transitive one-hop
        // C/CFG surface here; the full four-profile C gate is separate.
        Set<Function> allowedNoReturnChanges=new LinkedHashSet<>();
        Set<Function> affected=new LinkedHashSet<>();
        for(Candidate next:candidates) {
            allowedNoReturnChanges.add(next.provider);
            affected.add(next.loop.owner);
            affected.add(next.provider);
        }
        for(Instruction i:listing.getInstructions(true)) {
            monitor.checkCancelled();
            if(!pm(i)||opcode(i,PcodeOp.CALL)<1||
               i.getFlows().length!=1)continue;
            Function provider=fm.getFunctionAt(i.getFlows()[0]);
            if(provider==null||!allowedNoReturnChanges.contains(provider))
                continue;
            Function caller=fm.getFunctionContaining(i.getAddress());
            if(caller!=null&&!caller.isExternal())affected.add(caller);
        }
        if(affected.size()>96)
            throw new IllegalStateException(
                "UNSUPPORTED native CALL/CE direct consumer bound "+
                affected.size());
        Map<Function,String> baseline=new LinkedHashMap<>();
        Map<Function,String> identity=new LinkedHashMap<>();
        Map<Function,Boolean> oldNoReturn=new LinkedHashMap<>();
        DecompInterface dc=new DecompInterface();
        try{
            if(!dc.openProgram(p))throw new IllegalStateException("Native C generator absent");
            for(Function f:affected){
                monitor.checkCancelled();
                baseline.put(f,c(dc,f,monitor));
                identity.put(f,f.getName()+"|"+f.getBody()+"|"+f.getComment());
                oldNoReturn.put(f,f.hasNoReturn());
            }
        }finally{dc.dispose();}
        int count=fm.getFunctionCount();
        int tx=p.startTransaction("Atomic source-native returning CALL and CE recovery");
        boolean commit=false;
        try{
            for(Candidate candidate:candidates){
                monitor.checkCancelled();
                Instruction call=candidate.call;
                Instruction ce=candidate.ce;
                if(candidate.provider.hasNoReturn())
                    candidate.provider.setNoReturn(false);
                call.setFlowOverride(FlowOverride.NONE);
                Instruction updatedCall=listing.getInstructionAt(call.getAddress());
                if(updatedCall==null||
                   updatedCall.getFlowOverride()!=FlowOverride.NONE||
                   !updatedCall.getAddress().add(3).equals(updatedCall.getFallThrough())||
                   !Arrays.equals(updatedCall.getBytes(),candidate.callBytes))
                    throw new IllegalStateException("Returning native CALL continuation not restored "+call.getAddress());
                Address site=ce.getAddress();
                listing.clearCodeUnits(site,site.add(2),false);
                p.getProgramContext().setValue(ceContext,site,site,BigInteger.ONE);
                p.getProgramContext().setValue(directContext,site,site,BigInteger.ONE);
                p.getProgramContext().setValue(targetContext,site,site,
                    BigInteger.valueOf(candidate.loop.first+1));
                DisassembleCommand instruction=new DisassembleCommand(
                    new AddressSet(site,site.add(2)),null,true);
                instruction.enableCodeAnalysis(false);
                if(!instruction.applyTo(p,monitor))
                    throw new IllegalStateException("Native CE recode failed at "+site);
                Instruction recoded=listing.getInstructionAt(site);
                boolean branch=false;
                if(recoded!=null)for(PcodeOp op:recoded.getPcode())
                    if(op.getOpcode()==PcodeOp.BRANCH&&
                       op.getInput(0).getAddress().equals(word(p,candidate.loop.first+1)))
                        branch=true;
                if(recoded==null||!Arrays.equals(recoded.getBytes(),candidate.ceBytes)||
                   !branch||opcode(recoded,PcodeOp.CBRANCH)<1||
                   opcode(recoded,PcodeOp.BRANCHIND)!=0)
                    throw new IllegalStateException("Native source CE backedge not restored "+site);
            }
            if(fm.getFunctionCount()!=count)
                throw new IllegalStateException("Native function inventory changed");
            for(var before:identity.entrySet()){
                Function f=before.getKey();
                if(!before.getValue().equals(f.getName()+"|"+f.getBody()+"|"+f.getComment())||
                   (!allowedNoReturnChanges.contains(f)&&
                    !oldNoReturn.get(f).equals(f.hasNoReturn())))
                    throw new IllegalStateException("Native metadata regression "+f.getEntryPoint());
            }
            DecompInterface verify=new DecompInterface();
            try{
                if(!verify.openProgram(p))
                    throw new IllegalStateException("Updated native C generator absent");
                for(var before:baseline.entrySet()){
                    monitor.checkCancelled();
                    String after=c(verify,before.getKey(),monitor);
                    if(countWarnings(after)>countWarnings(before.getValue())||
                       countLoops(after)<countLoops(before.getValue()))
                        throw new IllegalStateException(
                            "Native returning CALL/CE C regression "+before.getKey().getEntryPoint());
                }
            }finally{verify.dispose();}
            commit=true;
        }finally{p.endTransaction(tx,commit);}
        log.appendMsg("Sunplus native returning CALL+CE",
            "CONFIRMED_STATIC atomic_call_ce="+candidates.size()+
            " directly_affected_C_owners="+affected.size()+
            " source_bytes_preserved=true C_nonregression=true"+
            " runtime_stack=UNKNOWN");
        return true;
    }
}
