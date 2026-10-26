package com.xebyte.sunplus;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Native Sunplus PM24 DO/CE architecture recovery during Ghidra auto-analysis.
 *
 * <p>One architectural rule works across codec profiles.  The pass executes
 * after disassembly and function discovery, and only completes already-decoded,
 * non-overlapping native loop endpoints when source counter provenance and
 * all interprocedural loop-state effects are statically bounded. Ambiguities
 * remain unresolved: the analyzer neither invents functions nor assumes
 * shared-stack silicon semantics for nested / recursive / indirect calls.
 *
 * <p>Per-function C gates reduce work compared with firmware-specific
 * postprocessing. Ghidra may hold an outer transaction, so nested transaction
 * rollback must be verified before this analyzer is enabled by default.
 * Until then it is discoverable but opt-in, and its dryRun path is immutable.
 * Full-corpus C and normalized Pcode remain independent release gates.
 * No hard-coded PM addresses, file hashes, or codec names.
 */
public final class SunplusNativeCeAutoAnalyzer extends AbstractAnalyzer {
    public static final String LANGUAGE = "SunplusSPHEAudioDSP:BE:16:default";
    private static final Pattern DO = Pattern.compile(
        "^DO\\s+(?:0x)?([0-9a-f]+)\\s+UNTIL\\s+CE$", Pattern.CASE_INSENSITIVE);
    private static final int MAX_LOOP_WORDS = 1024;
    private static final int MAX_BACKWARD_WRITER = 16;
    private static final int MAX_CALLEE_WORDS = 512;
    private static final int MAX_CHANGED_FUNCTIONS = 120;

    private record Loop(int first, int last, Instruction begin, Function owner) {}
    private record Candidate(Loop loop, byte[] endBytes, boolean missingCe,
                             Address nativeCallTarget) {}

    public SunplusNativeCeAutoAnalyzer() {
        super("Sunplus DSP Native DO/CE Flow",
            "Infer only source-verified counted loop endpoints during normal program analysis",
            AnalyzerType.FUNCTION_ANALYZER);
        setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after().after());
        // Discovery is automatic; mutation remains disabled until the fresh
        // import/readback release gate proves transaction rollback semantics.
        setDefaultEnablement(false);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program != null && LANGUAGE.equals(program.getLanguageID().getIdAsString());
    }

    private static Address pm(Program p, int word) {
        return p.getAddressFactory().getAddress(String.format("PM:%04x", word));
    }

    private static int word(Address addr) {
        return (int) addr.getAddressableWordOffset();
    }

    private static int code(Instruction ins, int opcode) {
        int n = 0;
        for (PcodeOp op : ins.getPcode()) if (op.getOpcode() == opcode) n++;
        return n;
    }

    private static boolean intersects(Loop a, Loop b) {
        return a.first <= b.last && b.first <= a.last;
    }

    // Decoder's native 24-bit CALL / conditional-RTS instruction always
    // advances to the next PM word on a returning or skipped path. Ghidra's
    // cached no-return inference may suppress its fallthrough despite the
    // already proven callee/PC-stack return contract. Recover only this
    // source-encoded continuation; never guess a branch/call target.
    private static Address nativeReturnContinuation(Instruction ins, Function owner) {
        if(ins==null||owner==null)return null;
        Address ft=ins.getFallThrough();
        if(ft!=null)return owner.getBody().contains(ft)?ft:null;
        if(ins.getLength()!=3||
           !"PM".equals(ins.getAddress().getAddressSpace().getName())||
           !"NONE".equals(ins.getFlowOverride().name()))return null;
        String op=ins.toString().trim().toUpperCase(java.util.Locale.ROOT);
        boolean isCall=ins.getFlowType().isCall() &&
            (op.startsWith("CALL ") || (op.startsWith("IF ")&&op.contains(" CALL ")));
        boolean isSkippedRts=op.startsWith("IF ")&&op.endsWith(" RTS");
        if(!isCall&&!isSkippedRts)return null;
        Address next=pm(owner.getProgram(),word(ins.getAddress())+1);
        return owner.getBody().contains(next)?next:null;
    }

    private static boolean nativeCounterWrite(Instruction ins) {
        String s = ins.toString().trim();
        return s.startsWith("LDI CNTR,") || s.startsWith("DMREAD CNTR,") ||
            s.startsWith("CNTR =") || s.startsWith("POP CNTR");
    }

    // Candidate plans are source-derived, not production annotations. Two-level
    // static CE requires explicit counter provenance and absence of CALL or
    // unpredictable control transfer throughout the entire outer interval.
    // Any hardware shared-PC-stack behavior remains UNKNOWN until separately
    // verified; this planner never mutates a saved program.
    private record NestedGroup(Loop outer, Instruction outerWriter, List<Loop> inner, List<Instruction> writers) {}
    private static boolean staticCounterWriter(Instruction i) {
        if (i == null) return false;
        String text = i.toString().trim();
        return text.startsWith("LDI CNTR,") || text.startsWith("DMREAD CNTR,") ||
            text.startsWith("CNTR =");
    }

    /**
     * Original DO words encode their CE endpoint irrespective of whether the
     * cached instruction context currently emits a counted-loop backedge.
     * A missing CE is recoverable only when the endpoint has no independent
     * machine control transfer or control-stack operation. The caller still
     * must prove its complete nested counter-frame/data-flow contract.
     */
    private static boolean nativeCeRecoverable(Loop loop, Listing listing, Program p) {
        Instruction end=listing.getInstructionAt(pm(p,loop.last));
        if(end==null||end.getLength()!=3||
           loop.owner==null||!loop.owner.getBody().contains(end.getAddress())||
           nativeCounterWrite(end)||mutatesControlStack(end)||
           code(end,PcodeOp.CALL)!=0||code(end,PcodeOp.RETURN)!=0||
           end.getFlowType().isCall()||end.getFlowType().isTerminal())
            return false;
        boolean alreadyIndirect=code(end,PcodeOp.CBRANCH)>=1 &&
            code(end,PcodeOp.BRANCHIND)==1 &&
            code(end,PcodeOp.BRANCH)==0;
        boolean missingContext=code(end,PcodeOp.BRANCHIND)==0 &&
            code(end,PcodeOp.BRANCH)==0 &&
            code(end,PcodeOp.CALL)==0 &&
            code(end,PcodeOp.RETURN)==0 &&
            !end.getFlowType().isCall() &&
            !end.getFlowType().isJump() &&
            !end.getFlowType().isTerminal() &&
            !end.getFlowType().isComputed() &&
            !end.toString().trim().startsWith("DO ");
        if(!alreadyIndirect&&!missingContext)return false;
        try {
            byte[] raw=loop.begin.getBytes();
            if(raw.length!=3)return false;
            int bits=(raw[0]&255)<<16|(raw[1]&255)<<8|(raw[2]&255);
            return bits>>>18==5&&(bits&15)==14&&
                ((bits>>>4)&0x3fff)==loop.last;
        }catch(ghidra.program.model.mem.MemoryAccessException unreadable){
            return false;
        }
    }

    private static List<NestedGroup> planarTwoLevelNested(
            List<Loop> loops, Program program, TaskMonitor monitor)
            throws CancelledException {
        Listing listing = program.getListing();
        List<NestedGroup> plans = new ArrayList<>();
        for (Loop outer : loops) {
            monitor.checkCancelled();
            if (outer.owner == null || outer.first >= outer.last ||
                outer.last - outer.first > MAX_LOOP_WORDS ||
                !nativeCeRecoverable(outer, listing, program)) continue;
            List<Loop> children = new ArrayList<>();
            boolean impossible = false;
            for (Loop other : loops) {
                if (outer == other || !intersects(outer, other)) continue;
                if (outer.first < other.first && other.last < outer.last &&
                    other.owner == outer.owner) children.add(other);
                else { impossible = true; break; }
            }
            if (impossible || children.isEmpty() || children.size() > 4) continue;
            children.sort((a,b) -> Integer.compare(a.first,b.first));
            for (int j=0; j<children.size();j++) {
                Loop child = children.get(j);
                if (child.first >= child.last ||
                    (j>0 && children.get(j-1).last >= child.first) ||
                    !nativeCeRecoverable(child,listing,program)) { impossible=true; break; }
            }
            if (impossible) continue;
            Instruction outerWriter = null;
            for (int k=1; k<=MAX_BACKWARD_WRITER; k++) {
                if (outer.first-k<0) break;
                Instruction candidate = listing.getInstructionAt(pm(program,outer.first-k));
                if (candidate == null || candidate.getLength()!=3 ||
                    candidate.getFlowType().isCall() || candidate.getFlowType().isJump() ||
                    mutatesControlStack(candidate) ||
                    candidate.toString().trim().startsWith("DO ") ||
                    !outer.owner.getBody().contains(candidate.getAddress())) break;
                if (staticCounterWriter(candidate)) { outerWriter=candidate; break; }
                if (candidate.getFlowType().isTerminal()) break;
            }
            // Source DO encodes the loop endpoint regardless of whether its
            // incoming CNTR was loaded locally or by a predecessor/caller.
            // Do not fabricate a writer when the counter is live-in.
            List<Instruction> writers = new ArrayList<>();
            for (int j=0;j<children.size();j++) {
                Loop child=children.get(j);
                int startAfter=j==0?outer.first+1:children.get(j-1).last+1;
                Instruction innerWriter=null;
                for (int w=child.first-1;w>=startAfter && w>=child.first-4;w--) {
                    Instruction candidate=listing.getInstructionAt(pm(program,w));
                    if (candidate==null || candidate.getLength()!=3 ||
                        candidate.getFlowType().isCall() || candidate.getFlowType().isJump() ||
                        mutatesControlStack(candidate) ||
                        !outer.owner.getBody().contains(candidate.getAddress())) break;
                    if (staticCounterWriter(candidate)) {innerWriter=candidate;break;}
                }
                if (innerWriter==null) {
                    // A conditional fork may select one of several sibling
                    // DO frames using the *same* earlier CNTR write. The
                    // nearby-writer heuristic misses that legal source form.
                    // Reuse only the UNIQUE native writer in the outer span;
                    // the full branch-sensitive frame machine below proves
                    // that every path reaching this DO has a pending save.
                    Instruction unique=null;
                    int found=0;
                    for(int w=outer.first+1;w<child.first;w++) {
                        Instruction candidate=listing.getInstructionAt(pm(program,w));
                        if(candidate!=null && candidate.getLength()==3 &&
                           outer.owner.getBody().contains(candidate.getAddress()) &&
                           staticCounterWriter(candidate)) {
                            unique=candidate;
                            found++;
                        }
                    }
                    if(found==1)innerWriter=unique;
                }
                if (innerWriter==null) {impossible=true;break;}
                writers.add(innerWriter);
            }
            if (impossible) continue;
            if(!sourceNestedFramesBalanced(outer,children,program,monitor))
                continue;
            if (!impossible) plans.add(new NestedGroup(outer,outerWriter,children,writers));
        }
        return plans;
    }

    // Three hardware DO levels: an outer loop owns one middle loop which owns
    // one or more nonoverlapping inner loops. Each CNTR writer has an exact
    // source predecessor and its own preserved frame. No address exceptions.
    private record ThreeLevelGroup(Loop outer, Instruction outerWriter,
                                   Loop middle, Instruction middleWriter,
                                   List<Loop> inner, List<Instruction> writers) {}

    private static Instruction boundedCounterWriter(Listing listing, Program p,
            Function owner, int start, int earliest, int maxBackward) {
        for(int n=1;n<=maxBackward && start-n>=earliest;n++) {
            Instruction i=listing.getInstructionAt(pm(p,start-n));
            if(i==null||i.getLength()!=3||
               !owner.getBody().contains(i.getAddress())||
               i.getFlowType().isCall()||i.getFlowType().isJump()||
               i.getFlowType().isTerminal()||mutatesControlStack(i)||
               i.toString().trim().startsWith("DO "))return null;
            if(staticCounterWriter(i))return i;
        }
        return null;
    }

    private static List<ThreeLevelGroup> planarThreeLevelNested(
            List<Loop> loops, Program program, TaskMonitor monitor)
            throws CancelledException {
        Listing listing=program.getListing();
        FunctionManager fm=program.getFunctionManager();
        List<ThreeLevelGroup> groups=new ArrayList<>();
        for(Loop outer:loops) {
            monitor.checkCancelled();
            if(outer.owner==null||outer.first>=outer.last||
               outer.last-outer.first>MAX_LOOP_WORDS||
               !nativeCeRecoverable(outer,listing,program))continue;
            List<Loop> inside=new ArrayList<>();
            boolean ambiguous=false;
            for(Loop another:loops) {
                if(another==outer||!intersects(another,outer))continue;
                if(outer.first<another.first&&another.last<outer.last&&
                   another.owner==outer.owner)inside.add(another);
                else {ambiguous=true;break;}
            }
            if(ambiguous||inside.size()<3||inside.size()>5)continue;
            // The source counter stack must have exactly one depth-2 parent.
            // A depth-3 sibling is nested within it, not directly under outer.
            Loop middle=null;
            for(Loop mid:inside) {
                int contained=0;
                for(Loop item:inside)
                    if(mid!=item&&mid.first<item.first&&item.last<mid.last)
                        contained++;
                if(contained==inside.size()-1){
                    if(middle!=null){ambiguous=true;break;}
                    middle=mid;
                }
            }
            if(ambiguous||middle==null||!nativeCeRecoverable(middle,listing,program))continue;
            List<Loop> inner=new ArrayList<>();
            for(Loop item:inside) {
                if(item==middle)continue;
                if(item.first<=middle.first||item.last>=middle.last||
                   !nativeCeRecoverable(item,listing,program)) {ambiguous=true;break;}
                inner.add(item);
            }
            if(ambiguous||inner.isEmpty()||inner.size()>4)continue;
            inner.sort((a,b)->Integer.compare(a.first,b.first));
            for(int k=1;k<inner.size();k++)
                if(inner.get(k-1).last>=inner.get(k).first){ambiguous=true;break;}
            if(ambiguous)continue;
            Instruction outerWriter=boundedCounterWriter(listing,program,outer.owner,
                outer.first,0,MAX_BACKWARD_WRITER);
            Instruction midWriter=boundedCounterWriter(listing,program,outer.owner,
                middle.first,outer.first+1,4);
            // Only the middle/third transition must have an explicit source
            // counter save. The outer DO may inherit the ABI-live CNTR value.
            if(midWriter==null)continue;
            List<Instruction> writers=new ArrayList<>();
            for(int k=0;k<inner.size();k++) {
                Loop child=inner.get(k);
                int earliest=k==0?middle.first+1:inner.get(k-1).last+1;
                Instruction writer=boundedCounterWriter(listing,program,outer.owner,
                    child.first,earliest,4);
                if(writer==null){ambiguous=true;break;}
                writers.add(writer);
            }
            if(ambiguous)continue;
            if(!sourceNestedFramesBalanced(outer,inside,program,monitor))
                continue;
            if(!ambiguous)
                groups.add(new ThreeLevelGroup(outer,outerWriter,middle,
                                                midWriter,inner,writers));
        }
        return groups;
    }

    // Generic zero-overhead nested frame analysis. The machine word encodes
    // each DO's end exactly; the abstract stack contains only *open* DO frames.
    // Counter writers create a pending count-stack save that must be consumed
    // by an inner DO or a proven count-consuming callee on every CFG branch.
    // This recovers nested conditional control without manually naming sites.
    private record NestedFlowState(int word,long frames,int depth,
                                   boolean pendingCount) {}

    private static boolean sourceNestedFramesBalanced(Loop outer,
            List<Loop> descendants, Program p, TaskMonitor monitor)
            throws CancelledException {
        Listing listing=p.getListing();
        FunctionManager fm=p.getFunctionManager();
        Map<Integer,Loop> starts=new LinkedHashMap<>();
        Map<Integer,Loop> ends=new LinkedHashMap<>();
        starts.put(outer.first,outer);ends.put(outer.last,outer);
        for(Loop child:descendants) {
            if(starts.putIfAbsent(child.first,child)!=null||
               ends.putIfAbsent(child.last,child)!=null)return false;
        }
        java.util.ArrayDeque<NestedFlowState> todo=new java.util.ArrayDeque<>();
        Set<NestedFlowState> visited=new LinkedHashSet<>();
        Map<String,Boolean> callReturnMemo=new LinkedHashMap<>();
        Map<Address,Boolean> countConsumerMemo=new LinkedHashMap<>();
        todo.add(new NestedFlowState(outer.first+1,outer.first,1,false));
        Set<Integer> reachedCeEnds=new LinkedHashSet<>();
        boolean rootCeReached=false;
        while(!todo.isEmpty()) {
            monitor.checkCancelled();
            NestedFlowState state=todo.removeFirst();
            if(!visited.add(state))continue;
            if(visited.size()>16*(MAX_LOOP_WORDS+1))return false;
            int w=state.word();
            if(w<outer.first+1||w>outer.last)return false;
            Instruction ins=listing.getInstructionAt(pm(p,w));
            if(ins==null||ins.getLength()!=3||
               !outer.owner.getBody().contains(ins.getAddress())||
               mutatesControlStack(ins))return false;
            int topWord=(int)((state.frames()>>((state.depth()-1)*14))&0x3fff);
            Loop active=starts.get(topWord);
            if(active==null)return false;
            // A jump into the CE of an unopened (or already closed) nested DO
            // would consume the wrong frame and is architecturally invalid.
            if(ends.containsKey(w)&&w!=active.last)return false;
            if(w==active.last) {
                if(state.pendingCount()||
                   !nativeCeRecoverable(active,listing,p))return false;
                reachedCeEnds.add(active.last);
                if(state.depth()==1) {
                    rootCeReached=true;
                } else {
                    int bits=(state.depth()-1)*14;
                    long rest=state.frames() & ((1L<<bits)-1);
                    todo.add(new NestedFlowState(w+1,rest,
                                                   state.depth()-1,false));
                }
                // CE=not-zero repeats the current DO body with the same
                // hardware PC frame and countdown state.
                todo.add(new NestedFlowState(active.first+1,state.frames(),
                                               state.depth(),false));
                continue;
            }
            boolean pending=state.pendingCount();
            Matcher doWord=DO.matcher(ins.toString().trim());
            if(doWord.matches()) {
                Loop child=starts.get(w);
                if(child==null||child==outer||state.depth()>=3||
                   !pending||child.first<=active.first||
                   child.last>=active.last||
                   Integer.parseInt(doWord.group(1),16)!=child.last)return false;
                long frames=state.frames() | ((long)w << (14*state.depth()));
                todo.add(new NestedFlowState(w+1,frames,state.depth()+1,false));
                continue;
            }
            if(ins.getFlowType().isComputed()&&
               !ins.getFlowType().isTerminal())return false;
            if(nativeCounterWrite(ins)) {
                if(pending||ins.getFlowType().isCall()||
                   ins.getFlowType().isJump()||
                   ins.getFlowType().isTerminal())return false;
                pending=true;
            }
            if(nativeJumpToResetExit(ins,p,monitor))continue;
            if(ins.getFlowType().isCall()) {
                if(ins.getFlows().length!=1||
                   !"NONE".equals(ins.getFlowOverride().name())||
                   nativeReturnContinuation(ins,outer.owner)==null)return false;
                Function callee=fm.getFunctionAt(ins.getFlows()[0]);
                if(pending) {
                    if(ins.getFlowType().isConditional()||callee==null)return false;
                    Boolean known=countConsumerMemo.get(callee.getEntryPoint());
                    boolean valid=known!=null?known:
                        balancedCountConsumer(callee,listing,p,monitor);
                    countConsumerMemo.put(callee.getEntryPoint(),valid);
                    if(!valid)return false;
                    pending=false;
                } else if(!returnsViaSharedPcStack(callee,listing,fm,
                          callReturnMemo,new LinkedHashSet<>(),0,monitor)) {
                    // Shared-count caller state can be borrowed by a native
                    // counted callee after the previous count was consumed.
                    // Require its one source-proven DO, CE and immediate RTS;
                    // ordinary unknown CALLs still fail closed. This is CFG
                    // evidence, not hardware PC-stack equivalence evidence.
                    if(callee==null)return false;
                    Boolean known=countConsumerMemo.get(callee.getEntryPoint());
                    boolean valid=known!=null?known:
                        balancedCountConsumer(callee,listing,p,monitor);
                    countConsumerMemo.put(callee.getEntryPoint(),valid);
                    if(!valid)return false;
                }
                todo.add(new NestedFlowState(word(nativeReturnContinuation(ins,outer.owner)),
                                               state.frames(),state.depth(),pending));
                continue;
            }
            if(ins.getFlowType().isTerminal()) {
                Address[] exits=ins.getFlows();
                if(exits.length==1&&sourceResetStackExit(exits[0],p,monitor))continue;
                return false;
            }
            Address ft=ins.getFallThrough();
            if(ft!=null){
                if(!"PM".equals(ft.getAddressSpace().getName()))return false;
                todo.add(new NestedFlowState(word(ft),state.frames(),
                                               state.depth(),pending));
            }
            Address[] flows=ins.getFlows();
            if(ins.getFlowType().isJump()&&flows.length==0)return false;
            if(ft==null&&flows.length==0)return false;
            for(Address dst:flows){
                if(!"PM".equals(dst.getAddressSpace().getName()))return false;
                int to=word(dst);
                if(to<outer.first+1||to>outer.last) {
                    if(sourceResetStackExit(dst,p,monitor)||
                       sourceClosedWaitLoopExit(dst,outer,listing,monitor))continue;
                    return false;
                }
                todo.add(new NestedFlowState(to,state.frames(),
                                               state.depth(),pending));
            }
        }
        return rootCeReached&&reachedCeEnds.containsAll(ends.keySet());
    }

    // Explicit ISA stack operations can mutate hardware PC/DO/CNTR frames
    // without appearing as a CALL or jump in Analyzer's flow graph. A callee
    // performing any of these operations cannot prove caller loop state
    // preservation. Use one architectural predicate for both normal and
    // nested direct-CE recovery, rather than a list of codec addresses.
    private static boolean mutatesControlStack(Instruction i) {
        if (i == null) return true;
        String op = i.toString().trim().toUpperCase(java.util.Locale.ROOT);
        return op.contains("TOPPCSTACK") || op.contains("POP PC") ||
               op.contains("PUSH PC") || op.contains("POP CNTR") ||
               op.contains("PUSH CNTR") || op.contains("POP LOOP") ||
               op.contains("PUSH LOOP") || op.contains("OWRCNTR") ||
               op.contains("POP STS") || op.contains("PUSH STS") ||
               op.equals("RTI") || op.endsWith(" RTI");
    }

    // Native CALL/RTS contract over the instructions reachable from the *real*
    // entry. Source functions may share code by jumping to a return-bearing
    // suffix of another function. Inspecting their full listing bodies would
    // incorrectly reject unrelated, unreachable instructions before that entry.
    // Preserve every PC/DO/CNTR frame; never invent CALL edges for tail JUMPs.
    private static boolean returnsViaSharedPcStack(Function f, Listing listing,
            FunctionManager fm, Map<String,Boolean> memo,
            Set<Address> active, int depth, TaskMonitor monitor)
            throws CancelledException {
        return f!=null&&returnsViaSharedPcStackAt(f,f.getEntryPoint(),
            listing,fm,memo,active,depth,monitor);
    }

    private static boolean returnsViaSharedPcStackAt(Function f, Address entry,
            Listing listing, FunctionManager fm, Map<String,Boolean> memo,
            Set<Address> active, int depth, TaskMonitor monitor)
            throws CancelledException {
        if(f==null||entry==null||f.isExternal()||depth>=12||
           !"PM".equals(entry.getAddressSpace().getName())||
           !f.getBody().contains(entry))return false;
        String key=depth+":"+entry;
        Boolean cached=memo.get(key);
        if(cached!=null)return cached;
        if(!active.add(entry))return false;
        try {
            // First recover a self-contained counted callee. This is a
            // separate hardware behavior contract from a flat RTS leaf.
            if(returnsWithLocalDoFrames(f,entry,listing,fm,memo,
                    active,depth,monitor)) {
                memo.put(key,true);
                return true;
            }
            java.util.ArrayDeque<Address> frontier=new java.util.ArrayDeque<>();
            Set<Address> visited=new LinkedHashSet<>();
            frontier.add(entry);
            boolean returnReachable=false;
            while(!frontier.isEmpty()) {
                monitor.checkCancelled();
                Address here=frontier.removeFirst();
                if(!f.getBody().contains(here))return false;
                if(!visited.add(here))continue;
                if(visited.size()>MAX_CALLEE_WORDS)return false;
                Instruction ins=listing.getInstructionAt(here);
                if(ins==null||ins.getLength()!=3||nativeCounterWrite(ins)||
                   mutatesControlStack(ins)||
                   ins.toString().trim().startsWith("DO ")||
                   (ins.getFlowType().isComputed()&&!ins.getFlowType().isTerminal()))
                    return false;
                String op=ins.toString().trim().toUpperCase(java.util.Locale.ROOT);
                boolean unconditionalRts=op.equals("RTS");
                boolean conditionalRts=op.startsWith("IF ")&&op.endsWith(" RTS");
                if(unconditionalRts||conditionalRts) {
                    // A conditional RTS returns on its taken path; its
                    // untaken path must also remain inside the verified body.
                    returnReachable=true;
                    if(!conditionalRts)continue;
                    Address ft=nativeReturnContinuation(ins,f);
                    if(ft==null)return false;
                    frontier.add(ft);
                    continue;
                }
                if(ins.getFlowType().isTerminal())return false;
                Address ft=nativeReturnContinuation(ins,f);
                Address[] branches=ins.getFlows();
                if(ins.getFlowType().isCall()) {
                    if(branches.length!=1||ft==null||
                       !"NONE".equals(ins.getFlowOverride().name())||
                       !f.getBody().contains(ft)||
                       !returnsViaSharedPcStack(fm.getFunctionAt(branches[0]),
                           listing,fm,memo,active,depth+1,monitor))return false;
                    // A CALL's target does not join the caller's local CFG.
                    frontier.add(ft);
                    continue;
                }
                if(ins.getFlowType().isJump()&&branches.length==0)return false;
                if(ft==null&&branches.length==0)return false;
                if(ft!=null) {
                    if(!f.getBody().contains(ft))return false;
                    frontier.add(ft);
                }
                for(Address dst:branches) {
                    if(f.getBody().contains(dst)) {
                        frontier.add(dst);
                        continue;
                    }
                    // A direct unconditional JUMP uses the current return
                    // PC frame: it must enter a proven reachable RTS suffix.
                    if(!ins.getFlowType().isJump()||
                       ins.getFlowType().isConditional()||ft!=null||
                       branches.length!=1||
                       !op.startsWith("JUMP ")||
                       !"PM".equals(dst.getAddressSpace().getName()))
                        return false;
                    Function target=fm.getFunctionContaining(dst);
                    if(target==null||target==f||
                       !returnsViaSharedPcStackAt(target,dst,listing,fm,
                           memo,active,depth,monitor))return false;
                    returnReachable=true;
                }
            }
            memo.put(key,returnReachable);
            return returnReachable;
        } finally {active.remove(entry);}
    }

    // A callee can have a complete *local* zero-overhead DO/CNTR frame.
    // Unlike a caller-provided counted consumer, it writes its own CNTR
    // before DO, pushes its caller's counter, and pops that exact frame on
    // completion. The control graph below proves frame balance at *every*
    // reachable RTS, including conditional short-circuit returns.
    private record CalleeCountState(Address pc, int activeStart,
                                    int activeEnd, boolean newCountPending) {}

    private static boolean returnsWithLocalDoFrames(Function f,Address entry,
            Listing listing,FunctionManager fm,Map<String,Boolean> memo,
            Set<Address> active,int depth,TaskMonitor monitor)
            throws CancelledException {
        if(f==null||entry==null||!f.getBody().contains(entry))return false;
        java.util.ArrayDeque<CalleeCountState> frontier=new java.util.ArrayDeque<>();
        Set<CalleeCountState> seen=new LinkedHashSet<>();
        frontier.add(new CalleeCountState(entry,-1,-1,false));
        boolean seenDo=false,seenRts=false;
        while(!frontier.isEmpty()) {
            monitor.checkCancelled();
            CalleeCountState state=frontier.removeFirst();
            if(!seen.add(state))continue;
            if(seen.size()>4*MAX_CALLEE_WORDS)return false;
            Address addr=state.pc();
            if(!f.getBody().contains(addr))return false;
            Instruction ins=listing.getInstructionAt(addr);
            if(ins==null||ins.getLength()!=3||mutatesControlStack(ins))return false;
            String op=ins.toString().trim().toUpperCase(java.util.Locale.ROOT);
            boolean rts=op.equals("RTS");
            boolean conditionalRts=op.startsWith("IF ")&&op.endsWith(" RTS");
            if(rts||conditionalRts) {
                if(state.activeEnd()!=-1||state.newCountPending())return false;
                seenRts=true;
                if(!conditionalRts)continue;
                Address skipped=nativeReturnContinuation(ins,f);
                if(skipped==null)return false;
                frontier.add(new CalleeCountState(skipped,-1,-1,false));
                continue;
            }
            if(ins.getFlowType().isTerminal())return false;
            if(state.activeEnd()!=-1&&word(addr)==state.activeEnd()) {
                if(code(ins,PcodeOp.CBRANCH)<1)return false;
                int indirect=code(ins,PcodeOp.BRANCHIND);
                if(indirect!=1) {
                    boolean direct=false;
                    for(PcodeOp pcode:ins.getPcode())
                        if(pcode.getOpcode()==PcodeOp.BRANCH&&
                           pcode.getInput(0).getAddress().equals(
                               pm(f.getProgram(),state.activeStart()+1)))
                            direct=true;
                    if(!direct)return false;
                }
                frontier.add(new CalleeCountState(
                    pm(f.getProgram(),state.activeStart()+1),
                    state.activeStart(),state.activeEnd(),false));
                Address next=pm(f.getProgram(),state.activeEnd()+1);
                if(!f.getBody().contains(next))return false;
                frontier.add(new CalleeCountState(next,-1,-1,false));
                continue;
            }
            if(ins.getFlowType().isComputed()&&
               !ins.getFlowType().isTerminal())return false;
            boolean pending=state.newCountPending();
            if(nativeCounterWrite(ins)) {
                if(pending||state.activeEnd()!=-1||
                   ins.getFlowType().isCall()||ins.getFlowType().isJump())
                    return false;
                pending=true;
            }
            Matcher matcher=DO.matcher(ins.toString().trim());
            if(matcher.matches()) {
                if(!pending||state.activeEnd()!=-1)return false;
                int end=Integer.parseInt(matcher.group(1),16);
                if(end<=word(addr)||end-word(addr)>MAX_LOOP_WORDS||
                   !f.getBody().contains(pm(f.getProgram(),end)))return false;
                byte[] raw;
                try {raw=ins.getBytes();}
                catch(ghidra.program.model.mem.MemoryAccessException failure){
                    return false;
                }
                if(raw.length!=3)return false;
                int bits=(raw[0]&255)<<16|(raw[1]&255)<<8|(raw[2]&255);
                if(bits>>>18!=5||(bits&15)!=14||
                   ((bits>>>4)&0x3fff)!=end)return false;
                seenDo=true;
                frontier.add(new CalleeCountState(
                    pm(f.getProgram(),word(addr)+1),word(addr),end,false));
                continue;
            }
            if(ins.getFlowType().isCall()) {
                if(pending||ins.getFlows().length!=1||
                   nativeReturnContinuation(ins,f)==null||
                   !"NONE".equals(ins.getFlowOverride().name())||
                   !returnsViaSharedPcStack(fm.getFunctionAt(ins.getFlows()[0]),
                       listing,fm,memo,active,depth+1,monitor))return false;
                frontier.add(new CalleeCountState(nativeReturnContinuation(ins,f),
                    state.activeStart(),state.activeEnd(),false));
                continue;
            }
            Address ft=ins.getFallThrough();
            Address[] branches=ins.getFlows();
            if(ins.getFlowType().isJump()&&branches.length==0)return false;
            if(ft==null&&branches.length==0)return false;
            if(ft!=null) {
                if(!f.getBody().contains(ft))return false;
                frontier.add(new CalleeCountState(ft,state.activeStart(),
                    state.activeEnd(),pending));
            }
            for(Address dst:branches) {
                // No cross-owner tail transfer while a counted frame or
                // pending CNTR save might still be active.
                if(!f.getBody().contains(dst))return false;
                frontier.add(new CalleeCountState(dst,state.activeStart(),
                    state.activeEnd(),pending));
            }
        }
        return seenDo&&seenRts;
    }

    // A source-proven leaf may consume the caller's freshly loaded CNTR with
    // exactly one DO UNTIL CE, then RTS. Architecturally the count stack saved
    // the outer CNTR on the call-site write; completing CE pops that frame.
    // A strict counted loop/return contract is sufficient for static backedge
    // recovery and requires no firmware-specific function names or addresses.
    private static boolean balancedCountConsumer(Function f, Listing listing,
            Program p, TaskMonitor monitor) throws CancelledException {
        // Ghidra's inferred hasNoReturn flag may itself be stale. For this
        // bounded leaf, the ORIGINAL native DO, CE, immediate RTS and return
        // P-code below are the authoritative evidence, not the cached flag.
        if(f==null||f.isExternal())return false;
        Address entry=f.getEntryPoint();
        if(!"PM".equals(entry.getAddressSpace().getName()))return false;
        Loop counted=null;
        int seen=0;boolean returned=false;
        for(Instruction ins:listing.getInstructions(f.getBody(),true)) {
            monitor.checkCancelled();
            if(++seen>MAX_CALLEE_WORDS||ins.getLength()!=3||
               mutatesControlStack(ins)||nativeCounterWrite(ins)||
               ins.getFlowType().isCall())return false;
            String text=ins.toString().trim();
            Matcher parsed=DO.matcher(text);
            if(parsed.matches()) {
                if(counted!=null)return false;
                counted=new Loop(word(ins.getAddress()),
                    Integer.parseInt(parsed.group(1),16),ins,f);
                // A source DO must be in the function, with a normal body.
                if(counted.first>=counted.last||
                   !f.getBody().contains(pm(p,counted.last)))return false;
            }
            if(text.equals("RTS")) {
                if(returned || counted==null ||
                   !pm(p,counted.last+1).equals(ins.getAddress())||
                   code(ins,PcodeOp.RETURN)!=1)return false;
                returned=true;
                continue;
            }
            if(ins.getFlowType().isTerminal())return false;
            // There can be no control escape before installing the incoming
            // counted DO frame, nor a branch around its CE to RTS. A callee
            // may have internal conditional branches inside that frame.
            if(counted==null &&
               (ins.getFlowType().isJump()||ins.getFlowType().isComputed()))
                return false;
            for(Address dst:ins.getFlows()) {
                if(!f.getBody().contains(dst))return false;
                if(counted!=null &&
                   (dst.compareTo(pm(p,counted.first+1))<0||
                    dst.compareTo(pm(p,counted.last))>0))return false;
            }
            if(ins.getFlowType().isComputed() &&
               (counted==null||!pm(p,counted.last).equals(ins.getAddress())))
                return false;
            if(returned)return false;
        }
        if(!returned||counted==null)return false;
        // The only branch-indirect belongs to the counted CE endpoint;
        // the native DO word determines its backedge without guessing.
        Instruction end=listing.getInstructionAt(pm(p,counted.last));
        if(end==null||code(end,PcodeOp.CBRANCH)<1)return false;
        boolean indirect=code(end,PcodeOp.BRANCHIND)==1&&
                         code(end,PcodeOp.BRANCH)==0;
        boolean direct=false;
        if(code(end,PcodeOp.BRANCHIND)==0) {
            for(PcodeOp op:end.getPcode())
                if(op.getOpcode()==PcodeOp.BRANCH &&
                   op.getInput(0).getAddress().equals(pm(p,counted.first+1)))
                    direct=true;
        }
        if(!indirect&&!direct)return false;
        try {
            byte[] raw=counted.begin.getBytes();
            if(raw.length!=3)return false;
            int bits=(raw[0]&255)<<16|(raw[1]&255)<<8|(raw[2]&255);
            return bits>>>18==5&&(bits&15)==14&&
                   ((bits>>>4)&0x3fff)==counted.last;
        }catch(ghidra.program.model.mem.MemoryAccessException ignored){return false;}
    }

    // A source-proven control-stack reset is a terminal escape from an active
    // DO frame. The CE reached along OTHER branches still has its encoded
    // backedge. No imported no-return metadata or codec address is trusted.
    private static boolean sourceResetStackHandler(Address entry, Program p,
            TaskMonitor monitor) throws CancelledException {
        Function f=p.getFunctionManager().getFunctionAt(entry);
        if(f==null||f.isExternal())return false;
        Listing listing=p.getListing();
        java.util.ArrayDeque<Address> todo=new java.util.ArrayDeque<>();
        Set<Address> seen=new LinkedHashSet<>();
        Map<String,Boolean> returns=new LinkedHashMap<>();
        boolean cleared=false;
        todo.add(entry);
        while(!todo.isEmpty()) {
            monitor.checkCancelled();
            Address at=todo.removeFirst();
            if(!f.getBody().contains(at))return false;
            if(!seen.add(at))continue;
            if(seen.size()>MAX_CALLEE_WORDS)return false;
            Instruction ins=listing.getInstructionAt(at);
            if(ins==null||ins.getLength()!=3)return false;
            String op=ins.toString().trim().toUpperCase(java.util.Locale.ROOT);
            if(op.equals("POP STS, POP CNTR, POP PC, POP LOOP")) {
                cleared=true;
                continue;
            }
            if(mutatesControlStack(ins)||nativeCounterWrite(ins)||op.startsWith("DO ")||
               op.equals("RTS")||op.equals("RTI")||op.endsWith(" RTS")||
               op.endsWith(" RTI")||ins.getFlowType().isComputed())return false;
            if(ins.getFlowType().isCall()) {
                if(ins.getFlows().length!=1||
                   !returnsViaSharedPcStack(p.getFunctionManager().getFunctionAt(
                       ins.getFlows()[0]),listing,p.getFunctionManager(),
                       returns,new LinkedHashSet<>(),0,monitor))return false;
                Address ft=nativeReturnContinuation(ins,f);
                if(ft==null)return false;
                todo.add(ft);
                continue;
            }
            if(ins.getFlowType().isTerminal())return false;
            Address ft=ins.getFallThrough();
            Address[] flows=ins.getFlows();
            if(ft==null&&flows.length==0)return false;
            if(ins.getFlowType().isJump()&&flows.length==0)return false;
            if(ft!=null)todo.add(ft);
            for(Address next:flows)todo.add(next);
        }
        return cleared;
    }

    // A bounded straight-line error tail may jump to a verified reset handler.
    // Unknown returns, calls, indirect jumps and stack mutations are rejected.
    private static boolean sourceResetStackExit(Address target, Program p,
            TaskMonitor monitor) throws CancelledException {
        Set<Address> seen=new LinkedHashSet<>();
        Address at=target;
        for(int k=0;k<8&&at!=null&&seen.add(at);k++) {
            monitor.checkCancelled();
            if(sourceResetStackHandler(at,p,monitor))return true;
            Instruction ins=p.getListing().getInstructionAt(at);
            if(ins==null||ins.getLength()!=3||mutatesControlStack(ins)||
               nativeCounterWrite(ins)||
               (ins.getFlowType().isCall()&&!ins.toString().trim().startsWith("JUMP "))||
               ins.getFlowType().isConditional()||ins.getFlowType().isComputed()||
               ins.toString().trim().startsWith("DO "))return false;
            if(ins.toString().trim().startsWith("JUMP ")) {
                Address[] flows=ins.getFlows();
                if(flows.length!=1||ins.getFallThrough()!=null)return false;
                at=flows[0];
            } else if(!ins.getFlowType().isTerminal()&&
                      ins.getFlows().length==0)at=ins.getFallThrough();
            else return false;
        }
        return false;
    }

    // A native JUMP to a reset can be classified as CALL_TERMINATOR by
    // Ghidra's no-return inference. Honor the encoded JUMP, not that flag.
    private static boolean nativeJumpToResetExit(Instruction ins, Program p,
            TaskMonitor monitor) throws CancelledException {
        if(ins==null||!ins.toString().trim().startsWith("JUMP ")||
           ins.getFlows().length!=1||ins.getFallThrough()!=null)return false;
        // Ghidra may classify the native unconditional JUMP as CALL_TERMINATOR
        // and attach CALL_RETURN to its listing. The *decoded source JUMP*
        // still performs a branch, not a hardware CALL/stack push. Reject
        // other explicit flow overrides; prove the destination separately.
        String override=ins.getFlowOverride().name();
        return ("NONE".equals(override)||"CALL_RETURN".equals(override))&&
            sourceResetStackExit(ins.getFlows()[0],p,monitor);
    }

    // A native conditional branch can abandon an active DO frame into a
    // closed firmware wait/poll loop. Such a path never reaches the caller's
    // CE and therefore cannot invalidate the *other*, source-encoded backedge.
    // This proves only static CFG non-returning reachability, NOT hardware
    // interrupt behavior or safe reuse of the abandoned PC/CNTR stack.
    // No special PM addresses or codec names: every reachable instruction
    // must stay inside a bounded, control-stack-neutral, closed wait region.
    private static boolean sourceClosedWaitLoopExit(Address entry, Loop active,
            Listing listing, TaskMonitor monitor) throws CancelledException {
        if(entry==null||active==null||active.owner==null)return false;
        java.util.ArrayDeque<Address> work=new java.util.ArrayDeque<>();
        Set<Address> visited=new LinkedHashSet<>();
        boolean backJump=false;
        work.add(entry);
        while(!work.isEmpty()) {
            monitor.checkCancelled();
            Address at=work.removeFirst();
            if(!"PM".equals(at.getAddressSpace().getName())||
               !active.owner.getBody().contains(at))return false;
            int w=word(at);
            if(w>=active.first+1&&w<=active.last)return false;
            if(!visited.add(at))continue;
            if(visited.size()>128)return false;
            Instruction ins=listing.getInstructionAt(at);
            if(ins==null||ins.getLength()!=3||mutatesControlStack(ins)||
               nativeCounterWrite(ins)||ins.toString().trim().startsWith("DO ")||
               ins.getFlowType().isTerminal()||ins.getFlowType().isComputed()||
               ins.getFlowType().isCall())return false;
            Address[] flows=ins.getFlows();
            Address fall=ins.getFallThrough();
            if(ins.getFlowType().isJump()&&flows.length==0)return false;
            if(fall==null&&flows.length==0)return false;
            if(fall!=null)work.add(fall);
            for(Address dst:flows) {
                if(dst.compareTo(at)<=0)backJump=true;
                work.add(dst);
            }
        }
        return backJump;
    }

    // A same-function, straight-line RTS tail has no path back to this CE.
    // This proves only that the path exits before the counted endpoint;
    // hardware frame cleanup on that path remains UNKNOWN. Do not use this
    // predicate as evidence that the caller's DO/CNTR stack was preserved.
    // The native CE backedge is source-encoded on the *remaining* paths.
    private static boolean sourceTerminalRtsExit(Address start, Function owner,
            Listing listing, TaskMonitor monitor) throws CancelledException {
        if(start==null||owner==null||!owner.getBody().contains(start))return false;
        Set<Address> visited=new LinkedHashSet<>();
        Address at=start;
        for(int n=0;n<12&&at!=null&&visited.add(at);n++) {
            monitor.checkCancelled();
            if(!owner.getBody().contains(at))return false;
            Instruction ins=listing.getInstructionAt(at);
            if(ins==null||ins.getLength()!=3)return false;
            String text=ins.toString().trim().toUpperCase(java.util.Locale.ROOT);
            if(text.equals("RTS"))return true;
            if(mutatesControlStack(ins)||nativeCounterWrite(ins)||text.startsWith("DO ")||
               ins.getFlowType().isCall()||ins.getFlowType().isJump()||
               ins.getFlowType().isTerminal()||ins.getFlowType().isComputed()||
               ins.getFlows().length!=0)return false;
            at=ins.getFallThrough();
        }
        return false;
    }

    // Interpret the *control/data-flow of the loop body*, not a linear code
    // interval. A counter re-load inside a DO is safe only if every reachable
    // branch consumes it in a source-verified counted callee before arriving
    // at the caller's CE. Conditional calls may skip the callee and cannot
    // discharge a pending count-stack frame.
    private record CountFlowState(int word, boolean pendingCounter) {}

    private static boolean sourceLoopCountFlowBalanced(Loop l, Program p,
            TaskMonitor monitor) throws CancelledException {
        Listing listing=p.getListing();
        FunctionManager fm=p.getFunctionManager();
        java.util.ArrayDeque<CountFlowState> todo=new java.util.ArrayDeque<>();
        Set<CountFlowState> seen=new LinkedHashSet<>();
        Map<Address,Boolean> counterConsumers=new LinkedHashMap<>();
        Map<String,Boolean> callReturns=new LinkedHashMap<>();
        todo.add(new CountFlowState(l.first+1,false));
        boolean sourceCeReached=false;
        int calls=0;
        while(!todo.isEmpty()) {
            monitor.checkCancelled();
            CountFlowState state=todo.removeFirst();
            if(!seen.add(state))continue;
            if(seen.size()>2*(MAX_LOOP_WORDS+1))return false;
            int w=state.word();
            if(w<l.first+1||w>l.last)return false;
            Instruction ins=listing.getInstructionAt(pm(p,w));
            if(ins==null||ins.getLength()!=3||
               !l.owner.getBody().contains(ins.getAddress())||
               mutatesControlStack(ins))return false;
            // Native CE decrements the *caller's original counter*. Its own
            // nested push frame must have been consumed on all paths.
            if(w==l.last) {
                if(state.pendingCounter()||nativeCounterWrite(ins))return false;
                sourceCeReached=true;
                continue;
            }
            if(ins.toString().trim().startsWith("DO ")||
               (ins.getFlowType().isComputed()&&
                !ins.getFlowType().isTerminal()))return false;
            boolean pending=state.pendingCounter();
            if(nativeJumpToResetExit(ins,p,monitor))continue;
            boolean call=ins.getFlowType().isCall();
            if(nativeCounterWrite(ins)) {
                if(pending || call || ins.getFlowType().isJump() ||
                   ins.getFlowType().isTerminal())return false;
                pending=true;
            }
            if(call) {
                if(++calls>8*(MAX_LOOP_WORDS+1)||
                   ins.getFlows().length!=1||
                   !"NONE".equals(ins.getFlowOverride().name())||
                   nativeReturnContinuation(ins,l.owner)==null)return false;
                Function provider=fm.getFunctionAt(ins.getFlows()[0]);
                if(pending) {
                    // A conditional CALL has a branch on which the counter
                    // is never consumed. Only unconditional CALL balances it.
                    if(ins.getFlowType().isConditional())return false;
                    if(provider==null)return false;
                    Boolean known=counterConsumers.get(provider.getEntryPoint());
                    boolean valid=known!=null?known:
                        balancedCountConsumer(provider,listing,p,monitor);
                    counterConsumers.put(provider.getEntryPoint(),valid);
                    if(!valid)return false;
                    pending=false;
                } else {
                    // A subsequent callee can execute one complete counted
                    // DO/CE using the currently live caller CNTR without a
                    // fresh counter write. Its native DO entry, source CE
                    // endpoint and immediate RTS are all required by the
                    // same balanced-count consumer contract. Only the exact
                    // source-native backedge is restored here; no hardware
                    // claim about the shared PC/CNTR stack is inferred.
                    boolean flatReturn=returnsViaSharedPcStack(provider,listing,fm,
                        callReturns,new LinkedHashSet<>(),0,monitor);
                    if(!flatReturn) {
                        if(provider==null)return false;
                        Boolean known=counterConsumers.get(provider.getEntryPoint());
                        boolean countedReturn=known!=null?known:
                            balancedCountConsumer(provider,listing,p,monitor);
                        counterConsumers.put(provider.getEntryPoint(),countedReturn);
                        if(!countedReturn)return false;
                    }
                }
                Address ft=nativeReturnContinuation(ins,l.owner);
                int successor=word(ft);
                if(successor<=w||successor>l.last)return false;
                todo.add(new CountFlowState(successor,pending));
                continue;
            }
            if(ins.getFlowType().isTerminal()) {
                Address[] exits=ins.getFlows();
                if(exits.length==1&&sourceResetStackExit(exits[0],p,monitor))continue;
                return false;
            }
            Address fallthrough=ins.getFallThrough();
            if(fallthrough!=null) {
                if(!"PM".equals(fallthrough.getAddressSpace().getName()))return false;
                todo.add(new CountFlowState(word(fallthrough),pending));
            }
            Address[] flows=ins.getFlows();
            if(ins.getFlowType().isJump()&&flows.length==0)return false;
            if(fallthrough==null&&flows.length==0)return false;
            for(Address dst:flows) {
                if(!"PM".equals(dst.getAddressSpace().getName()))return false;
                int to=word(dst);
                if(to<l.first+1||to>l.last) {
                    if(sourceResetStackExit(dst,p,monitor)||
                       sourceTerminalRtsExit(dst,l.owner,listing,monitor)||
                       sourceClosedWaitLoopExit(dst,l,listing,monitor))continue;
                    return false;
                }
                todo.add(new CountFlowState(to,pending));
            }
        }
        // A loop whose CE is never reachable from its original DO successor
        // cannot be classified by this proof, even when the state queue is
        // exhausted without an explicit contradiction. Unreachable source
        // endpoints must never be transformed into synthetic backedges.
        return sourceCeReached;
    }

    private static boolean eligible(Loop l, List<Loop> all, Program p, TaskMonitor monitor)
            throws Exception {
        Listing listing = p.getListing();
        Function owner = l.owner;
        if (owner == null || owner.isExternal() || l.first >= l.last ||
            l.last - l.first > MAX_LOOP_WORDS ||
            !owner.getBody().contains(pm(p, l.last))) return false;
        // Resident wrapper-specific CE semantics must not be rewritten by the
        // generic codec counter model. Test the actual ISA context, not a
        // firmware/profile filename.
        Register wrapper = p.getRegister("srvdsp_wrapper_mode");
        if (wrapper != null) {
            BigInteger mode = p.getProgramContext().getValue(wrapper,
                l.begin.getAddress(), false);
            if (mode != null && mode.signum() != 0) return false;
        }
        for (Loop other : all) if (l != other && intersects(l, other)) return false;
        Address after = pm(p, l.first + 1);
        if (!after.equals(l.begin.getFallThrough())) return false;
        Instruction last = listing.getInstructionAt(pm(p, l.last));
        // Two actual-source conditions require the same architecture rule:
        // (a) already decoded conditional CE with an indirect hardware loop
        //     backedge, or
        // (b) a decoded, control-stack-neutral endpoint whose *missing* CE
        //     context suppresses the mandatory counted-loop P-code branch.
        // The original DO word must still encode this exact endpoint and
        // the bounded interprocedural count flow must separately balance.
        // Native CALL/RTS/RTI/JUMP endpoints need their own composite flow
        // contracts; never reinterpret them as ordinary CE terminators.
        if (last == null || last.getLength() != 3) return false;
        boolean nativeIndirectCe=code(last,PcodeOp.CBRANCH)>=1 &&
            code(last,PcodeOp.BRANCHIND)==1 &&
            code(last,PcodeOp.BRANCH)==0;
        boolean missingNativeCe=code(last,PcodeOp.BRANCHIND)==0 &&
            code(last,PcodeOp.BRANCH)==0 &&
            !last.getFlowType().isCall() &&
            !last.getFlowType().isJump() &&
            !last.getFlowType().isTerminal() &&
            !last.getFlowType().isComputed() &&
            !last.toString().trim().equals("RTS") &&
            !last.toString().trim().equals("RTI") &&
            !last.toString().trim().startsWith("DO ");
        // A native CALL can be the very last instruction of DO..CE.
        // Ghidra cannot represent CALL and the CE backedge with one flow
        // enum. Its P-code must retain the ORIGINAL target and control
        // stack behavior. Limit this extra case to a source-returning,
        // stack-preserving callee, no stale CALL_RETURN override, and a
        // decoded caller continuation. Other composite instructions stay
        // UNSUPPORTED instead of receiving invented backedges.
        boolean nativeCallCeCandidate=false;
        if(code(last,PcodeOp.CALL)==1&&
           code(last,PcodeOp.BRANCH)==0&&
           code(last,PcodeOp.BRANCHIND)<=1&&
           (last.getFlowType().isCall()||
            "INVALID".equals(last.getFlowType().toString()))&&
           last.toString().trim().matches("(?i)^CALL\\s+0x[0-9a-f]+$")&&
           "NONE".equals(last.getFlowOverride().name())&&
           owner.getBody().contains(pm(p,l.last+1))) {
            // One native CALL can be combined with a computed CE backedge.
            // Ghidra represents that composite flow as INVALID, not CALL.
            // Read the exact PM target from original CALL P-code rather
            // than relying on the incomplete instruction FlowType enum.
            Address target=null;
            for(PcodeOp op:last.getPcode())
                if(op.getOpcode()==PcodeOp.CALL)
                    target=op.getInput(0).getAddress();
            Function provider=target!=null&&
                "PM".equals(target.getAddressSpace().getName())?
                p.getFunctionManager().getFunctionAt(target):null;
            nativeCallCeCandidate=provider!=null&&!provider.isExternal()&&
                returnsViaSharedPcStack(provider,listing,p.getFunctionManager(),
                    new LinkedHashMap<>(),new LinkedHashSet<>(),0,monitor);
        }
        if(code(last,PcodeOp.CALL)>0&&!nativeCallCeCandidate)return false;
        if(!nativeIndirectCe&&!missingNativeCe&&!nativeCallCeCandidate)return false;
        Register directContext = p.getRegister("codec_ce_direct_backedge");
        if (directContext == null) return false;
        BigInteger alreadyDirect = p.getProgramContext().getValue(directContext,
            last.getAddress(), false);
        if (alreadyDirect != null && alreadyDirect.signum() != 0) return false;

        // Source ISA word encodes the complete target. No guessed endpoints.
        byte[] raw = l.begin.getBytes();
        if (raw.length != 3) return false;
        int bits = (raw[0] & 255) << 16 | (raw[1] & 255) << 8 | (raw[2] & 255);
        if (bits >>> 18 != 5 || (bits & 15) != 14 ||
            (bits >>> 4 & 0x3fff) != l.last) return false;

        // DO installs the actual architectural loop-start address regardless
        // of where the 14-bit CNTR value came from. A caller may supply CNTR
        // through the native ABI before entering this function. Do not
        // falsely classify such loops as having no backedge because their
        // source counter writer lies outside the immediate predecessor span.
        // Counter VALUE provenance stays UNKNOWN; the source-native DO/CE
        // backedge itself is exact. No writes within the active loop are
        // permitted unless all their stack effects are separately proved.
        // One machine-source state machine handles conditional branches,
        // nested counted subroutine calls, and input CNTR safely.
        if(!sourceLoopCountFlowBalanced(l,p,monitor))return false;
        return true;
    }

    private static String c(DecompInterface decompiler, Function f, TaskMonitor monitor)
            throws Exception {
        DecompileResults result = decompiler.decompileFunction(f, 35, monitor);
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
            throw new IllegalStateException("Original Analyzer C unavailable " + f.getEntryPoint());
        }
        return result.getDecompiledFunction().getC();
    }

    private static int cLoops(String source) {
        return source.split("do \\{", -1).length - 1;
    }

    private static int cWarnings(String source) {
        return source.split("WARNING:", -1).length - 1;
    }

    private static boolean run(Program program, AddressSetView set, TaskMonitor monitor,
                               MessageLog log, boolean commitChanges) throws Exception {
        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();
        List<Loop> all = new ArrayList<>();
        for (Instruction ins : listing.getInstructions(true)) {
            monitor.checkCancelled();
            if (!"PM".equals(ins.getAddress().getAddressSpace().getName())) continue;
            Matcher m = DO.matcher(ins.toString().trim());
            if (m.matches()) {
                int target = Integer.parseInt(m.group(1), 16);
                all.add(new Loop(word(ins.getAddress()), target, ins,
                    fm.getFunctionContaining(ins.getAddress())));
            }
        }
        // The nested experiment is read-only and must not increase normal
        // import latency or silently select static hardware semantics.
        List<NestedGroup> twoLevelPlans = commitChanges ? List.of() :
            planarTwoLevelNested(all, program, monitor);
        List<Candidate> candidates = new ArrayList<>();
        for (Loop l : all) {
            monitor.checkCancelled();
            if (!set.intersects(pm(program, l.first), pm(program, l.last)) ||
                !eligible(l, all, program, monitor)) continue;
            Instruction finish=listing.getInstructionAt(pm(program,l.last));
            boolean missingCe=code(finish,PcodeOp.BRANCHIND)==0;
            Address nativeCallTarget=null;
            for(PcodeOp op:finish.getPcode())
                if(op.getOpcode()==PcodeOp.CALL)
                    nativeCallTarget=op.getInput(0).getAddress();
            candidates.add(new Candidate(l,finish.getBytes(),missingCe,nativeCallTarget));
        }
        if (!commitChanges) {
            int nestedEnds = 0;
            for (NestedGroup plan : twoLevelPlans) nestedEnds += plan.inner.size() + 1;
            log.appendMsg("Sunplus DSP two-level static CE",
                "Source-only planner groups="+twoLevelPlans.size()+
                " CE_endpoints="+nestedEnds+
                "; preview only; hardware PC-stack proof UNKNOWN");
        }
        if (candidates.isEmpty()) return true;

        Map<Function, List<Candidate>> perOwner = new LinkedHashMap<>();
        for (Candidate candidate : candidates)
            perOwner.computeIfAbsent(candidate.loop.owner, ignored -> new ArrayList<>()).add(candidate);
        if (perOwner.size() > MAX_CHANGED_FUNCTIONS) {
            log.appendMsg(getClassName(), "Too many loop owners; no automated changes");
            return true;
        }
        // Read-only planning never opens Ghidra transactions; a source
        // discovery is NOT a successful C/CFG transformation.
        if (!commitChanges) {
            log.appendMsg("Sunplus DSP native DO/CE",
                "Source-eligible "+candidates.size()+" native CE endpoints in "+
                perOwner.size()+" existing owners; C acceptance pending");
            return true;
        }
        Register ce=program.getRegister("codec_ce_loop_end");
        Register direct=program.getRegister("codec_ce_direct_backedge");
        Register target=program.getRegister("codec_ce_direct_start");
        if(ce==null||direct==null||target==null)
            throw new IllegalStateException("UNSUPPORTED native CE context register");
        int sourceFunctionCount=fm.getFunctionCount();
        int recovered=0,missing=0,rejected=0;
        // Complete and verify one native owner at a time. A single
        // impossible C/CFG owner must not erase proven changes to unrelated
        // source functions. Unlike a global speculative transaction, each
        // owner has an exact original-context and function-identity rollback.
        for(var ownerEntry:perOwner.entrySet()) {
            monitor.checkCancelled();
            Function owner=ownerEntry.getKey();
            List<Candidate> ownerCandidates=ownerEntry.getValue();
            String before;
            DecompInterface oldC=new DecompInterface();
            try {
                if(!oldC.openProgram(program))
                    throw new IllegalStateException("Original native C generator unavailable");
                before=c(oldC,owner,monitor);
                if(before.isBlank()||before.contains("halt_baddata"))
                    throw new IllegalStateException(
                        "UNSUPPORTED native owner C baseline "+owner.getEntryPoint());
            }catch(CancelledException cancelled){throw cancelled;}
            catch(Exception unsupported) {
                rejected+=ownerCandidates.size();
                log.appendMsg("Sunplus native CE",
                    "UNSUPPORTED owner "+owner.getEntryPoint()+
                    " C baseline: "+unsupported.getMessage());
                continue;
            }finally{oldC.dispose();}
            Map<Address,List<BigInteger>> contextBefore=new LinkedHashMap<>();
            Map<Address,String> originalFlow=new LinkedHashMap<>();
            for(Candidate candidate:ownerCandidates) {
                Address at=pm(program,candidate.loop.last);
                originalFlow.put(at,nativeFlowSignature(listing.getInstructionAt(at)));
                contextBefore.put(at,List.of(
                    getContextOrSentinel(program,ce,at),
                    getContextOrSentinel(program,direct,at),
                    getContextOrSentinel(program,target,at)));
            }
            String identity=owner.getName()+"|"+owner.getBody()+"|"+
                owner.getComment()+"|"+owner.hasNoReturn();
            int tx=program.startTransaction(
                "Source-native DSP DO/CE owner "+owner.getEntryPoint());
            boolean accepted=false;
            String failure=null;
            try {
                for(Candidate candidate:ownerCandidates) {
                    monitor.checkCancelled();
                    Address at=pm(program,candidate.loop.last);
                    listing.clearCodeUnits(at,at.add(2),false);
                    program.getProgramContext().setValue(ce,at,at,BigInteger.ONE);
                    program.getProgramContext().setValue(direct,at,at,BigInteger.ONE);
                    program.getProgramContext().setValue(target,at,at,
                        BigInteger.valueOf(candidate.loop.first+1));
                    DisassembleCommand decode=new DisassembleCommand(
                        new AddressSet(at,at.add(2)),null,true);
                    decode.enableCodeAnalysis(false);
                    if(!decode.applyTo(program,monitor))
                        throw new IllegalStateException("Native CE decode rejected "+at);
                    Instruction rendered=listing.getInstructionAt(at);
                    if(rendered==null||
                       !Arrays.equals(rendered.getBytes(),candidate.endBytes))
                        throw new IllegalStateException("Native CE bytes changed "+at);
                    int correctEdges=0;
                    for(PcodeOp op:rendered.getPcode()) {
                        if(op.getOpcode()==PcodeOp.BRANCH&&
                           op.getInput(0).getAddress().equals(
                               pm(program,candidate.loop.first+1)))
                            correctEdges++;
                    }
                    if(correctEdges!=1||
                       code(rendered,PcodeOp.CBRANCH)<1||
                       code(rendered,PcodeOp.BRANCHIND)!=0)
                        throw new IllegalStateException(
                            "Native DO/CE backedge missing "+at);
                    if(candidate.nativeCallTarget!=null) {
                        int sourceCalls=0;
                        for(PcodeOp op:rendered.getPcode())
                            if(op.getOpcode()==PcodeOp.CALL&&
                               candidate.nativeCallTarget.equals(
                                   op.getInput(0).getAddress()))
                                sourceCalls++;
                        if(sourceCalls!=1||code(rendered,PcodeOp.CALL)!=1)
                            throw new IllegalStateException(
                                "Composite native CALL target changed "+at);
                    }
                    boolean qa=program.getDomainFile()!=null&&
                        program.getDomainFile().getPathname().startsWith(
                            "/RUSH28-architecture-import-validation/");
                    if(qa&&"1".equals(System.getenv(
                        "RUSH28_NATIVE_CE_ABORT_AFTER_FIRST_QA")))
                        throw new IllegalStateException(
                            "QA_FAULT_INJECTED_AFTER_NATIVE_CE_RECODE");
                }
                if(fm.getFunctionCount()!=sourceFunctionCount||
                   !identity.equals(owner.getName()+"|"+owner.getBody()+"|"+
                       owner.getComment()+"|"+owner.hasNoReturn()))
                    throw new IllegalStateException(
                        "Native CE source function identity changed");
                DecompInterface nextC=new DecompInterface();
                try {
                    if(!nextC.openProgram(program))
                        throw new IllegalStateException("Updated native C unavailable");
                    String after=c(nextC,owner,monitor);
                    if(after.isBlank()||after.contains("halt_baddata")||
                       cWarnings(after)>cWarnings(before)||
                       cLoops(after)<cLoops(before))
                        throw new IllegalStateException(
                            "Native CE C/CFG regression "+owner.getEntryPoint());
                }finally{nextC.dispose();}
                accepted=true;
            }catch(CancelledException cancelled){throw cancelled;}
            catch(Exception unsupported){failure=unsupported.toString();}
            finally{program.endTransaction(tx,accepted);}
            if(!accepted) {
                rejected+=ownerCandidates.size();
                if(fm.getFunctionCount()!=sourceFunctionCount||
                   !identity.equals(owner.getName()+"|"+owner.getBody()+"|"+
                       owner.getComment()+"|"+owner.hasNoReturn()))
                    throw new IllegalStateException(
                        "UNSUPPORTED native CE rollback leaked owner metadata");
                for(Candidate candidate:ownerCandidates) {
                    Address at=pm(program,candidate.loop.last);
                    Instruction restored=listing.getInstructionAt(at);
                    if(restored==null||
                       !Arrays.equals(restored.getBytes(),candidate.endBytes)||
                       !originalFlow.get(at).equals(nativeFlowSignature(restored))||
                       !contextBefore.get(at).equals(List.of(
                           getContextOrSentinel(program,ce,at),
                           getContextOrSentinel(program,direct,at),
                           getContextOrSentinel(program,target,at))))
                        throw new IllegalStateException(
                            "UNSUPPORTED native CE rollback leaked P-code context "+at);
                }
                log.appendMsg("Sunplus DSP native DO/CE",
                    "UNSUPPORTED owner "+owner.getEntryPoint()+
                    " reason="+failure);
            }else{
                recovered+=ownerCandidates.size();
                for(Candidate candidate:ownerCandidates)
                    if(candidate.missingCe)missing++;
            }
        }
        log.appendMsg("Sunplus DSP native DO/CE",
            "CONFIRMED_STATIC recovered="+recovered+
            " missing_CE_context="+missing+
            " UNSUPPORTED="+rejected+
            " original_bytes_preserved=true verified_owner_C=true");
        return true;
    }

    // The same bytes can decode to different control flow under different
    // SLEIGH context. Capture full original CFG + P-code for rollback
    // comparison, not just an instruction's 24-bit source bytes.
    private static String nativeFlowSignature(Instruction i) {
        if(i==null)return "UNDEFINED";
        StringBuilder proof=new StringBuilder()
            .append(i.getFlowType()).append('|')
            .append(i.getFlowOverride()).append('|')
            .append(i.getFallThrough()).append('|')
            .append(Arrays.toString(i.getFlows()));
        for(PcodeOp op:i.getPcode())
            proof.append('|').append(op.getOpcode()).append(':')
                .append(Arrays.toString(op.getInputs())).append("->")
                .append(op.getOutput());
        return proof.toString();
    }

    // Missing context values are represented by a sentinel OUTSIDE legal
    // nonnegative SLEIGH context bitfields, avoiding null List.of entries.
    private static BigInteger getContextOrSentinel(Program p,Register reg,
            Address at) {
        BigInteger value=p.getProgramContext().getValue(reg,at,false);
        return value==null?BigInteger.valueOf(-1):value;
    }

    private static String getClassName() { return "SunplusNativeCeAutoAnalyzer"; }

    /**
     * Read-only machine-source eligibility plan (no transactions and no
     * Pcode changes). Ghidra script service can own an outer transaction;
     * never use nested rollback as a simulated dry run. Actual C acceptance
     * is performed by the automatic pass on a newly analyzed program.
     */
    public boolean dryRun(Program program, AddressSetView set,
                          TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program) || set == null || set.isEmpty()) return true;
        try {
            return run(program, set, monitor, log, false);
        }
        catch (CancelledException cancelled) { throw cancelled; }
        catch (Exception failure) {
            log.appendMsg(getClassName(), "Dry-run gated: " + failure.getMessage());
            return false;
        }
    }

    /**
     * Called by the MCP bridge only after the standard auto-analysis task
     * has closed its transaction and saved its state. This isolation is
     * required: a false nested Ghidra transaction does not undo edits held
     * by an enclosing transaction. No original firmware bytes are modified.
     */
    public boolean applyAfterSavedAnalysis(Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        if (!canAnalyze(program)) return true;
        if (program.isChanged()) {
            log.appendMsg(getClassName(),
                "Refusing native CE recovery while other program edits are unsaved");
            return false;
        }
        try {
            AddressSetView loaded = program.getMemory().getLoadedAndInitializedAddressSet();
            return run(program, loaded, monitor, log, true);
        }
        catch (CancelledException cancelled) { throw cancelled; }
        catch (Exception failure) {
            log.appendMsg(getClassName(), "Native CE recovery rejected: " + failure+
                " cleanAfterRollback="+!program.isChanged());
            return false;
        }
    }

    /**
     * Production source-native nested DO/CE recovery.
     * Only proven, bounded native nested groups are eligible. The shared
     * transactional Ghidra C gate rejects regressions and preserves bytes.
     * The controlled fault-injection QA path remains separate.
     */
    public boolean applyProvenNestedAfterSavedAnalysis(
            Program program, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        if (!canAnalyze(program)) return true;
        boolean isolatedQa = program.getDomainFile()!=null &&
            program.getDomainFile().getPathname().startsWith(
                "/RUSH28-architecture-import-validation/");
        if (isolatedQa && "1".equals(System.getenv("RUSH28_NESTED_CE_QA")))
            return true;
        if (program.isChanged()) {
            log.appendMsg(getClassName(), "UNSUPPORTED nested CE: unsaved program changes");
            return false;
        }
        try {return recoverNestedSourceFrames(program,monitor,log,false);}
        catch (CancelledException cancelled) {throw cancelled;}
        catch (Exception failure) {
            boolean rolledBack=!program.isChanged();
            log.appendMsg(getClassName(), "UNSUPPORTED nested CE: "+
                failure.getMessage()+" cleanAfterRollback="+rolledBack);
            // A rollback is integrity evidence, not acceptance evidence.
            // Never report a failed source transformation as a successful
            // processor pass simply because the original data stayed clean.
            return false;
        }
    }

    /**
     * QA-only top-level two-level native CE trial. Never enabled on production
     * saved programs: full hardware shared-PC-stack semantics remain UNKNOWN.
     * This runs after the ordinary analysis transaction has been saved, and
     * verifies every recoded source instruction and every affected owner's C
     * before atomically committing a private QA program's new context.
     */
    public boolean applyExperimentalNestedAfterSavedAnalysis(
            Program program, TaskMonitor monitor, MessageLog log) throws CancelledException {
        if (!canAnalyze(program)) return true;
        boolean qaProgram = program.getDomainFile()!=null &&
            program.getDomainFile().getPathname().startsWith(
                "/RUSH28-architecture-import-validation/");
        if (!qaProgram || !"1".equals(System.getenv("RUSH28_NESTED_CE_QA"))) return true;
        if (program.isChanged()) {
            log.appendMsg(getClassName(), "Nested QA refused unsaved program changes");
            return false;
        }
        try {return recoverNestedSourceFrames(program,monitor,log,true);}
        catch (CancelledException c){throw c;}
        catch (Exception e){
            log.appendMsg(getClassName(), "Nested QA rollback: "+e+
                " cleanAfterRollback="+!program.isChanged());
            return false;
        }
    }

    private record NestedSite(Address address, byte[] source, int depth,
                              boolean end, Address expectedBackedge) {}

    private static boolean recoverNestedSourceFrames(Program program,
            TaskMonitor monitor, MessageLog log, boolean qa) throws Exception {
        Listing listing=program.getListing();
        FunctionManager fm=program.getFunctionManager();
        List<Loop> loops=new ArrayList<>();
        for (Instruction inst:listing.getInstructions(true)) {
            monitor.checkCancelled();
            if (!"PM".equals(inst.getAddress().getAddressSpace().getName())) continue;
            Matcher matcher=DO.matcher(inst.toString().trim());
            if (matcher.matches()) loops.add(new Loop(word(inst.getAddress()),
                Integer.parseInt(matcher.group(1),16),inst,
                fm.getFunctionContaining(inst.getAddress())));
        }
        List<NestedGroup> groups=planarTwoLevelNested(loops,program,monitor);
        List<ThreeLevelGroup> thirdGroups=planarThreeLevelNested(loops,program,monitor);
        if (groups.isEmpty()&&thirdGroups.isEmpty()) {
            log.appendMsg("Sunplus native nested "+(qa?"QA":"production"),
                "No eligible source-proven nested groups; untouched");
            return true;
        }
        if (groups.size()+thirdGroups.size()>20)
            throw new IllegalStateException("Nested source group bound exceeded");
        Map<Address,NestedSite> sites=new LinkedHashMap<>();
        Map<Function,String> previous=new LinkedHashMap<>();
        for (NestedGroup group:groups) {
            Loop outer=group.outer;
            previous.putIfAbsent(outer.owner,null);
            // LDI CNTR carries an encoded 14-bit immediate already. Leave
            // its original P-code unchanged; only DM/register writers can
            // inject high counter bits and require a scoped architecture mask.
            if (group.outerWriter!=null &&
                !group.outerWriter.toString().trim().startsWith("LDI CNTR,"))
                addNestedSite(sites,group.outerWriter,1,false,null);
            addNestedSite(sites,outer.begin,1,false,null);
            addNestedSite(sites,listing.getInstructionAt(pm(program,outer.last)),1,
                          true,pm(program,outer.first+1));
            for (int k=0;k<group.inner.size();k++) {
                Loop inner=group.inner.get(k);
                addNestedSite(sites,group.writers.get(k),2,false,null);
                addNestedSite(sites,inner.begin,2,false,null);
                addNestedSite(sites,listing.getInstructionAt(pm(program,inner.last)),2,
                              true,pm(program,inner.first+1));
            }
        }
        for(ThreeLevelGroup group:thirdGroups) {
            Loop outer=group.outer;
            previous.putIfAbsent(outer.owner,null);
            if(group.outerWriter!=null &&
               !group.outerWriter.toString().trim().startsWith("LDI CNTR,"))
                addNestedSite(sites,group.outerWriter,1,false,null);
            addNestedSite(sites,outer.begin,1,false,null);
            addNestedSite(sites,listing.getInstructionAt(pm(program,outer.last)),1,
                          true,pm(program,outer.first+1));
            addNestedSite(sites,group.middleWriter,2,false,null);
            addNestedSite(sites,group.middle.begin,2,false,null);
            addNestedSite(sites,listing.getInstructionAt(pm(program,group.middle.last)),2,
                          true,pm(program,group.middle.first+1));
            for(int k=0;k<group.inner.size();k++) {
                Loop child=group.inner.get(k);
                addNestedSite(sites,group.writers.get(k),3,false,null);
                addNestedSite(sites,child.begin,3,false,null);
                addNestedSite(sites,listing.getInstructionAt(pm(program,child.last)),3,
                              true,pm(program,child.first+1));
            }
        }
        Map<Function,String> identities=new LinkedHashMap<>();
        for(Function f:previous.keySet())
            identities.put(f,f.getName()+"|"+f.getBody()+"|"+
                f.hasNoReturn()+"|"+f.getComment());
        Set<Function> missingBaselineOwners=new LinkedHashSet<>();
        DecompInterface generator=new DecompInterface();
        try {
            if (!generator.openProgram(program))
                throw new IllegalStateException("Nested C unavailable");
            for (Function f:previous.keySet()) {
                monitor.checkCancelled();
                try {
                    String baseline=c(generator,f,monitor);
                    if (baseline.isBlank() || baseline.contains("halt_baddata"))
                        throw new IllegalStateException(
                            "UNSUPPORTED native baseline C "+f.getEntryPoint());
                    previous.put(f,baseline);
                }catch(CancelledException cancelled){throw cancelled;}
                catch(Exception unavailable) {
                    if(qa)throw unavailable;
                    missingBaselineOwners.add(f);
                    log.appendMsg("Sunplus nested source production",
                        "UNSUPPORTED native owner C baseline "+
                        f.getEntryPoint()+": "+unavailable.getMessage());
                }
            }
        }finally{generator.dispose();}
        int originalFunctions=fm.getFunctionCount();
        if(qa) {
            // Private fault-injection QA intentionally preserves one original
            // all-or-nothing transaction for rollback verification.
            int tx=program.startTransaction("QA native source nested DO/CE atomic trial");
            boolean accept=false;
            try {
                rewriteNestedSites(program,sites,monitor,true);
                verifyNestedOwners(program,previous,identities,originalFunctions,monitor);
                accept=true;
            }finally{program.endTransaction(tx,accept);}
        } else {
            // Native owner is the atomic update boundary. One anomalous
            // DSP function must not veto otherwise source-proven nested
            // groups in unrelated functions. Bounded owner-level work also
            // avoids building one huge speculative C graph in Ghidra.
            Map<Function,Map<Address,NestedSite>> byOwner=new LinkedHashMap<>();
            for(NestedSite site:sites.values()) {
                Function owner=fm.getFunctionContaining(site.address);
                if(owner==null||!previous.containsKey(owner))
                    throw new IllegalStateException(
                        "UNSUPPORTED nested site without proven owner "+site.address);
                byOwner.computeIfAbsent(owner,ignored->new LinkedHashMap<>())
                    .put(site.address,site);
            }
            int acceptedOwners=0,rejectedOwners=0,acceptedEndpoints=0;
            for(var row:byOwner.entrySet()) {
                monitor.checkCancelled();
                Function owner=row.getKey();
                if(missingBaselineOwners.contains(owner)) {
                    rejectedOwners++;
                    continue;
                }
                Map<Address,List<BigInteger>> sourceContexts=
                    snapshotNativeNestedContexts(program,row.getValue());
                Map<Address,String> originalFlows=new LinkedHashMap<>();
                for(NestedSite site:row.getValue().values())
                    originalFlows.put(site.address,nativeFlowSignature(
                        listing.getInstructionAt(site.address)));
                int tx=program.startTransaction(
                    "Architecture native nested CE owner "+owner.getEntryPoint());
                boolean accept=false;
                String problem=null;
                try {
                    rewriteNestedSites(program,row.getValue(),monitor,false);
                    verifyNestedOwners(program,
                        java.util.Collections.singletonMap(owner,previous.get(owner)),
                        java.util.Collections.singletonMap(owner,identities.get(owner)),
                        originalFunctions,monitor);
                    accept=true;
                }catch(CancelledException cancelled){throw cancelled;}
                catch(Exception unsupported){problem=unsupported.toString();}
                finally{program.endTransaction(tx,accept);}
                if(!accept) {
                    assertNestedSourceRollback(program,row.getValue(),
                        sourceContexts,originalFlows);
                    if(fm.getFunctionCount()!=originalFunctions||
                       !identities.get(owner).equals(
                           owner.getName()+"|"+owner.getBody()+"|"+
                           owner.hasNoReturn()+"|"+owner.getComment()))
                        throw new IllegalStateException(
                            "UNSUPPORTED nested owner rollback leaked function identity");
                }
                if(accept) {
                    acceptedOwners++;
                    for(NestedSite site:row.getValue().values())
                        if(site.end)acceptedEndpoints++;
                } else {
                    rejectedOwners++;
                    log.appendMsg("Sunplus nested source production",
                        "UNSUPPORTED owner "+owner.getEntryPoint()+
                        " rollback="+problem);
                }
            }
            log.appendMsg("Sunplus nested source production",
                "CONFIRMED_STATIC owner_transactions="+acceptedOwners+
                " recovered_CE="+acceptedEndpoints+
                " UNSUPPORTED_owner_transactions="+rejectedOwners+
                " source_bytes_checked=true C_nonregression_per_owner=true"+
                " hardware shared-PC-stack proof UNKNOWN");
            return true;
        }
        int recovered=0;
        for(NestedGroup group:groups) recovered+=group.inner.size()+1;
        for(ThreeLevelGroup group:thirdGroups)recovered+=group.inner.size()+2;
        log.appendMsg("Sunplus nested source QA",
            "Recovered "+recovered+" static depth<=3 endpoints in "+
            (groups.size()+thirdGroups.size())+" groups (triple="+
            thirdGroups.size()+"); source bytes, identities and C checked;"+
            " hardware shared-PC-stack proof UNKNOWN");
        return true;
    }

    /**
     * Owner-local rollback must restore analysis context, not just preserve
     * firmware bytes. A recoded instruction can have identical source bytes
     * yet different P-code because its contextual CE flags leaked.
     */
    private static Map<Address,List<BigInteger>> snapshotNativeNestedContexts(
            Program program,Map<Address,NestedSite> sites) {
        Map<Address,List<BigInteger>> context=new LinkedHashMap<>();
        String[] names={"codec_ce_nested_mode","codec_ce_static_depth",
                        "codec_ce_loop_end","codec_ce_direct_backedge",
                        "codec_ce_direct_start","codec_ce_counter14"};
        for(NestedSite site:sites.values()) {
            List<BigInteger> values=new ArrayList<>();
            for(String name:names) {
                Register register=program.getRegister(name);
                if(register==null)
                    throw new IllegalStateException("UNSUPPORTED nested context "+name);
                values.add(program.getProgramContext().getValue(
                    register,site.address,false));
            }
            context.put(site.address,values);
        }
        return context;
    }

    private static void assertNestedSourceRollback(Program program,
            Map<Address,NestedSite> sites,
            Map<Address,List<BigInteger>> before,
            Map<Address,String> originalFlows) throws Exception {
        Map<Address,List<BigInteger>> after=
            snapshotNativeNestedContexts(program,sites);
        if(!before.equals(after))
            throw new IllegalStateException(
                "UNSUPPORTED nested owner rollback leaked processor context");
        for(NestedSite site:sites.values()) {
            Instruction restored=program.getListing().getInstructionAt(site.address);
            if(restored==null||
               !Arrays.equals(restored.getBytes(),site.source)||
               !originalFlows.get(site.address).equals(nativeFlowSignature(restored)))
                throw new IllegalStateException(
                    "UNSUPPORTED nested owner rollback changed source/CFG at "+site.address);
        }
    }

    private static void rewriteNestedSites(Program program,
            Map<Address,NestedSite> sites,TaskMonitor monitor,boolean qa)
            throws Exception {
        Listing listing=program.getListing();
        Register nested=program.getRegister("codec_ce_nested_mode");
        Register depth=program.getRegister("codec_ce_static_depth");
        Register ce=program.getRegister("codec_ce_loop_end");
        Register direct=program.getRegister("codec_ce_direct_backedge");
        Register dest=program.getRegister("codec_ce_direct_start");
        Register counter14=program.getRegister("codec_ce_counter14");
        if(nested==null||depth==null||ce==null||direct==null||
           dest==null||counter14==null)
            throw new IllegalStateException("Native nested context registers absent");
        for(NestedSite site:sites.values()) {
            monitor.checkCancelled();
            Instruction original=listing.getInstructionAt(site.address);
            boolean sourceCounterWriter=staticCounterWriter(original);
            listing.clearCodeUnits(site.address,site.address.add(2),false);
            program.getProgramContext().setValue(nested,site.address,site.address,BigInteger.ONE);
            program.getProgramContext().setValue(depth,site.address,site.address,
                BigInteger.valueOf(site.depth));
            if (site.end || sourceCounterWriter)
                program.getProgramContext().setValue(counter14,site.address,site.address,BigInteger.ONE);
            if(site.end) {
                program.getProgramContext().setValue(ce,site.address,site.address,BigInteger.ONE);
                program.getProgramContext().setValue(direct,site.address,site.address,BigInteger.ONE);
                program.getProgramContext().setValue(dest,site.address,site.address,
                    BigInteger.valueOf(word(site.expectedBackedge)));
            }
        }
        boolean firstNestedRecode=true;
        for(NestedSite site:sites.values()) {
            monitor.checkCancelled();
            DisassembleCommand command=new DisassembleCommand(
                new AddressSet(site.address,site.address.add(2)),null,true);
            command.enableCodeAnalysis(false);
            if(!command.applyTo(program,monitor))
                throw new IllegalStateException("Native nested decode failed at "+site.address);
            Instruction rendered=listing.getInstructionAt(site.address);
            if(rendered==null||!Arrays.equals(site.source,rendered.getBytes()))
                throw new IllegalStateException("Native nested source bytes differ at "+site.address);
            if(firstNestedRecode) {
                firstNestedRecode=false;
                if(qa && "1".equals(System.getenv("RUSH28_NESTED_CE_ABORT_AFTER_FIRST_QA")))
                    throw new IllegalStateException("QA_FAULT_INJECTED_AFTER_NESTED_RECODE");
            }
            if(site.end) {
                int directEdges=0;
                for(PcodeOp op:rendered.getPcode())
                    if(op.getOpcode()==PcodeOp.BRANCH&&
                       site.expectedBackedge.equals(op.getInput(0).getAddress()))
                        directEdges++;
                if(directEdges!=1||code(rendered,PcodeOp.CBRANCH)==0||
                   code(rendered,PcodeOp.BRANCHIND)!=0)
                    throw new IllegalStateException(
                        "Source nested CE backedge absent at "+site.address);
            }
        }
    }

    private static void verifyNestedOwners(Program program,
            Map<Function,String> previous,Map<Function,String> identities,
            int originalFunctions,TaskMonitor monitor)throws Exception {
        if(program.getFunctionManager().getFunctionCount()!=originalFunctions)
            throw new IllegalStateException("Nested recovery changed function inventory");
        for(var original:identities.entrySet()) {
            Function f=original.getKey();
            String now=f.getName()+"|"+f.getBody()+"|"+
                f.hasNoReturn()+"|"+f.getComment();
            if(!original.getValue().equals(now))
                throw new IllegalStateException(
                    "Nested recovery altered owner identity "+f.getEntryPoint());
        }
        DecompInterface verify=new DecompInterface();
        try {
            if(!verify.openProgram(program))
                throw new IllegalStateException("Native nested updated C unavailable");
            for(var entry:previous.entrySet()) {
                monitor.checkCancelled();
                String after=c(verify,entry.getKey(),monitor);
                String before=entry.getValue();
                if(after.isBlank()||after.contains("halt_baddata")||
                   cWarnings(after)>cWarnings(before)||
                   cLoops(after)<cLoops(before))
                    throw new IllegalStateException(
                        "Native nested C nonregression failed at "+
                        entry.getKey().getEntryPoint());
            }
        }finally{verify.dispose();}
    }

    private static void addNestedSite(Map<Address,NestedSite> target,Instruction instruction,
                                      int depth, boolean end,Address expected)
            throws Exception {
        if (instruction==null || instruction.getLength()!=3)
            throw new IllegalStateException("Missing native nested machine word");
        Address address=instruction.getAddress();
        NestedSite site=new NestedSite(address,instruction.getBytes(),depth,end,expected);
        NestedSite previous=target.putIfAbsent(address,site);
        // One CNTR writer may feed alternative sibling DO instructions.
        // Identical context is idempotent; conflicting depth/backedge isn't.
        if(previous!=null && (previous.depth()!=site.depth() ||
            previous.end()!=site.end() ||
            !java.util.Objects.equals(previous.expectedBackedge(),site.expectedBackedge()) ||
            !Arrays.equals(previous.source(),site.source())))
            throw new IllegalStateException("Conflicting source nested context "+address);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        if (!canAnalyze(program) || set == null || set.isEmpty()) return true;
        try {
            return run(program, set, monitor, log, true);
        }
        catch (CancelledException cancelled) { throw cancelled; }
        catch (Exception failure) {
            log.appendMsg("Sunplus DSP native DO/CE", "Skipped unsafe recovery: " + failure.getMessage());
            return true; // original program is protected by rollback
        }
    }
}
