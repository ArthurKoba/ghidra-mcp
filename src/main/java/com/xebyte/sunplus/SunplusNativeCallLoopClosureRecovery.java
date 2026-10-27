package com.xebyte.sunplus;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

/**
 * Native processor model: source-encoded zero-overhead DO/CE frame survives
 * a proven returning CALL. A stale Ghidra CALL_RETURN suppresses its real
 * fallthrough, so merely re-decoding the first CE can expose *further* native
 * DO frames with indirect backedges, making Analyzer C worse.
 *
 * Source exactness and a complete owner-local C gate are mandatory.
 * All program changes are atomic and rolled back on a CFG/C regression.
 * This is an ISA control-flow recovery, not a set of firmware-address fixes.
 */
public final class SunplusNativeCallLoopClosureRecovery {
    private SunplusNativeCallLoopClosureRecovery() {}
    private static final Pattern DO=Pattern.compile(
        "^DO\\s+0x([0-9a-f]+)\\s+UNTIL\\s+CE$",Pattern.CASE_INSENSITIVE);
    private static final Pattern BAD_EDGE=Pattern.compile(
        "Could not recover jumptable at 0x([0-9a-f]+)",Pattern.CASE_INSENSITIVE);
    private static final int MAX_GAP_WORDS=16;
    private static final int MAX_CLOSURE_WORDS=256;
    private static final int MAX_PROVEN_LOOPS=24;
    private static final int MAX_TWO_FRAME_GROUPS=12;
    private record Root(Instruction begin,Instruction call,Function owner,
                        Function callee,int first,int last) {}
    private static boolean pm(Instruction i) {
        return i!=null&&i.getLength()==3&&
            "PM".equals(i.getAddress().getAddressSpace().getName());
    }
    private static int op(Instruction i,int code) {
        int n=0;
        if(i!=null)for(PcodeOp x:i.getPcode())if(x.getOpcode()==code)n++;
        return n;
    }
    private static Address addr(Program p,int word){
        return p.getAddressFactory().getAddress(String.format("PM:%04x",word));
    }
    private static int word(Address a){return (int)a.getAddressableWordOffset();}
    private static String c(DecompInterface d,Function f,TaskMonitor monitor)
            throws Exception {
        d.flushCache();
        DecompileResults out=d.decompileFunction(f,40,monitor);
        if(!out.decompileCompleted()||out.getDecompiledFunction()==null)
            throw new IllegalStateException("UNSUPPORTED native C at "+f.getEntryPoint());
        String source=out.getDecompiledFunction().getC();
        if(source.isBlank()||source.contains("halt_baddata"))
            throw new IllegalStateException("UNSUPPORTED native C source "+f.getEntryPoint());
        return source;
    }
    private static int warnings(String c){return c.split("WARNING:",-1).length-1;}
    private static int loops(String c){return c.split("do \\{",-1).length-1;}
    private static boolean sourceCounterLoad(Instruction ins) {
        if(!pm(ins))return false;
        String s=ins.toString().trim();
        return s.startsWith("DMREAD CNTR,")||s.startsWith("LDI CNTR,")||
               s.startsWith("CNTR =");
    }
    private static boolean returningCallInCountedFrame(Instruction ins,
            Program p, Listing listing,FunctionManager fm,TaskMonitor monitor)
            throws CancelledException {
        if(!pm(ins)||!ins.getFlowType().isCall()||
           ins.getFlowOverride()!=FlowOverride.NONE||
           ins.getFlows().length!=1||op(ins,PcodeOp.CALL)!=1)return false;
        Function provider=fm.getFunctionAt(ins.getFlows()[0]);
        if(provider==null||provider.isExternal())return false;
        if(SunplusNativeCeAutoAnalyzer.returnsViaSharedPcStack(provider,
             listing,fm,new LinkedHashMap<>(),new LinkedHashSet<>(),0,monitor))
             return true;
        // A caller may load CNTR immediately before an unconditional CALL
        // into an RTS-returning counted leaf. Its native DO/CE consumes the
        // newly loaded count while the hardware stack saves the outer frame.
        // A conditional CALL cannot guarantee that the loaded count is used.
        Instruction before=listing.getInstructionAt(ins.getAddress().subtract(3));
        return !ins.getFlowType().isConditional() &&
            sourceCounterLoad(before) &&
            SunplusNativeCeAutoAnalyzer.balancedCountConsumer(provider,
                listing,p,monitor);
    }
    private static boolean exactDo(Instruction inst,int expectedEnd)throws Exception {
        if(!pm(inst))return false;
        byte[] b=inst.getBytes();
        int bits=(b[0]&255)<<16|(b[1]&255)<<8|(b[2]&255);
        return (bits>>>18)==5&&(bits&15)==14&&
            ((bits>>>4)&0x3fff)==expectedEnd;
    }
    private static List<Root> plan(Program p,TaskMonitor monitor)throws Exception {
        Listing listing=p.getListing();FunctionManager fm=p.getFunctionManager();
        List<Root> roots=new ArrayList<>();
        for(Instruction inst:listing.getInstructions(true)) {
            monitor.checkCancelled();
            if(!pm(inst))continue;
            Matcher d=DO.matcher(inst.toString().trim());
            if(!d.matches())continue;
            int first=word(inst.getAddress()),last=Integer.parseInt(d.group(1),16);
            if(first>=last||last-first>MAX_GAP_WORDS||
               !exactDo(inst,last)||listing.getInstructionAt(addr(p,last))!=null)
                continue;
            Function owner=fm.getFunctionContaining(inst.getAddress());
            if(owner==null||owner.isExternal()||
               owner.getBody().contains(addr(p,last)))continue;
            Instruction call=null;
            for(int w=first+1;w<last;w++) {
                Instruction candidate=listing.getInstructionAt(addr(p,w));
                if(pm(candidate)&&candidate.getFlowOverride()==FlowOverride.CALL_RETURN&&
                   candidate.toString().trim().matches("(?i)^CALL\\s+0x[0-9a-f]+$")) {
                    if(call!=null){call=null;break;}
                    call=candidate;
                }
            }
            if(call==null||call.getFlows().length!=1||
               op(call,PcodeOp.CALL)!=1||
               !owner.getBody().contains(call.getAddress()))continue;
            Function provider=fm.getFunctionAt(call.getFlows()[0]);
            // A source-native RTS may be reached through a verified shared
            // suffix owned by a different function. The ordinary bounded
            // callee scanner cannot prove that shape, but the architecture's
            // existing shared-PC-stack reachability contract can. Both
            // inspect original native PM instructions; neither infers
            // execution on silicon or fabricates a cross-function CALL.
            if(provider==null||provider.isExternal())continue;
            boolean localReturn=SunplusNativeReturningCallCeRecovery
                .sourceReachableNativeRts(provider,listing,monitor);
            boolean sharedReturn=localReturn||
                SunplusNativeCeAutoAnalyzer.returnsViaSharedPcStack(
                    provider,listing,fm,new LinkedHashMap<>(),
                    new LinkedHashSet<>(),0,monitor);
            if(!sharedReturn)continue;
            int gapFirst=word(call.getAddress())+1;
            if(gapFirst>last)continue;
            boolean unowned=true;
            for(int w=gapFirst;w<=last;w++){
                Address here=addr(p,w);
                if(listing.getInstructionAt(here)!=null||
                   fm.getFunctionContaining(here)!=null||
                   listing.getDefinedDataAt(here)!=null){unowned=false;break;}
            }
            if(!unowned)continue;
            roots.add(new Root(inst,call,owner,provider,first,last));
            if(roots.size()>64)return List.of();
        }
        return roots;
    }
    // Source-native DO/CE with one nested counted frame. Unlike the flat
    // C view, both CNTR loads and both DO constructors must be re-decoded:
    // the inner CNTR load saves the outer count, its CE restores that count,
    // and the outer CE must not restore it from the wrong shadow register.
    // Treat the six original instruction words as one architecture unit.
    private static int recoverTwoFrameCountedLoops(Program p,
            Map<Integer,Instruction> originalDoByEnd,Set<Integer> deferredEnds,
            Function owner,Listing listing,FunctionManager fm,
            TaskMonitor monitor)throws Exception {
        Register mode=p.getRegister("codec_ce_nested_mode");
        Register depth=p.getRegister("codec_ce_static_depth");
        Register count14=p.getRegister("codec_ce_counter14");
        Register ce=p.getRegister("codec_ce_loop_end");
        Register direct=p.getRegister("codec_ce_direct_backedge");
        Register back=p.getRegister("codec_ce_direct_start");
        if(mode==null||depth==null||count14==null||
           ce==null||direct==null||back==null)
            throw new IllegalStateException("UNSUPPORTED nested source SLEIGH context");
        int completed=0,groups=0;
        for(int outerEnd:deferredEnds) {
            monitor.checkCancelled();
            Instruction parent=originalDoByEnd.get(outerEnd);
            if(!pm(parent)||!exactDo(parent,outerEnd))continue;
            int outerFirst=word(parent.getAddress());
            if(outerEnd<=outerFirst||outerEnd-outerFirst>64)continue;
            Instruction outerCe=listing.getInstructionAt(addr(p,outerEnd));
            if(!pm(outerCe)||op(outerCe,PcodeOp.CBRANCH)<1||
               op(outerCe,PcodeOp.BRANCHIND)!=1||
               op(outerCe,PcodeOp.BRANCH)!=0)continue;
            Instruction outerWriter=listing.getInstructionAt(addr(p,outerFirst-1));
            if(!sourceCounterLoad(outerWriter))continue;
            Instruction child=null;
            int childEnd=-1,innerFirst=-1;
            boolean invalid=false;
            for(int w=outerFirst+1;w<outerEnd;w++) {
                Instruction ins=listing.getInstructionAt(addr(p,w));
                if(!pm(ins)){invalid=true;break;}
                Function assigned=fm.getFunctionContaining(ins.getAddress());
                if(assigned!=null&&assigned!=owner){invalid=true;break;}
                Matcher parsed=DO.matcher(ins.toString().trim());
                if(parsed.matches()) {
                    if(child!=null){invalid=true;break;}
                    child=ins;innerFirst=w;
                    childEnd=Integer.parseInt(parsed.group(1),16);
                    if(!exactDo(child,childEnd)||childEnd<=innerFirst||
                       childEnd>=outerEnd){invalid=true;break;}
                }
            }
            if(invalid||child==null)continue;
            Instruction innerWriter=listing.getInstructionAt(addr(p,innerFirst-1));
            Instruction innerCe=listing.getInstructionAt(addr(p,childEnd));
            if(!sourceCounterLoad(innerWriter)||!pm(innerCe)||
               op(innerCe,PcodeOp.CBRANCH)<1||
               op(innerCe,PcodeOp.BRANCHIND)!=0||
               !directTo(innerCe,addr(p,innerFirst+1)))continue;
            for(int w=outerFirst+1;w<outerEnd;w++) {
                monitor.checkCancelled();
                Instruction ins=listing.getInstructionAt(addr(p,w));
                if(ins==null){invalid=true;break;}
                if(w==innerFirst||w==innerFirst-1||w==childEnd)continue;
                if(ins.toString().trim().startsWith("DO ")||
                   ins.getFlowType().isComputed()||
                   ins.getFlowType().isTerminal()||
                   ins.getFlowType().isJump()||
                   sourceCounterLoad(ins)){
                    invalid=true;break;
                }
                if(ins.getFlowType().isCall()&&
                   !returningCallInCountedFrame(ins,p,listing,fm,monitor)){
                    invalid=true;break;
                }
            }
            if(invalid)continue;
            if(++groups>MAX_TWO_FRAME_GROUPS)
                throw new IllegalStateException(
                    "UNSUPPORTED bounded native two-frame group count");
            Address[] sites={
                outerWriter.getAddress(),parent.getAddress(),innerWriter.getAddress(),
                child.getAddress(),addr(p,childEnd),addr(p,outerEnd)};
            for(int j=0;j<sites.length;j++) {
                monitor.checkCancelled();
                Address at=sites[j];
                int level=(j==0||j==1||j==5)?1:2;
                Instruction current=listing.getInstructionAt(at);
                if(!pm(current))
                    throw new IllegalStateException("Lost counted native word "+at);
                byte[] bytes=current.getBytes();
                String mnemonic=current.toString().trim();
                listing.clearCodeUnits(at,at.add(2),false);
                p.getProgramContext().setValue(mode,at,at,BigInteger.ONE);
                p.getProgramContext().setValue(depth,at,at,BigInteger.valueOf(level));
                p.getProgramContext().setValue(count14,at,at,BigInteger.ONE);
                if(j==4||j==5) {
                    p.getProgramContext().setValue(ce,at,at,BigInteger.ONE);
                    p.getProgramContext().setValue(direct,at,at,BigInteger.ONE);
                    p.getProgramContext().setValue(back,at,at,
                        BigInteger.valueOf((j==4?innerFirst:outerFirst)+1));
                }
                DisassembleCommand recode=new DisassembleCommand(
                    new AddressSet(at,at.add(2)),null,true);
                recode.enableCodeAnalysis(false);
                if(!recode.applyTo(p,monitor))
                    throw new IllegalStateException(
                        "Native two-frame instruction decode failed "+at);
                Instruction restored=listing.getInstructionAt(at);
                if(!pm(restored)||!Arrays.equals(bytes,restored.getBytes())||
                   !mnemonic.equals(restored.toString().trim()))
                    throw new IllegalStateException(
                        "Original native two-frame instruction mutated "+at);
                if(j==4||j==5) {
                    if(op(restored,PcodeOp.CBRANCH)<1||
                       op(restored,PcodeOp.BRANCHIND)!=0||
                       !directTo(restored,
                          addr(p,(j==4?innerFirst:outerFirst)+1)))
                        throw new IllegalStateException(
                            "Native hardware two-frame CE edge absent "+at);
                }
            }
            completed+=2;
        }
        return completed;
    }

    // A complete source-native DO/CE/RTS sequence can be decoded but remain
    // without a Ghidra function owner. Its absence from the function catalog
    // is not an ISA property. Recover its exact machine backedge without
    // creating an invented function, CALL/XREF or C substitute.
    private record UnownedCountedFrame(Instruction begin,int first,int last,
                                      byte[] sourceBegin,byte[] sourceEnd) {}
    private static boolean recoverUnownedCountedFrames(Program p,
            TaskMonitor monitor,MessageLog log)throws Exception {
        Listing listing=p.getListing();FunctionManager fm=p.getFunctionManager();
        List<UnownedCountedFrame> candidates=new ArrayList<>();
        for(Instruction begin:listing.getInstructions(true)){
            monitor.checkCancelled();
            if(!pm(begin)||fm.getFunctionContaining(begin.getAddress())!=null)
                continue;
            Matcher parsed=DO.matcher(begin.toString().trim());
            if(!parsed.matches())continue;
            int first=word(begin.getAddress());
            int last=Integer.parseInt(parsed.group(1),16);
            if(last<=first||last-first>MAX_GAP_WORDS||
               !exactDo(begin,last))continue;
            Instruction writer=listing.getInstructionAt(addr(p,first-1));
            Instruction finish=listing.getInstructionAt(addr(p,last));
            Instruction returnIns=listing.getInstructionAt(addr(p,last+1));
            if(!sourceCounterLoad(writer)||!pm(finish)||!pm(returnIns)||
               !returnIns.toString().trim().equals("RTS")||
               op(returnIns,PcodeOp.RETURN)!=1||
               !finish.getFlowType().isFallthrough()||
               op(finish,PcodeOp.CBRANCH)!=0||
               op(finish,PcodeOp.BRANCHIND)!=0||
               op(finish,PcodeOp.BRANCH)!=0||
               op(finish,PcodeOp.CALL)!=0||
               fm.getFunctionContaining(finish.getAddress())!=null||
               fm.getFunctionContaining(returnIns.getAddress())!=null)
                continue;
            boolean valid=true;
            int returningCalls=0;
            for(int w=first+1;w<last;w++) {
                Instruction body=listing.getInstructionAt(addr(p,w));
                if(!pm(body)||fm.getFunctionContaining(body.getAddress())!=null||
                   body.toString().trim().startsWith("DO ")||
                   body.getFlowType().isTerminal()||
                   body.getFlowType().isJump()||
                   body.getFlowType().isComputed()||
                   sourceCounterLoad(body)) {
                    valid=false;break;
                }
                if(body.getFlowType().isCall()) {
                    if(!returningCallInCountedFrame(body,p,listing,fm,monitor)){
                        valid=false;break;
                    }
                    returningCalls++;
                }
                if(!addr(p,w+1).equals(body.getFallThrough())) {
                    valid=false;break;
                }
            }
            if(!valid||returningCalls!=1)continue;
            candidates.add(new UnownedCountedFrame(begin,first,last,
                begin.getBytes(),finish.getBytes()));
            if(candidates.size()>24)
                throw new IllegalStateException(
                   "UNSUPPORTED unowned native frame scan bound");
        }
        if(candidates.isEmpty())return true;
        Register ce=p.getRegister("codec_ce_loop_end");
        Register direct=p.getRegister("codec_ce_direct_backedge");
        Register start=p.getRegister("codec_ce_direct_start");
        Register width=p.getRegister("codec_ce_counter14");
        if(ce==null||direct==null||start==null||width==null)
            throw new IllegalStateException("No native counted-loop contexts");
        byte[] baselineHash=original(p);
        int sourceFunctions=fm.getFunctionCount();
        Map<Function,String> identity=new LinkedHashMap<>();
        Map<Function,String> priorC=new LinkedHashMap<>();
        DecompInterface generator=new DecompInterface();
        try {
            if(!generator.openProgram(p))
                throw new IllegalStateException("Native C generator unavailable");
            for(Function f:fm.getFunctions(true))if(!f.isExternal()){
                monitor.checkCancelled();
                identity.put(f,sourceIdentity(f));
                priorC.put(f,c(generator,f,monitor));
            }
        }finally{generator.dispose();}
        int accepted=0,rejected=0;
        for(UnownedCountedFrame frame:candidates) {
            monitor.checkCancelled();
            Address site=addr(p,frame.last());
            int tx=p.startTransaction("Native original-source unowned DO/CE semantics");
            boolean commit=false;
            String error=null;
            try {
                Instruction current=listing.getInstructionAt(site);
                if(!pm(current)||!Arrays.equals(current.getBytes(),frame.sourceEnd())||
                   !Arrays.equals(listing.getInstructionAt(frame.begin().getAddress())
                       .getBytes(),frame.sourceBegin()))
                    throw new IllegalStateException("Native frame identity changed");
                listing.clearCodeUnits(site,site.add(2),false);
                p.getProgramContext().setValue(ce,site,site,BigInteger.ONE);
                p.getProgramContext().setValue(direct,site,site,BigInteger.ONE);
                p.getProgramContext().setValue(start,site,site,
                    BigInteger.valueOf(frame.first()+1));
                p.getProgramContext().setValue(width,site,site,BigInteger.ONE);
                DisassembleCommand recode=new DisassembleCommand(
                    new AddressSet(site,site.add(2)),null,true);
                recode.enableCodeAnalysis(false);
                if(!recode.applyTo(p,monitor))
                    throw new IllegalStateException("Native unowned CE decode rejected");
                Instruction end=listing.getInstructionAt(site);
                if(!pm(end)||!Arrays.equals(end.getBytes(),frame.sourceEnd())||
                   op(end,PcodeOp.CBRANCH)<1||
                   op(end,PcodeOp.BRANCHIND)!=0||
                   !directTo(end,addr(p,frame.first()+1)))
                    throw new IllegalStateException("Native DO/CE backedge missing");
                if(fm.getFunctionCount()!=sourceFunctions||
                   !Arrays.equals(original(p),baselineHash))
                    throw new IllegalStateException("Source program changed");
                for(var row:identity.entrySet())
                    if(!row.getValue().equals(sourceIdentity(row.getKey())))
                        throw new IllegalStateException(
                            "Original native function identity changed");
                DecompInterface afterC=new DecompInterface();
                try {
                    if(!afterC.openProgram(p))
                        throw new IllegalStateException("Native C generator closed");
                    for(var row:priorC.entrySet()) {
                        monitor.checkCancelled();
                        String output=c(afterC,row.getKey(),monitor);
                        if(warnings(output)>warnings(row.getValue())||
                           loops(output)<loops(row.getValue()))
                            throw new IllegalStateException(
                                "Native unowned CE changed unrelated C");
                    }
                }finally{afterC.dispose();}
                commit=true;
            }catch(CancelledException cancelled){throw cancelled;}
            catch(Exception failed){error=failed.toString();}
            finally{p.endTransaction(tx,commit);}
            if(commit) {
                accepted++;
                log.appendMsg("Sunplus source-only unowned CE",
                    "CONFIRMED_STATIC source="+frame.begin().getAddress()+
                    " end="+site+" original_backedge="+addr(p,frame.first()+1)+
                    " original_bytes_preserved=true C_nonregression=true");
            }else {
                rejected++;
                if(!Arrays.equals(original(p),baselineHash)||
                   fm.getFunctionCount()!=sourceFunctions)
                    throw new IllegalStateException(
                        "Source native unowned CE rollback failed");
                log.appendMsg("Sunplus source-only unowned CE",
                    "UNSUPPORTED source="+frame.begin().getAddress()+
                    " original_source_preserved=true reason="+error);
            }
        }
        log.appendMsg("Sunplus source-only unowned CE",
            "source_proven="+accepted+" unsupported="+rejected);
        return true;
    }

    private static String sourceIdentity(Function f) {
        return f.getName()+"|"+f.getBody()+"|"+f.hasNoReturn()+"|"+
            f.isThunk()+"|"+f.getComment();
    }
    private static byte[] original(Program p)throws Exception {
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        byte[] chunk=new byte[8192];
        for(var block:p.getMemory().getBlocks())if(block.isInitialized()) {
            Address at=block.getStart();
            long remaining=block.getSize();
            while(remaining>0){
                int size=(int)Math.min(remaining,chunk.length);
                if(p.getMemory().getBytes(at,chunk,0,size)!=size)
                    throw new IllegalStateException("Short native source read");
                sha.update(chunk,0,size);
                at=at.add(size);remaining-=size;
            }
        }
        return sha.digest();
    }
    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,
            MessageLog log)throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
            p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return recover(p,monitor,log);}
        catch(CancelledException cancelled){throw cancelled;}
        catch(Exception failure) {
            log.appendMsg("Sunplus architecture CALL/loop closure",
                "UNSUPPORTED "+failure+" cleanAfterRollback="+!p.isChanged());
            return false;
        }
    }
    private static boolean recover(Program p,TaskMonitor monitor,
            MessageLog log)throws Exception {
        List<Root> candidates=plan(p,monitor);
        if(candidates.isEmpty())
            return recoverUnownedCountedFrames(p,monitor,log);
        Register endCtx=p.getRegister("codec_ce_loop_end");
        Register direct=p.getRegister("codec_ce_direct_backedge");
        Register start=p.getRegister("codec_ce_direct_start");
        if(endCtx==null||direct==null||start==null)
            throw new IllegalStateException("No native CE SLEIGH contexts");
        Listing listing=p.getListing();
        FunctionManager fm=p.getFunctionManager();
        int savedFunctionCount=fm.getFunctionCount();
        byte[] sourceHash=original(p);
        int accepted=0,acceptedLoops=0,rejected=0;
        for(Root root:candidates) {
            monitor.checkCancelled();
            Function owner=root.owner();
            // Two roots in one owner are rescheduled on a later model pass,
            // after its newly confirmed native C state has been saved.
            if(owner.getBody().contains(addr(p,root.last())))continue;
            String before;
            DecompInterface originalC=new DecompInterface();
            try {
                if(!originalC.openProgram(p))
                    throw new IllegalStateException("Baseline C generator absent");
                before=c(originalC,owner,monitor);
            }finally{originalC.dispose();}
            String savedOwner=sourceIdentity(owner);
            Address callAt=root.call().getAddress();
            byte[] callBytes=root.call().getBytes();
            Address gap=addr(p,word(callAt)+1),end=addr(p,root.last());
            byte[] rawEnd=new byte[3];p.getMemory().getBytes(end,rawEnd);
            int tx=p.startTransaction(
                "Source-native returning CALL plus counted DO/CE closure "+owner.getEntryPoint());
            boolean commit=false;String failure=null;int changed=0;
            try {
                root.call().setFlowOverride(FlowOverride.NONE);
                if(!gap.equals(root.call().getFallThrough()))
                    throw new IllegalStateException("CALL source continuation missing");
                p.getProgramContext().setValue(endCtx,end,end,BigInteger.ONE);
                p.getProgramContext().setValue(direct,end,end,BigInteger.ONE);
                p.getProgramContext().setValue(start,end,end,
                    BigInteger.valueOf(root.first()+1));
                DisassembleCommand decode=new DisassembleCommand(
                    new AddressSet(gap,end.add(2)),null,true);
                decode.enableCodeAnalysis(false);
                if(!decode.applyTo(p,monitor))
                    throw new IllegalStateException("Native gap decoder refused");
                for(int w=word(gap);w<=root.last();w++) {
                    Instruction ins=listing.getInstructionAt(addr(p,w));
                    if(!pm(ins))
                        throw new IllegalStateException("Missing native successor at "+addr(p,w));
                }
                Instruction exactEnd=listing.getInstructionAt(end);
                if(!Arrays.equals(exactEnd.getBytes(),rawEnd)||
                   op(exactEnd,PcodeOp.CBRANCH)<1||op(exactEnd,PcodeOp.BRANCHIND)!=0||
                   !directTo(exactEnd,addr(p,root.first()+1)))
                    throw new IllegalStateException("Native root CE machine edge missing");
                AddressSet body=new AddressSet(owner.getBody());
                body.add(gap,end.add(2));owner.setBody(body);
                DecompInterface stage=new DecompInterface();
                String expanded;
                try {
                    if(!stage.openProgram(p))
                        throw new IllegalStateException("Expanded C unavailable");
                    expanded=c(stage,owner,monitor);
                }finally{stage.dispose();}
                // Warning owners are authoritative *affected-flow evidence*:
                // a newly exposed counted CE with an exact original DO is
                // a hardware frame, never a speculative jump table.
                Set<Integer> warningSites=new LinkedHashSet<>();
                Matcher warnings=BAD_EDGE.matcher(expanded);
                while(warnings.find())
                    warningSites.add(Integer.parseInt(warnings.group(1),16));
                Map<Integer,Instruction> machineDoByEnd=new LinkedHashMap<>();
                for(Instruction inst:listing.getInstructions(true)) {
                    monitor.checkCancelled();
                    if(!pm(inst))continue;
                    Matcher nativeDo=DO.matcher(inst.toString().trim());
                    if(!nativeDo.matches())continue;
                    int endWord=Integer.parseInt(nativeDo.group(1),16);
                    if(endWord<=word(inst.getAddress())||
                       endWord-word(inst.getAddress())>64||
                       !exactDo(inst,endWord))continue;
                    if(endWord<word(gap)||endWord>word(gap)+MAX_CLOSURE_WORDS)
                        continue;
                    if(machineDoByEnd.putIfAbsent(endWord,inst)!=null)
                        throw new IllegalStateException("Ambiguous source DO/CE frame "+endWord);
                }
                Set<Integer> deferredNestedFrames=new LinkedHashSet<>();
                for(int ceWord:warningSites) {
                    Instruction nativeDo=machineDoByEnd.get(ceWord);
                    Instruction ce=listing.getInstructionAt(addr(p,ceWord));
                    if(nativeDo==null||!pm(ce)||
                       op(ce,PcodeOp.CBRANCH)<1||
                       op(ce,PcodeOp.BRANCHIND)!=1||
                       op(ce,PcodeOp.BRANCH)!=0||op(ce,PcodeOp.CALL)!=0||
                       op(ce,PcodeOp.RETURN)!=0)continue;
                    int beginWord=word(nativeDo.getAddress());
                    boolean safe=true;
                    for(int w=beginWord+1;w<ceWord;w++) {
                        Instruction inner=listing.getInstructionAt(addr(p,w));
                        if(!pm(inner)||inner.toString().trim().startsWith("DO ")||
                           inner.getFlowType().isComputed()||
                           inner.getFlowType().isTerminal()){safe=false;break;}
                        if(inner.getFlowType().isCall()&&
                           !returningCallInCountedFrame(inner,p,listing,fm,monitor)) {
                            safe=false;break;
                        }
                    }
                    if(!safe) {
                        // A nested DO owns an independent hardware CNTR/PC
                        // frame; defer the whole source pair rather than
                        // pretending its parent is an ordinary flat loop.
                        deferredNestedFrames.add(ceWord);
                        continue;
                    }
                    Address ceAt=addr(p,ceWord);
                    byte[] sourceBytes=ce.getBytes();
                    listing.clearCodeUnits(ceAt,ceAt.add(2),false);
                    p.getProgramContext().setValue(endCtx,ceAt,ceAt,BigInteger.ONE);
                    p.getProgramContext().setValue(direct,ceAt,ceAt,BigInteger.ONE);
                    p.getProgramContext().setValue(start,ceAt,ceAt,
                        BigInteger.valueOf(beginWord+1));
                    DisassembleCommand recode=new DisassembleCommand(
                        new AddressSet(ceAt,ceAt.add(2)),null,true);
                    recode.enableCodeAnalysis(false);
                    if(!recode.applyTo(p,monitor))
                        throw new IllegalStateException("Nested CALL/CE decoder rejected "+ceAt);
                    Instruction fixed=listing.getInstructionAt(ceAt);
                    if(!pm(fixed)||!Arrays.equals(fixed.getBytes(),sourceBytes)||
                       op(fixed,PcodeOp.CBRANCH)<1||op(fixed,PcodeOp.BRANCHIND)!=0||
                       !directTo(fixed,addr(p,beginWord+1)))
                        throw new IllegalStateException("Native source CE edge mismatch "+ceAt);
                    changed++;
                    if(changed>MAX_PROVEN_LOOPS)
                        throw new IllegalStateException("Unbounded dynamic counted-frame closure");
                }
                int completedTwoFrameCE=recoverTwoFrameCountedLoops(p,
                    machineDoByEnd,deferredNestedFrames,owner,listing,fm,monitor);
                changed+=completedTwoFrameCE;
                if(changed>MAX_PROVEN_LOOPS)
                    throw new IllegalStateException("Too many native source CE frames");
                if(!Arrays.equals(sourceHash,original(p))||
                   fm.getFunctionCount()!=savedFunctionCount||
                   !Arrays.equals(root.call().getBytes(),callBytes))
                    throw new IllegalStateException("Native source/function identity drift");
                for(Function f:fm.getFunctions(true)) {
                    if(f==owner)continue;
                    if(f.getBody().contains(gap))
                        throw new IllegalStateException("Source owner collision");
                }
                DecompInterface check=new DecompInterface();
                try {
                    if(!check.openProgram(p))
                        throw new IllegalStateException("Updated C unavailable");
                    String finalC=c(check,owner,monitor);
                    if(warnings(finalC)>warnings(before)||
                       loops(finalC)<loops(before))
                        throw new IllegalStateException(
                            "UNSUPPORTED native CALL/CE closure C nonregression "+
                            owner.getEntryPoint());
                }finally{check.dispose();}
                commit=true;
            }catch(CancelledException cancelled){throw cancelled;}
            catch(Exception error){failure=error.toString();}
            finally{p.endTransaction(tx,commit);}
            if(commit) {
                accepted++;acceptedLoops+=changed+1;
                log.appendMsg("Sunplus native CALL/loop closure",
                    "CONFIRMED_STATIC owner="+owner.getEntryPoint()+
                    " encoded_CE_recovered="+(changed+1)+
                    " C_nonregression=true source_bytes_preserved=true");
            }else {
                rejected++;
                if(!savedOwner.equals(sourceIdentity(owner))||
                   fm.getFunctionCount()!=savedFunctionCount||
                   !Arrays.equals(sourceHash,original(p)))
                    throw new IllegalStateException("UNSUPPORTED source CALL/CE rollback leak");
                log.appendMsg("Sunplus native CALL/loop closure",
                    "UNSUPPORTED owner="+owner.getEntryPoint()+" reason="+failure);
            }
        }
        if(accepted+rejected>0)
            log.appendMsg("Sunplus native CALL/loop closure",
                "CONFIRMED_STATIC transactions="+accepted+
                " source_proven_CE="+acceptedLoops+
                " UNSUPPORTED_transactions="+rejected);
        return recoverUnownedCountedFrames(p,monitor,log);
    }
    private static boolean directTo(Instruction i,Address expected) {
        for(PcodeOp p:i.getPcode())
            if(p.getOpcode()==PcodeOp.BRANCH &&
               p.getInput(0).getAddress().equals(expected))return true;
        return false;
    }
}
