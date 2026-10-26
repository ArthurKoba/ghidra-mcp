package com.xebyte.sunplus;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-proven SE-negative ASHIFT/C+DM specialization, shared by all codec
 * modules. A signed-negative literal in an unbranched single DO is a native
 * data-flow fact, not a firmware-specific special case. By eliminating a
 * redundant dynamic-SE branch from each parallel shift, the C generator can
 * preserve the native instructions without dropping live blocks. This pass
 * affects analysis-only per-instruction context, never program bytes or an
 * architectural SE register. No hardware timing equivalence is asserted.
 */
public final class SunplusNativeSeSignAutoRecovery {
    private static final Pattern DO = Pattern.compile("^DO\\s+0x([0-9a-f]+)\\s+UNTIL CE$",Pattern.CASE_INSENSITIVE);
    private static final Pattern LOAD = Pattern.compile("^LDI SE,0x([0-9a-f]+)$",Pattern.CASE_INSENSITIVE);
    private static final int MAX_LOOP_WORDS=96;
    private static final int MAX_WRITER_DISTANCE=16;
    private static final int MAX_CHANGED_OWNERS=24;

    private record NativeShift(Address at,String sourceText,byte[] bytes,Function owner,boolean negative) {}
    private SunplusNativeSeSignAutoRecovery() {}

    private static Address pm(Program p,long word) {
        return p.getAddressFactory().getAddress(String.format("PM:%04x",word));
    }
    private static boolean nativeInsn(Instruction i) {
        return i!=null&&i.getLength()==3&&"PM".equals(i.getAddress().getAddressSpace().getName());
    }
    private static int operations(Instruction i,int opcode) {
        int n=0;for(PcodeOp p:i.getPcode())if(p.getOpcode()==opcode)n++;return n;
    }
    private static boolean outputsSe(Instruction i,Address se) {
        for(PcodeOp op:i.getPcode())
            if(op.getOutput()!=null&&op.getOutput().isRegister()&&
               op.getOutput().getAddress().equals(se))return true;
        return false;
    }
    private static byte[] sourceImage(Program p,TaskMonitor monitor)throws Exception {
        MessageDigest hash=MessageDigest.getInstance("SHA-256");byte[] buf=new byte[8192];
        for(MemoryBlock b:p.getMemory().getBlocks())if(b.isInitialized()) {
            Address at=b.getStart();long left=b.getSize();
            while(left>0) {
                monitor.checkCancelled();int n=(int)Math.min(left,buf.length);
                if(p.getMemory().getBytes(at,buf,0,n)!=n)throw new IllegalStateException("Incomplete source memory");
                hash.update(buf,0,n);at=at.add(n);left-=n;
            }
        }
        return hash.digest();
    }
    private static String c(DecompInterface dc,Function f,TaskMonitor monitor)throws Exception {
        DecompileResults dr=dc.decompileFunction(f,38,monitor);
        if(!dr.decompileCompleted()||dr.getDecompiledFunction()==null)
            throw new IllegalStateException("Original native C unavailable "+f.getEntryPoint());
        String src=dr.getDecompiledFunction().getC();
        if(src.isBlank()||src.contains("halt_baddata"))throw new IllegalStateException("Unsupported native C "+f.getEntryPoint());
        return src;
    }
    private static int warnings(String text){return text.split("WARNING:",-1).length-1;}
    private static int loops(String text){return text.split("do \\{",-1).length-1;}

    private static Map<Function,List<NativeShift>> plan(Program p,TaskMonitor monitor)
            throws CancelledException {
        Listing listing=p.getListing();var fm=p.getFunctionManager();
        Register se=p.getRegister("SE");
        if(se==null)return Map.of();
        Map<Function,List<NativeShift>> candidates=new LinkedHashMap<>();
        for(Instruction begin:listing.getInstructions(true)) {
            monitor.checkCancelled();if(!nativeInsn(begin))continue;
            Matcher m=DO.matcher(begin.toString().trim());if(!m.matches())continue;
            long first=begin.getAddress().getAddressableWordOffset();
            long last=Long.parseLong(m.group(1),16);
            if(last<=first||last-first>MAX_LOOP_WORDS)continue;
            Function owner=fm.getFunctionContaining(begin.getAddress());
            if(owner==null||!owner.getBody().contains(pm(p,last)))continue;
            Instruction end=listing.getInstructionAt(pm(p,last));
            if(!nativeInsn(end)||!end.getFlowType().isConditional())continue;
            boolean nativeCe=false;
            for(Address back:end.getFlows())if(back.equals(pm(p,first+1)))nativeCe=true;
            if(!nativeCe)continue;
            Boolean signNegative=null;
            for(int distance=1;distance<=MAX_WRITER_DISTANCE;distance++) {
                long w=first-distance;if(w<0)break;
                Instruction writer=listing.getInstructionAt(pm(p,w));
                if(!nativeInsn(writer)||fm.getFunctionContaining(writer.getAddress())!=owner||
                   writer.getFlowType().isJump()||writer.getFlowType().isCall()||
                   writer.getFlowType().isTerminal())break;
                Matcher source=LOAD.matcher(writer.toString().trim());
                if(source.matches()){
                    int raw=Integer.parseInt(source.group(1),16);
                    if(raw<=0xffff)signNegative=raw>=0x8000;
                    break;
                }
                if(outputsSe(writer,se.getAddress()))break;
            }
            if(signNegative==null)continue;
            List<NativeShift> local=new ArrayList<>();boolean sound=true;
            for(long w=first+1;w<last;w++) {
                Instruction ins=listing.getInstructionAt(pm(p,w));
                if(!nativeInsn(ins)||fm.getFunctionContaining(ins.getAddress())!=owner||
                   ins.getFlowType().isCall()||ins.getFlowType().isJump()||
                   ins.getFlowType().isTerminal()||
                   ins.toString().trim().startsWith("DO ")){sound=false;break;}
                if(outputsSe(ins,se.getAddress())){sound=false;break;}
                String text=ins.toString().trim();
                // Signed-negative parallel DM/ASHIFT constructors, plus
                // nonnegative standalone ASHIFT HI or OR-LSHIFT LO where
                // the source ISA has a proven branch-free constructor.
                boolean shiftSpecializable=signNegative ?
                    text.startsWith("SR = ASHIFT ")&&text.contains(",")&&
                        !text.contains(" BY ") :
                    !text.contains(" BY ")&&(
                        (text.startsWith("SR = ASHIFT ")&&text.contains("(HI)"))||
                        (text.startsWith("SR = LSHIFT ")&&text.contains(",")&&
                            (text.contains("DM(")||text.contains("PM(")))||
                        (text.startsWith("SR = SR OR LSHIFT ")&&
                            (text.endsWith("(LO)")||
                             (text.contains(",")&&text.contains("(LO)"))||
                             (text.contains(",")&&text.contains("(HI)")&&text.contains("DM(")))));
                if(shiftSpecializable&&operations(ins,PcodeOp.CBRANCH)==1&&
                   (!signNegative||operations(ins,PcodeOp.INT_SRIGHT)>=1)) {
                    try{local.add(new NativeShift(ins.getAddress(),text,
                        ins.getBytes(),owner,signNegative));}
                    catch(Exception e){sound=false;break;}
                }
            }
            if(!sound)continue;
            // First preserve the originally accepted intra-DO sign proof.
            // An ambiguous fallthrough region must NEVER invalidate the
            // already proven source-native loop-body specialization.
            for(Instruction other:listing.getInstructions(true)) {
                monitor.checkCancelled();if(!nativeInsn(other))continue;
                long from=other.getAddress().getAddressableWordOffset();
                if(from>=first&&from<=last)continue;
                for(Address target:other.getFlows()) {
                    if(!"PM".equals(target.getAddressSpace().getName()))continue;
                    long destination=target.getAddressableWordOffset();
                    if(destination>first&&destination<=last)sound=false;
                }
                if(!sound)break;
            }
            if(!sound)continue;

            // Following a full source-native CE, an unbranched short tail
            // inherits the proved SE literal if no instruction (including
            // the CE endpoint) can write it and no outside jump bypasses the
            // dominating writer. Reject only the optional tail on conflict.
            if(!signNegative&&!outputsSe(end,se.getAddress())) {
                List<NativeShift> tail=new ArrayList<>();
                long tailEnd=last;
                for(long w=last+1;w<=last+12;w++) {
                    Instruction ins=listing.getInstructionAt(pm(p,w));
                    if(!nativeInsn(ins)||
                       fm.getFunctionContaining(ins.getAddress())!=owner||
                       ins.getFlowType().isCall()||ins.getFlowType().isJump()||
                       ins.getFlowType().isTerminal()||
                       ins.toString().trim().startsWith("DO ")||
                       outputsSe(ins,se.getAddress()))break;
                    tailEnd=w;
                    String text=ins.toString().trim();
                    boolean sourceParallel=(text.startsWith("SR = LSHIFT ")||
                        text.startsWith("SR = ASHIFT ")||
                        text.startsWith("SR = SR OR LSHIFT "))&&
                        text.contains(",")&&!text.contains(" BY ")&&
                        (text.contains("DM(")||text.contains("PM("));
                    if(sourceParallel&&operations(ins,PcodeOp.CBRANCH)==1) {
                        try {tail.add(new NativeShift(ins.getAddress(),text,
                            ins.getBytes(),owner,false));}
                        catch(Exception badSource){tail.clear();break;}
                    }
                }
                if(!tail.isEmpty()) {
                    boolean tailHasExternalEntry=false;
                    for(Instruction other:listing.getInstructions(true)) {
                        monitor.checkCancelled();if(!nativeInsn(other))continue;
                        long from=other.getAddress().getAddressableWordOffset();
                        if(from>=first&&from<=tailEnd)continue;
                        for(Address branch:other.getFlows()) {
                            if(!"PM".equals(branch.getAddressSpace().getName()))continue;
                            long destination=branch.getAddressableWordOffset();
                            if(destination>last&&destination<=tailEnd)
                                tailHasExternalEntry=true;
                        }
                        if(tailHasExternalEntry)break;
                    }
                    if(!tailHasExternalEntry)local.addAll(tail);
                }
            }
            if(local.isEmpty())continue;
            candidates.computeIfAbsent(owner,unused->new ArrayList<>()).addAll(local);
            if(candidates.size()>MAX_CHANGED_OWNERS)return Map.of();
        }
        return candidates;
    }
    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,MessageLog log)
            throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
                p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return run(p,monitor,log);}
        catch(CancelledException cancelled){throw cancelled;}
        catch(Exception error){
            log.appendMsg("Sunplus native SE sign",error.toString());return false;
        }
    }
    private static boolean run(Program p,TaskMonitor monitor,MessageLog log)throws Exception {
        Register negativeContext=p.getRegister("codec_se_proven_negative");
        Register nonnegativeContext=p.getRegister("codec_se_proven_nonnegative");
        if(negativeContext==null||nonnegativeContext==null)return true;
        Map<Function,List<NativeShift>> groups=plan(p,monitor);
        if(groups.isEmpty())return true;
        byte[] image=sourceImage(p,monitor);
        int beforeTotal=p.getFunctionManager().getFunctionCount();
        int changedOwners=0,changedShifts=0,reducedWarnings=0;
        Listing listing=p.getListing();
        DecompInterface baseline=new DecompInterface();
        if(!baseline.openProgram(p))throw new IllegalStateException("No original native C backend");
        Map<Function,String> old=new LinkedHashMap<>();
        try{
            for(Function f:groups.keySet())old.put(f,c(baseline,f,monitor));
        }finally{baseline.dispose();}
        for(var entry:groups.entrySet()) {
            monitor.checkCancelled();Function f=entry.getKey();String before=old.get(f);
            int priorWarnings=warnings(before);
            if(priorWarnings==0)continue;
            int tx=p.startTransaction("Source-proven signed DSP SE C flow recovery");
            boolean accepted=false;
            try {
                int changed=0;
                for(NativeShift evidence:entry.getValue()) {
                    Instruction ins=listing.getInstructionAt(evidence.at());
                    if(ins==null||!ins.toString().trim().equals(evidence.sourceText())||
                       !Arrays.equals(ins.getBytes(),evidence.bytes())||
                       p.getFunctionManager().getFunctionContaining(evidence.at())!=f)
                        throw new IllegalStateException("Source SE proof changed "+evidence.at());
                    Register context=evidence.negative()?negativeContext:nonnegativeContext;
                    Register otherContext=evidence.negative()?nonnegativeContext:negativeContext;
                    BigInteger other=p.getProgramContext().getValue(otherContext,evidence.at(),false);
                    if(BigInteger.ONE.equals(other))throw new IllegalStateException("Conflicting SE sign context "+evidence.at());
                    BigInteger prior=p.getProgramContext().getValue(context,evidence.at(),false);
                    if(BigInteger.ONE.equals(prior))continue;
                    if(prior!=null&&prior.signum()!=0)throw new IllegalStateException("Unknown SE context "+evidence.at());
                    int oldBranches=operations(ins,PcodeOp.CBRANCH);
                    int oldRight=operations(ins,PcodeOp.INT_SRIGHT);
                    listing.clearCodeUnits(evidence.at(),evidence.at().add(2),true);
                    p.getProgramContext().setValue(context,evidence.at(),evidence.at(),BigInteger.ONE);
                    DisassembleCommand decode=new DisassembleCommand(
                        new AddressSet(evidence.at(),evidence.at().add(2)),null,true);
                    decode.enableCodeAnalysis(false);
                    if(!decode.applyTo(p,monitor))throw new IllegalStateException("Native SE recode failed "+evidence.at());
                    Instruction updated=listing.getInstructionAt(evidence.at());
                    if(updated==null||!Arrays.equals(updated.getBytes(),evidence.bytes())||
                       !updated.toString().trim().equals(evidence.sourceText())||
                       operations(updated,PcodeOp.CBRANCH)!=oldBranches-1||
                       (evidence.negative()?operations(updated,PcodeOp.INT_SRIGHT)!=oldRight:
                            operations(updated,PcodeOp.INT_SRIGHT)>oldRight))
                        throw new IllegalStateException("Native signed shift P-code mismatch "+evidence.at());
                    changed++;
                }
                if(changed==0)continue;
                if(!Arrays.equals(image,sourceImage(p,monitor))||
                   p.getFunctionManager().getFunctionCount()!=beforeTotal)
                    throw new IllegalStateException("Source native image/function inventory changed");
                DecompInterface after=new DecompInterface();
                try {
                    if(!after.openProgram(p))throw new IllegalStateException("No modified C engine");
                    String result=c(after,f,monitor);
                    int reduced=priorWarnings-warnings(result);
                    accepted=reduced>0&&loops(result)>=loops(before);
                    if(accepted){changedOwners++;changedShifts+=changed;reducedWarnings+=reduced;}
                }finally{after.dispose();}
            }catch(Exception unsafe){
                log.appendMsg("Sunplus native SE sign", "Reject "+f.getEntryPoint()+": "+unsafe.getMessage());
            }finally{p.endTransaction(tx,accepted);}
        }
        log.appendMsg("Sunplus native SE sign", "Native proven-sign SE restored shiftSites="+
            changedShifts+" ownerFunctions="+changedOwners+" C_warnings_removed="+reducedWarnings+
            " original_source_unchanged=true hardware_effects_UNKNOWN");
        return true;
    }
}
