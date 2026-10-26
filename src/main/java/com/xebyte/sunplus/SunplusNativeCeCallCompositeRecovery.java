package com.xebyte.sunplus;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

/**
 * Program-linked, source-proven composite native CALL/CE behavior contracts.
 *
 * Ghidra FlowType has no representable value for a single instruction with
 * both a native CALL and a hardware counted-loop backedge. The ISA explicitly
 * emits CALL, CNTR decrement, CBRANCH and BRANCH in sequence, so Ghidra labels
 * the compound FlowType INVALID even when its two real flow references and C
 * are correct. Never force FlowOverride.CALL or BRANCH: both are incomplete.
 *
 * Classify this architecture-only composite as CONFIRMED_STATIC in the saved
 * Analyzer program; preserve the actual FlowType and *both* native flow edges.
 * Runtime stack timing and silicon behavior remain UNKNOWN.
 */
public final class SunplusNativeCeCallCompositeRecovery {
    public static final String OPTIONS_NAME="Sunplus DSP Native Composite CE CALL";
    private static final int MAX_NATIVE_COMPOSITES=128;
    private static final int MAX_PROOF_BACK_DISTANCE=1024;
    private SunplusNativeCeCallCompositeRecovery() {}

    private record Contract(Address instruction,Address callerEntry,Address callee,
                            Address countedBackedge,Address doInstruction,
                            String originalBytes) {
        String serialize(){
            return "CONFIRMED_STATIC|CALL="+callee+"|DO="+doInstruction+
                "|CE_BACKEDGE="+countedBackedge+"|CALLER="+callerEntry+
                "|NATIVE_BYTES="+originalBytes+
                "|RUNTIME_STACK=UNKNOWN|GHIDRA_FLOWTYPE=INVALID_COMPOSITE";
        }
    }
    private static int count(Instruction i,int op) {
        int n=0;for(PcodeOp x:i.getPcode())if(x.getOpcode()==op)n++;return n;
    }
    private static boolean nativeInstruction(Instruction i){
        return i!=null && i.getLength()==3 &&
            "PM".equals(i.getAddress().getAddressSpace().getName());
    }
    private static Contract sourceProvesComposite(Program p,Instruction at) throws Exception {
        if(!nativeInstruction(at)||!"INVALID".equals(at.getFlowType().toString())||
           !at.toString().trim().startsWith("CALL ")||
           !"NONE".equals(at.getFlowOverride().name())||
           at.getFlows().length!=2||count(at,PcodeOp.CALL)!=1||
           count(at,PcodeOp.CBRANCH)!=1||count(at,PcodeOp.BRANCH)!=1)
            return null;
        Address call=null,back=null;
        for(PcodeOp op:at.getPcode()){
            if(op.getOpcode()==PcodeOp.CALL)call=op.getInput(0).getAddress();
            if(op.getOpcode()==PcodeOp.BRANCH)back=op.getInput(0).getAddress();
        }
        if(call==null||back==null||call.equals(back)||
           !"PM".equals(call.getAddressSpace().getName())||
           !"PM".equals(back.getAddressSpace().getName())||
           !Arrays.asList(at.getFlows()).containsAll(java.util.List.of(call,back)))return null;
        Address current=at.getAddress();
        if(back.compareTo(current)>=0||back.getAddressableWordOffset()<1||
           current.getAddressableWordOffset()-back.getAddressableWordOffset()>MAX_PROOF_BACK_DISTANCE)
            return null;
        Function caller=p.getFunctionManager().getFunctionContaining(current);
        Function callee=p.getFunctionManager().getFunctionAt(call);
        if(caller==null||callee==null||callee.isExternal()||
           !caller.getBody().contains(back))return null;
        Address precedingDO=back.subtract(3);
        Instruction setup=p.getListing().getInstructionAt(precedingDO);
        if(!nativeInstruction(setup)||!caller.getBody().contains(precedingDO)||
           !setup.toString().trim().matches("(?i)^DO\\s+0x"+
                String.format("%04x",current.getAddressableWordOffset())+"\\s+UNTIL CE$") )
            return null;
        var register=p.getRegister("codec_ce_loop_end");
        var direct=p.getRegister("codec_ce_direct_backedge");
        if(register==null||direct==null||
           !java.math.BigInteger.ONE.equals(p.getProgramContext().getValue(register,current,false))||
           !java.math.BigInteger.ONE.equals(p.getProgramContext().getValue(direct,current,false)))return null;
        // P-code order is architectural: original CALL occurs before loop
        // counter update and CE backedge; no synthetic continuation may be
        // confused with a second machine CALL instruction.
        int callOp=-1,subOp=-1,backOp=-1,position=0;
        for(PcodeOp op:at.getPcode()){
            if(op.getOpcode()==PcodeOp.CALL)callOp=position;
            if(op.getOpcode()==PcodeOp.INT_SUB && subOp<0)subOp=position;
            if(op.getOpcode()==PcodeOp.BRANCH)backOp=position;
            position++;
        }
        if(callOp!=0||subOp<=callOp||backOp<=subOp)return null;
        return new Contract(current,caller.getEntryPoint(),call,back,precedingDO,
            HexFormat.of().formatHex(at.getBytes()));
    }

    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,
                                                   MessageLog log) throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
             p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return run(p,monitor,log);}
        catch(CancelledException cancelled){throw cancelled;}
        catch(Exception issue){log.appendMsg("Sunplus native composite CE/CALL",issue.toString());return false;}
    }
    private static boolean run(Program p,TaskMonitor monitor,MessageLog log) throws Exception {
        Map<Address,Contract> proven=new TreeMap<>();int invalid=0;
        for(Instruction i:p.getListing().getInstructions(true)){
            monitor.checkCancelled();
            if(!nativeInstruction(i)||!"INVALID".equals(i.getFlowType().toString()))continue;
            invalid++;
            Contract proof=sourceProvesComposite(p,i);
            if(proof!=null)proven.put(i.getAddress(),proof);
        }
        if(proven.size()>MAX_NATIVE_COMPOSITES)
            throw new IllegalStateException("Composite native flow proof overflow");
        if(invalid==0)return true;
        if(proven.isEmpty()){
            log.appendMsg("Sunplus native composite CE/CALL",
                "unresolved_invalid_native_flow="+invalid+" provenance UNKNOWN");
            return true;
        }
        Options options=p.getOptions(OPTIONS_NAME);
        int tx=p.startTransaction("Source-native composite CE and CALL behavior contracts");
        boolean accepted=false;
        try{
            for(var entry:proven.entrySet()){
                Address at=entry.getKey();Contract proof=entry.getValue();
                // No changes to P-code, original CALL/reference, function
                // body, or instruction-level FlowType. Only project-linked
                // semantic evidence is stored for consumers of the model.
                Instruction current=p.getListing().getInstructionAt(at);
                if(sourceProvesComposite(p,current)==null)
                    throw new IllegalStateException("Composite native source changed "+at);
                String key=at.toString();String raw=proof.serialize();
                if(!raw.equals(options.getString(key,"")))options.setString(key,raw);
            }
            options.setInt("verified_composite_ce_call_count",proven.size());
            options.setInt("unresolved_invalid_native_flow_count",invalid-proven.size());
            options.setString("scope","ORIGINAL_NATIVE_STATIC_PCODE:CALL_THEN_CE_BRANCH; HARDWARE_UNKNOWN");
            accepted=true;
        }finally{p.endTransaction(tx,accepted);}
        log.appendMsg("Sunplus native composite CE/CALL",
            "CONFIRMED_STATIC="+proven.size()+" unresolved_invalid_native_flow="+
            (invalid-proven.size())+" native_CALL_and_CE_edges_preserved=true");
        return true;
    }
}
