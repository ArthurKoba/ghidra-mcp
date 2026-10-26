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
import java.util.*;

/**
 * Link source-proven shared conditional branch continuations without
 * falsely attributing one native instruction to multiple functions.
 *
 * Native branches from distinct functions can enter the same unowned short
 * handler, which performs a DM read and directly branches to one existing
 * native consumer function. Ghidra function bodies cannot own the same PM
 * instructions twice. Retain exact incoming source machine edges, outgoing
 * tail-consumer and bytes, with UNCERTAIN runtime calling semantics.
 */
public final class SunplusNativeSharedContinuationRecovery {
    public static final String OPTIONS_NAME="Sunplus DSP Shared Native Continuations";
    private static final int MAX_SHARES=128;
    private static final int MAX_ISLAND=32;
    private SunplusNativeSharedContinuationRecovery(){}
    private record Shared(Address entry,Address ending,Address target,
        Set<Address> providers,Set<Address> branchSites,String hexSource) {
        String proof(){return "CONFIRMED_STATIC|ENTRY="+entry+"|END="+ending+
            "|TAIL_CONSUMER="+target+"|BRANCH_PROVIDER_FUNCTIONS="+providers+
            "|SOURCE_BRANCH_SITES="+branchSites+"|SOURCE_PM_HEX="+hexSource+
            "|OWNER=SHARED_UNASSIGNED|EXECUTION=UNKNOWN";}
    }
    private static boolean pm(Instruction i){return i!=null&&i.getLength()==3&&
        "PM".equals(i.getAddress().getAddressSpace().getName());}
    private static boolean directJump(Instruction i,Address to){
        if(!pm(i)||!i.toString().trim().matches("(?i)^(?:IF\\s+\\w+\\s+)?JUMP\\s+0x[0-9a-f]+$") ||
           i.getFlowType().isComputed()||i.getFlowType().isCall())return false;
        if(!Arrays.asList(i.getFlows()).contains(to))return false;
        for(PcodeOp code:i.getPcode())
            if(code.getOpcode()==PcodeOp.BRANCH||code.getOpcode()==PcodeOp.CBRANCH)
                return true;
        return false;
    }
    private static Map<Address,Shared> discover(Program p,TaskMonitor monitor)
            throws CancelledException {
        var listing=p.getListing();var fm=p.getFunctionManager();
        Map<Address,Shared> found=new LinkedHashMap<>();
        for(Instruction start:listing.getInstructions(true)){
            monitor.checkCancelled();if(!pm(start)||
                fm.getFunctionContaining(start.getAddress())!=null)continue;
            Address entry=start.getAddress();
            Set<Address> providers=new LinkedHashSet<>(),sites=new LinkedHashSet<>();
            for(Instruction source:listing.getInstructions(true)){
                monitor.checkCancelled();
                if(!pm(source)||!directJump(source,entry))continue;
                Function owner=fm.getFunctionContaining(source.getAddress());
                if(owner==null||owner.isExternal())continue;
                providers.add(owner.getEntryPoint());sites.add(source.getAddress());
            }
            if(providers.size()<2)continue;
            Address at=entry;Address last=null,consumer=null;
            StringBuilder sourceBytes=new StringBuilder();boolean valid=true;
            for(int i=0;i<MAX_ISLAND;i++){
                Instruction ins=listing.getInstructionAt(at);
                if(!pm(ins)||fm.getFunctionContaining(at)!=null){valid=false;break;}
                try{sourceBytes.append(HexFormat.of().formatHex(ins.getBytes()));}
                catch(ghidra.program.model.mem.MemoryAccessException e){valid=false;break;}
                last=at;
                if(ins.toString().trim().startsWith("JUMP ")&&
                    ins.getFlows().length==1&&ins.getFallThrough()==null){
                    consumer=ins.getFlows()[0];break;
                }
                if(ins.getFlowType().isJump()||ins.getFlowType().isCall()||
                   ins.getFlowType().isTerminal()||
                   ins.getFallThrough()==null||
                   !ins.getFallThrough().equals(at.add(3))){valid=false;break;}
                at=at.add(3);
            }
            if(!valid||consumer==null||last==null||
               fm.getFunctionContaining(consumer)==null||
               !"PM".equals(consumer.getAddressSpace().getName()))continue;
            // No flow from elsewhere is allowed into the middle of the island.
            for(Instruction ins:listing.getInstructions(true)){
                monitor.checkCancelled();if(!pm(ins)||
                    ins.getAddress().compareTo(entry)>=0&&
                    ins.getAddress().compareTo(last)<=0)continue;
                for(Address target:ins.getFlows()){
                    if(target.compareTo(entry)>0&&target.compareTo(last)<=0){
                        valid=false;break;
                    }
                }
                if(!valid)break;
            }
            if(valid){
                found.put(entry,new Shared(entry,last,consumer,providers,sites,
                    sourceBytes.toString()));
                if(found.size()>MAX_SHARES)return Map.of();
            }
        }
        return found;
    }
    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,
            MessageLog log)throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(
            p.getLanguageID().getIdAsString()))return true;
        if(p.isChanged())return false;
        try{return run(p,monitor,log);}
        catch(CancelledException e){throw e;}
        catch(Exception fail){log.appendMsg("Sunplus shared native continuation",fail.toString());return false;}
    }
    private static boolean run(Program p,TaskMonitor monitor,MessageLog log)
            throws Exception {
        var found=discover(p,monitor);if(found.isEmpty())return true;
        Options options=p.getOptions(OPTIONS_NAME);
        int tx=p.startTransaction("Source-native cross-function shared continuation contracts");
        boolean accepted=false;
        try{
            for(var item:found.entrySet()){
                if(!item.getValue().proof().equals(options.getString(item.getKey().toString(),"")))
                    options.setString(item.getKey().toString(),item.getValue().proof());
            }
            options.setInt("shared_continuation_count",found.size());
            options.setString("provenance","ORIGINAL_MACHINE_JUMP_INPUTS_AND_TAIL_CONSUMER_ONLY");
            accepted=true;
        }finally{p.endTransaction(tx,accepted);}
        int words=0;for(Shared c:found.values())
            words+=(int)((c.ending.getAddressableWordOffset()-c.entry.getAddressableWordOffset())+1);
        log.appendMsg("Sunplus shared native continuation",
            "CONFIRMED_STATIC shared_continuations="+found.size()+
            " shared_PM_words="+words+
            " machine_jump_edges_preserved=true; functions_unmodified=true");
        return true;
    }
}
