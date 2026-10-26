package com.xebyte.sunplus;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.listing.Data;
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
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-backed sparse DM16 layout normalizer for freshly imported modules.
 *
 * The original machine ISA has 16-bit addressed DM words.  Ghidra's
 * otherwise unmapped DM can emit overlapping _DAT_DM_xxx pseudo-symbols
 * after decompiler data-flow analysis. This pass only widens words actually
 * referenced in generated Analyzer C diagnostics, and only when original
 * machine Pcode proves 2-byte native DM LOAD/STORE semantics.
 *
 * Does not assert physical RAM/MMIO ownership, volatility, or protocol.
 * Refuses user-defined typed data, initialized hardware memory, or a
 * non-improving decompiler result. Caller owns no outer transaction.
 */
public final class SunplusNativeDmWordAutoNormalizer {
    // Analyzer sometimes drops the underscore prefix on a DM symbol while
    // emitting the same overlap warning for another alias of that cell.
    // Both spellings are source-backed in generated C; scope further to
    // native 16-bit DM ISA evidence and preserve typed/user-defined cells.
    private static final Pattern SYMBOL = Pattern.compile("\\b_?DAT_DM_([a-fA-F0-9]{1,4})\\b");
    private static final String WARNING =
        "Globals starting with '_' overlap smaller symbols at the same address";
    private static final int MAX_CELLS = 600;
    private static final int MAX_FUNCTIONS = 1000;

    private SunplusNativeDmWordAutoNormalizer() {}

    private static Address at(AddressSpace dm, int word) {
        return dm.getAddress((long) word * dm.getAddressableUnitSize());
    }

    private static byte[] initializedHash(Program p, TaskMonitor monitor) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[8192];
        for (MemoryBlock b : p.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            Address addr = b.getStart();long n = b.getSize();
            while (n > 0) {
                monitor.checkCancelled();int len = (int)Math.min(n,buf.length);
                if (p.getMemory().getBytes(addr,buf,0,len) != len)
                    throw new IllegalStateException("Native source bytes unavailable");
                digest.update(buf,0,len);addr = addr.add(len);n -= len;
            }
        }
        return digest.digest();
    }

    private static String decompile(DecompInterface decompiler, Function f, TaskMonitor monitor)
            throws Exception {
        DecompileResults result = decompiler.decompileFunction(f,35,monitor);
        if (!result.decompileCompleted() || result.getDecompiledFunction()==null)
            throw new IllegalStateException("Native generated C unavailable at "+f.getEntryPoint());
        String code = result.getDecompiledFunction().getC();
        if (code.isBlank() || code.contains("halt_baddata"))
            throw new IllegalStateException("Incomplete source-native Analyzer C at "+f.getEntryPoint());
        return code;
    }

    private record Stats(int successes,int overlaps,int semanticWarnings,int warningFunctions,int loops) {}

    private static Stats stats(Map<Function,String> map) {
        int overlaps=0,semantic=0,warns=0,loops=0;
        for(String code:map.values()) {
            boolean overlap=false,other=false;
            for(String line:code.split("\\n"))if(line.contains("WARNING:")){
                if(line.contains(WARNING)) overlap=true;else other=true;
            }
            overlaps+=overlap?1:0;semantic+=other?1:0;
            warns+=overlap||other?1:0;
            loops+=code.split("do \\{",-1).length-1;
        }
        return new Stats(map.size(),overlaps,semantic,warns,loops);
    }

    private static Map<Function,String> cAll(Program p,TaskMonitor monitor)throws Exception {
        Map<Function,String> result=new LinkedHashMap<>();
        DecompInterface decompiler=new DecompInterface();
        try {
            if(!decompiler.openProgram(p))throw new IllegalStateException("Native C backend unavailable");
            for(Function f:p.getFunctionManager().getFunctions(true)){
                monitor.checkCancelled();
                if(f.isExternal())continue;
                if(result.size() >= MAX_FUNCTIONS)throw new IllegalStateException("Native C inventory exceeds bound");
                result.put(f,decompile(decompiler,f,monitor));
            }
        } finally {decompiler.dispose();}
        return result;
    }

    private static boolean sourceProvesDm16(Program p,TaskMonitor monitor) throws CancelledException {
        AddressSpace dm=p.getAddressFactory().getAddressSpace("DM");
        if(dm==null||dm.getAddressableUnitSize()!=2) return false;
        int id=dm.getSpaceID();
        for(Instruction ins:p.getListing().getInstructions(true)){
            monitor.checkCancelled();
            if(!"PM".equals(ins.getAddress().getAddressSpace().getName()))continue;
            for(PcodeOp op:ins.getPcode()){
                int c=op.getOpcode();
                if(c!=PcodeOp.LOAD&&c!=PcodeOp.STORE)continue;
                if(op.getNumInputs()<2||!op.getInput(0).isConstant()||
                   op.getInput(0).getOffset()!=id)continue;
                int width=c==PcodeOp.LOAD
                  ?(op.getOutput()==null?0:op.getOutput().getSize())
                  :(op.getNumInputs()>=3?op.getInput(2).getSize():0);
                if(width==2)return true;
            }
        }
        return false;
    }

    public static boolean applyAfterSavedAnalysis(Program p,TaskMonitor monitor,MessageLog log)
            throws CancelledException {
        if(p==null||!SunplusNativeCeAutoAnalyzer.LANGUAGE.equals(p.getLanguageID().getIdAsString()))
            return true;
        if(p.isChanged()){
            log.appendMsg("Sunplus native DM16","Refusing unsafe unsaved input");return false;
        }
        try {return run(p,monitor,log);}
        catch(CancelledException e){throw e;}
        catch(Exception failure){
            log.appendMsg("Sunplus native DM16","Typed DM recovery rejected: "+failure+
                " cleanAfterRollback="+!p.isChanged());
            return false;
        }
    }

    private static boolean run(Program p,TaskMonitor monitor,MessageLog log) throws Exception {
        if(!sourceProvesDm16(p,monitor))return true;
        Map<Function,String> before=cAll(p,monitor);
        Stats baseline=stats(before);
        if(baseline.overlaps()==0)return true;
        AddressSpace dm=p.getAddressFactory().getAddressSpace("DM");
        Listing listing=p.getListing();Memory memory=p.getMemory();
        SortedSet<Integer> words=new TreeSet<>();
        for(String code:before.values()){
            if(!code.contains(WARNING))continue;
            Matcher matcher=SYMBOL.matcher(code);
            while(matcher.find()){
                int word=Integer.parseInt(matcher.group(1),16);
                Address address=at(dm,word);
                MemoryBlock block=memory.getBlock(address);
                if(block!=null&&(block.isInitialized()||block.isVolatile()||
                    !block.isRead()||!block.isWrite()))continue;
                Data data=listing.getDataContaining(address);
                if(data!=null&&(!data.getAddress().equals(address)||
                    data.getLength()!=1||!"undefined".equals(data.getDataType().getName())))continue;
                Symbol symbol=p.getSymbolTable().getPrimarySymbol(address);
                if(symbol!=null&&symbol.getSource()==SourceType.USER_DEFINED)continue;
                words.add(word);
                if(words.size()>MAX_CELLS){
                    log.appendMsg("Sunplus native DM16","Too many source DM symbols, skip");
                    return true;
                }
            }
        }
        // C can hide an undersized symbol after an earlier recovery pass:
        // the remaining warning need not print the leading-underscore name.
        // Use only the *original instruction* P-code for exact constant DM
        // 16-bit LOAD/STORE addresses in functions still reporting overlap.
        // This is the same source evidence as the read-only Java DM audit.
        int pcodeProven = 0;
        int dmSpaceId = dm.getSpaceID();
        for (var owner : before.entrySet()) {
            if (!owner.getValue().contains(WARNING)) continue;
            for (Instruction ins : listing.getInstructions(owner.getKey().getBody(), true)) {
                monitor.checkCancelled();
                if (!"PM".equals(ins.getAddress().getAddressSpace().getName())) continue;
                for (PcodeOp op : ins.getPcode()) {
                    int operation = op.getOpcode();
                    if (operation != PcodeOp.LOAD && operation != PcodeOp.STORE) continue;
                    if (op.getNumInputs() < 2 || !op.getInput(0).isConstant() ||
                        op.getInput(0).getOffset() != dmSpaceId ||
                        !op.getInput(1).isConstant()) continue;
                    int width = operation == PcodeOp.LOAD
                        ? (op.getOutput() == null ? 0 : op.getOutput().getSize())
                        : (op.getNumInputs() >= 3 ? op.getInput(2).getSize() : 0);
                    if (width != 2) continue;
                    long originalWord = op.getInput(1).getOffset();
                    if (originalWord < 0 || originalWord > 0xffff) continue;
                    int word = (int) originalWord;
                    if (words.contains(word)) continue;
                    Address address = at(dm, word);
                    MemoryBlock block = memory.getBlock(address);
                    if (block != null && (block.isInitialized() || block.isVolatile() ||
                        !block.isRead() || !block.isWrite())) continue;
                    Data data = listing.getDataContaining(address);
                    if (data != null && (!data.getAddress().equals(address) ||
                        data.getLength() != 1 ||
                        !"undefined".equals(data.getDataType().getName()))) continue;
                    Symbol symbol = p.getSymbolTable().getPrimarySymbol(address);
                    // The original ISA LOAD/STORE proves a 16-bit DM cell
                    // even when Ghidra omitted its primary symbol. Requiring
                    // a generated symbol here discards exactly the missing-
                    // owner cells responsible for residual overlap C output.
                    // Explicit user symbols or conflicting alias origins stay
                    // protected; unreferenced/guessed cells are never added.
                    if (symbol != null &&
                        (symbol.getSource() == SourceType.USER_DEFINED ||
                         !symbol.getAddress().equals(address))) continue;
                    words.add(word);
                    pcodeProven++;
                    if (words.size() > MAX_CELLS) {
                        log.appendMsg("Sunplus native DM16","Too many source DM cells, skip");
                        return true;
                    }
                }
            }
        }
        if (pcodeProven > 0)
            log.appendMsg("Sunplus native DM16",
                "Additional exact 2-byte constant-address DM P-code proofs="+pcodeProven);
        if(words.isEmpty()){
            log.appendMsg("Sunplus native DM16","No safe native DM16 candidates from C overlap warning");
            return true;
        }
        Map<Function,String> identities=new LinkedHashMap<>();
        for(Function f:before.keySet())
            identities.put(f,f.getName()+"/"+f.getBody()+"/"+f.hasNoReturn());
        byte[] image=initializedHash(p,monitor);
        int transaction=p.startTransaction("Architectural 16-bit sparse DM typing from original C/Pcode");
        boolean accepted=false;
        try {
            // Only contiguous, source-referenced DM words are mapped. Never
            // initialize physical memory, fabricate MMIO owner, or mark volatile.
            Integer runStart=null,runEnd=null;int blocks=0;
            for(int word:words){
                if(memory.getBlock(at(dm,word))!=null){
                    if(runStart!=null){createBlock(memory,dm,runStart,runEnd);blocks++;runStart=null;runEnd=null;}
                    continue;
                }
                if(runStart==null){runStart=word;runEnd=word;}
                else if(word==runEnd+1){runEnd=word;}
                else {createBlock(memory,dm,runStart,runEnd);blocks++;runStart=word;runEnd=word;}
            }
            if(runStart!=null){createBlock(memory,dm,runStart,runEnd);blocks++;}
            for(int word:words){
                monitor.checkCancelled();Address address=at(dm,word);
                Data existing=listing.getDataContaining(address);
                if(existing!=null&&existing.getLength()==1&&
                   "undefined".equals(existing.getDataType().getName()))
                    listing.clearCodeUnits(address,address.add(1),false);
                Data data=listing.createData(address,Undefined2DataType.dataType);
                if(data==null||data.getLength()!=2)throw new IllegalStateException("Invalid native DM16 at "+address);
            }
            if(!Arrays.equals(image,initializedHash(p,monitor)))
                throw new IllegalStateException("Firmware image modified by DM layout");
            for(var e:identities.entrySet()){
                Function f=e.getKey();
                if(!e.getValue().equals(f.getName()+"/"+f.getBody()+"/"+f.hasNoReturn()))
                    throw new IllegalStateException("Native function identity changed "+f.getEntryPoint());
            }
            Stats result=stats(cAll(p,monitor));
            log.appendMsg("Sunplus native DM16", "Original overlap warnings "+baseline.overlaps()+
                ", after="+result.overlaps()+", words="+words.size()+", runs="+blocks);
            if(result.successes()!=baseline.successes()||result.overlaps()>=baseline.overlaps()||
               result.semanticWarnings()>baseline.semanticWarnings()||
               result.warningFunctions()>baseline.warningFunctions()||result.loops()<baseline.loops())
                throw new IllegalStateException("Native C/warning semantic quality gate failed");
            accepted=true;
        }
        finally {p.endTransaction(transaction,accepted);}
        return true;
    }

    private static void createBlock(Memory memory,AddressSpace dm,int start,int end) throws Exception {
        var block=memory.createUninitializedBlock(
            String.format("SUNPLUS_DM16_%04x_%04x",start,end),at(dm,start),
            (long)(end-start+1)*2L,false);
        block.setRead(true);block.setWrite(true);
        block.setComment("Native 16-bit DM word references; physical RAM/MMIO ownership UNKNOWN");
    }
}
