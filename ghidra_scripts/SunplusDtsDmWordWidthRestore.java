// Strictly bounded, transactional 16-bit DM cell metadata materialization.
// Input is exact DSP target evidence; import on an isolated 103-function GZF first.\n// NOT an automatic postprocessor, firmware mutation, or hardware RAM/MMIO claim.
// Physical RAM, MMIO, read latency, hardware side effects remain UNKNOWN.
//@category Sunplus/Regression
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.math.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.HexFormat;
public class SunplusDtsDmWordWidthRestore extends GhidraScript {
 private Address dm(int w){return currentProgram.getAddressFactory().getAddress(String.format("DM:%04x",w));}
 private Address pm(int w){return currentProgram.getAddressFactory().getAddress(String.format("PM:%04x",w));}
 private String digest(byte[] raw)throws Exception{
   return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
 }
 private String initializedSha()throws Exception{
   MessageDigest dig=MessageDigest.getInstance("SHA-256");
   byte[] buf=new byte[8192];
   for(MemoryBlock b:currentProgram.getMemory().getBlocks()){
     if(!b.isInitialized())continue;
     Address a=b.getStart();long left=b.getSize();
     while(left>0){int n=(int)Math.min(left,buf.length);
       if(currentProgram.getMemory().getBytes(a,buf,0,n)!=n)throw new IllegalStateException("Native byte read error");
       dig.update(buf,0,n);a=a.add(n);left-=n;
     }
   }
   return HexFormat.of().formatHex(dig.digest());
 }
 private String nativeBodies(){
   StringBuilder sb=new StringBuilder();
   for(Function f:currentProgram.getFunctionManager().getFunctions(true))
     sb.append(f.getEntryPoint()).append(':').append(f.getName()).append(':').append(f.getBody()).append('\n');
   return sb.toString();
 }
 private String c(Function f)throws Exception{
   DecompInterface d=new DecompInterface();
   try{
     d.toggleCCode(true);d.setSimplificationStyle("decompile");
     if(!d.openProgram(currentProgram))throw new IllegalStateException("Decompiler init failed");
     DecompileResults r=d.decompileFunction(f,45,monitor);
     if(!r.decompileCompleted()||r.getDecompiledFunction()==null)
       throw new IllegalStateException("C generation failed "+f.getEntryPoint()+" "+r.getErrorMessage());
     return r.getDecompiledFunction().getC();
   }finally{d.dispose();}
 }
 private int warningCount(String c){return c.split("WARNING:",-1).length-1;}
 private int doCount(String c){return c.split("do \\{",-1).length-1;}
 @Override public void run()throws Exception{
   if(currentProgram==null||!"dts-profile.bin".equals(currentProgram.getName())||
      !"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString())||
      currentProgram.getFunctionManager().getFunctionCount()!=103)
     throw new IllegalStateException("Wrong target image/language/inventory");
   String[] argv=getScriptArgs();
   if(argv.length!=1)throw new IllegalArgumentException("Required exact saved native overlap manifest");
   byte[] manifest=Files.readAllBytes(Path.of(argv[0]));
   if(!digest(manifest).equals("9cc8e6a1fd7838773c170d9225cd02d7b95e67d18e5fd4027fce8b29fab27643"))
     throw new IllegalStateException("Manifest checksum does not match 625 validated overlap events");
   List<String> lines=Files.readAllLines(Path.of(argv[0]));
   ArrayList<Integer> words=new ArrayList<>();
   for(String line:lines){
     if(!line.matches("[0-9a-f]{4}"))throw new IllegalStateException("Invalid manifest entry: "+line);
     int w=Integer.parseInt(line,16);
     if(!words.isEmpty()&&w<=words.get(words.size()-1))throw new IllegalStateException("Unsorted/duplicate manifest");
     words.add(w);
   }
   if(words.size()!=317)throw new IllegalStateException("Wrong overlap inventory: "+words.size());
   int[] proofFuncs={0x0376,0x179c,0x03d7,0x1bf9,0x1a5c,0x1a98,0x1f39,0x2033};
   Function[] funcs=new Function[proofFuncs.length];
   int[] beforeDo=new int[proofFuncs.length];
   for(int i=0;i<proofFuncs.length;i++){
     funcs[i]=currentProgram.getFunctionManager().getFunctionAt(pm(proofFuncs[i]));
     if(funcs[i]==null)throw new IllegalStateException("Missing proof function PM:"+Integer.toHexString(proofFuncs[i]));
     String oldC=c(funcs[i]);
     if(warningCount(oldC)!=1)throw new IllegalStateException("Proof owner baseline C warning mismatch "+funcs[i].getEntryPoint());
     beforeDo[i]=doCount(oldC);
   }
   for(int w:words){
     monitor.checkCancelled();
     Address a=dm(w);
     if(a.getAddressSpace().getAddressableUnitSize()!=2||
        currentProgram.getMemory().getBlock(a)!=null||
        currentProgram.getListing().getDataContaining(a)!=null)
       throw new IllegalStateException("Not an absent 2-byte DM cell: "+a);
     Symbol sym=currentProgram.getSymbolTable().getPrimarySymbol(a);
     if(sym==null||sym.getSource()!=SourceType.DEFAULT||
        !sym.getName().equals(String.format("DAT_DM_%04x",w)))
       throw new IllegalStateException("Existing label not a matching auto-generated DAT_DM symbol: "+a);
   }
   String bytes=initializedSha(),bodies=nativeBodies();
   if(!bytes.equals("6f7af5491b3d174382a9a12a7a96b9cdfdc81b0414a296e620087c25a42df3d1"))
     throw new IllegalStateException("Original initialized memory differs from verified canonical DTS");
   int tx=currentProgram.startTransaction("317 source-proven 16-bit DSP DM cells, uninitialized undefined2");
   boolean commit=false;
   try{
     Memory m=currentProgram.getMemory();
     Listing listing=currentProgram.getListing();
     int i=0,createdRuns=0,createdWords=0;
     while(i<words.size()){
       monitor.checkCancelled();
       int first=words.get(i);
       int last=first;
       int j=i+1;
       while(j<words.size()&&words.get(j)==last+1){last=words.get(j);j++;}
       String blockName=String.format("R24_DM_SOURCEPROVEN_%04x_%04x",first,last);
       MemoryBlock block=m.createUninitializedBlock(blockName,dm(first),(long)(last-first+1)*2L,false);
       block.setRead(true);block.setWrite(true);
       block.setComment("Only 16-bit DM word storage width/source use proven; not a RAM/MMIO/peripheral owner claim.");
       if(block.isInitialized()||block.getSize()!=(long)(last-first+1)*2L)
         throw new IllegalStateException("DM block storage contract mismatch "+blockName);
       createdRuns++;
       for(int k=i;k<j;k++){
         int w=words.get(k);
         Address at=dm(w);
         Data typed=listing.createData(at,Undefined2DataType.dataType);
         if(typed==null||typed.getLength()!=2||
           !typed.getDataType().getName().equals("undefined2"))
           throw new IllegalStateException("Failed 2-byte undefined data at "+at);
         Symbol label=currentProgram.getSymbolTable().getPrimarySymbol(at);
         if(label==null||label.getSource()!=SourceType.DEFAULT||
           !label.getName().equals(String.format("DAT_DM_%04x",w)))
           throw new IllegalStateException("Existing DAT_DM label was renamed/altered "+at);
         createdWords++;
       }
       i=j;
     }
     if(createdRuns!=76||createdWords!=317)
       throw new IllegalStateException("Unexpected materialization: runs="+createdRuns+" words="+createdWords);
     if(!bytes.equals(initializedSha())||!bodies.equals(nativeBodies()))
       throw new IllegalStateException("PM/native initialized bytes or function names/bounds altered");
     for(int k=0;k<proofFuncs.length;k++){
       String afterC=c(funcs[k]);
       int warnings=warningCount(afterC);
       if(warnings!=0||doCount(afterC)!=beforeDo[k]||afterC.contains("halt_baddata"))
         throw new IllegalStateException("Changed semantic warning/do count at "+funcs[k].getEntryPoint()+" warnings="+warnings);
       println("R24_DM317_C_OWNER "+funcs[k].getEntryPoint()+" warnings=0 do="+doCount(afterC)+" length="+afterC.length());
     }
     println("R24_DM317_CREATED bytes_unchanged=true labels_preserved=true functions_unchanged=true words="+createdWords+" runs="+createdRuns);
     commit=true;
   }finally{currentProgram.endTransaction(tx,commit);}
   if(!commit)throw new IllegalStateException("DM width transaction rolled back");
   println("R24_DM317_GUARDED_REPAIR=PASS");
 }
}
