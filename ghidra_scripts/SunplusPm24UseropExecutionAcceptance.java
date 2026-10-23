// Isolated 24-bit PM P-code userop execution contract test on local Ghidra.
// Simulates full 24-bit program-memory state, including write-read aliasing.
// No canonical Ghidra Program / firmware bytes are modified.
//@category Sunplus/Regression
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import java.util.Arrays;

public class SunplusPm24UseropExecutionAcceptance extends GhidraScript {
 private void need(boolean b,String m){if(!b)throw new IllegalStateException(m);}
 public final class Pm24Library extends AnnotatedPcodeUseropLibrary<byte[]> {
  private final SleighLanguage lang;
  private final AddressSpace pm;
  private int loads=0,stores=0;
  private Pm24Library(SleighLanguage l){lang=l;pm=l.getAddressFactory().getAddressSpace("PM");}
  private long wordOffset(byte[] addr){
   if(addr.length!=2)throw new IllegalStateException("PM word addresses must be 16-bit");
   return Utils.bytesToLong(addr,addr.length,lang.isBigEndian()) & 0xffffL;
  }
  @PcodeUserop(hasSideEffects=true)
  public byte[] dsp_pm_load24(@OpExecutor PcodeExecutor<byte[]> e, byte[] wordAddr){
   loads++;return e.getState().getVar(pm,wordOffset(wordAddr),3,true,e.getReason());
  }
  @PcodeUserop(hasSideEffects=true)
  public void dsp_pm_store24(@OpExecutor PcodeExecutor<byte[]> e,byte[] wordAddr,byte[] word){
   if(word.length!=3)throw new IllegalStateException("PM data values must be full 24-bit");
   stores++;e.getState().setVar(pm,wordOffset(wordAddr),3,true,word);
  }
 }
 public void run()throws Exception {
  need(currentProgram!=null&&"SunplusSPHEAudioDSP:BE:16:default".equals(currentProgram.getLanguageID().getIdAsString()),"Must use local native Sunplus DSP language");
  SleighLanguage lang=(SleighLanguage)currentProgram.getLanguage();
  AddressSpace pm=lang.getAddressFactory().getAddressSpace("PM");
  need(pm!=null&&pm.getAddressableUnitSize()==3,"Expected 24-bit PM word-addressed memory");
  Pm24Library lib=new Pm24Library(lang);
  PcodeEmulator emulator=new PcodeEmulator(lang){
   @Override protected PcodeUseropLibrary<byte[]> createUseropLibrary(){return lib;}
  };
  PcodeThread<byte[]> thread=emulator.newThread();
  byte[] original={ (byte)0xab,(byte)0xcd,(byte)0xe7 };
  emulator.getSharedState().setVar(pm,0x0200L,3,true,original);
  PcodeUseropLibrary<byte[]> bound=thread.getUseropLibrary();
  PcodeProgram prog=SleighProgramCompiler.compileProgram(lang,"pm24-contract","""
   local src:2 = 0x0200;
   local value:3 = dsp_pm_load24(src);
   dsp_pm_store24(0x0201:2,value);
   dsp_pm_store24(0x0200:2,0x123456:3);
   local replaced:3 = dsp_pm_load24(0x0200:2);
   dsp_pm_store24(0x0202:2,replaced);
   """,bound);
  thread.getExecutor().execute(prog,bound);
  byte[] copied=emulator.getSharedState().getVar(pm,0x0201L,3,true,Reason.INSPECT);
  byte[] overwritten=emulator.getSharedState().getVar(pm,0x0200L,3,true,Reason.INSPECT);
  byte[] aliased=emulator.getSharedState().getVar(pm,0x0202L,3,true,Reason.INSPECT);
  need(Arrays.equals(copied,original),"PM high/low bytes truncated or word address mistreated");
  need(Arrays.equals(overwritten,new byte[]{0x12,0x34,0x56}),"PM overwrite failed");
  need(Arrays.equals(aliased,overwritten),"PM read-after-write aliasing failed");
  need(lib.loads==2&&lib.stores==3,"Expected 2 loads and 3 writes");
  println("SUNPLUS_PM24_USEROP_EXECUTION_ACCEPTANCE=PASS loads="+lib.loads+" stores="+lib.stores+" bytes=3 pm_word_unit=3 roundtrip_initial_hex="+String.format("%02x%02x%02x",original[0]&255,original[1]&255,original[2]&255)+" aliases_preserved=true isolated=true");
 }
}
