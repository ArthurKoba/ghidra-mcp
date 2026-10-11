// Read-only differential EmulatorHelper regression on real PCM native words.
// Compare generic SE-dependent shift execution with opt-in proven-negative SE.
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SunplusSeNegativeArithmeticAcceptance extends GhidraScript {
    private Address pm(long word) {
        return currentProgram.getAddressFactory().getAddress(
            "PM:" + Long.toHexString(word));
    }
    private Address dm(long word) {
        return currentProgram.getAddressFactory().getAddress(
            "DM:" + Long.toHexString(word));
    }
    private String execute(long word, int se, int sample,
                           boolean specialized, Register negative) throws Exception {
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            emu.writeRegister("PC", word);
            emu.writeRegister("SE", se);
            emu.writeRegister("AR", sample);
            emu.writeRegister("SR0", sample);
            emu.writeRegister("SR1", 0x6d2a);
            emu.writeRegister("MY0", 0x0123);
            emu.writeRegister("I0", 0x340);
            emu.writeRegister("I1", 0x342);
            emu.writeRegister("I2", 0x344);
            emu.writeRegister("M1", 1);
            emu.writeRegister("M3", 1);
            emu.writeMemoryValue(dm(0x340),2,0x1357);
            emu.writeMemoryValue(dm(0x342),2,0x2468);
            emu.writeMemoryValue(dm(0x344),2,0x7654);
            emu.setContextRegister(negative,
                specialized?BigInteger.ONE:BigInteger.ZERO);
            if(!emu.step(monitor)) {
                throw new IllegalStateException("Emulator failed PM:"
                    + Long.toHexString(word) + " " + emu.getLastError());
            }
            StringBuilder result=new StringBuilder();
            for(String reg : new String[]{
                "SR0","SR1","AR","MY0","I0","I1","I2","SE"}) {
                result.append(reg).append('=')
                    .append(emu.readRegister(reg).toString(16))
                    .append(';');
            }
            for(long a : new long[]{0x340,0x342,0x344}) {
                result.append("DM").append(Long.toHexString(a)).append('=');
                byte[] bytes=emu.readMemory(dm(a),2);
                if(bytes==null||bytes.length!=2) {
                    throw new IllegalStateException("Cannot read DM:"+Long.toHexString(a));
                }
                result.append(String.format("%02x%02x",bytes[0]&0xff,bytes[1]&0xff))
                    .append(';');
            }
            return result.toString();
        }finally{emu.dispose();}
    }
    @Override public void run() throws Exception {
        boolean standalone = "se_negative_type12.bin".equals(currentProgram.getName());
        if((!standalone && !"pcm-profile.bin".equals(currentProgram.getName()))||
           !"SunplusSPHEAudioDSP:BE:16:default".equals(
               currentProgram.getLanguageID().getIdAsString())) {
            throw new IllegalStateException("Wrong PCM fixture");
        }
        Register negative=currentProgram.getProgramContext()
            .getRegister("codec_se_proven_negative");
        if(negative==null)throw new IllegalStateException("No SE mode");
        int compared=0;
        long[] words=standalone
            ? new long[]{0x600,0x601,0x602}
            : new long[]{0x06c1,0x12bb,0x12bc};
        int transaction=currentProgram.startTransaction(
            "Native fixture decode, always rollback");
        try {
        if(standalone) {
            for(long word:words) {
                if(!disassemble(pm(word))) {
                    throw new IllegalStateException("Fixture decode failed " + pm(word));
                }
            }
        }
        for(int index=0;index<words.length;index++) {
            long word=words[index];
            int se=(index==0)?0xffff:0xfffe;
            for(int sample:new int[]{0x0000,0x0001,0x8003,0x7fff,0xffff}) {
                String baseline=execute(word,se,sample,false,negative);
                String optimized=execute(word,se,sample,true,negative);
                if(!baseline.equals(optimized)){
                    println("MISMATCH at PM:"+Long.toHexString(word)
                       + " sample="+Integer.toHexString(sample)
                       + " baseline="+baseline+" optimized="+optimized);
                    throw new IllegalStateException("Shift P-code differential failed");
                }
                compared++;
            }
            println("SE_NEGATIVE_ARITHMETIC_SITE=PASS PM:"
                 +Long.toHexString(word)+" variants=5");
        }
        if(compared!=15)throw new IllegalStateException("Incomplete corpus");
        println("SE_NEGATIVE_ARITHMETIC_ACCEPTANCE=PASS variants="+compared);
        }finally{currentProgram.endTransaction(transaction,false);}
    }
}
