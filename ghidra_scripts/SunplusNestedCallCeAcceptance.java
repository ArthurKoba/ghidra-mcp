// Isolated native-code CALL/RTS and CE-loop emulator tests.
// Proves bounded synthetic call-return and counter stacks, not silicon PC-stack fidelity.
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import java.math.BigInteger;

public class SunplusNestedCallCeAcceptance extends GhidraScript {
    private Address pm(long w) {
        return currentProgram.getAddressFactory().getAddress("PM:" + Long.toHexString(w));
    }
    @Override public void run() throws Exception {
        boolean twoCalls = "nested_ce_call_2stage.bin".equals(currentProgram.getName());
        if (!twoCalls && !"nested_ce_call_2x3.bin".equals(currentProgram.getName()))
            throw new IllegalStateException("Unexpected fixture");
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(
                currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("Unexpected ISA");
        int tx=currentProgram.startTransaction("Temporary native nested call fixture");
        try {
            Register nested = currentProgram.getProgramContext().getRegister("codec_ce_nested_mode");
            Register ceEnd = currentProgram.getProgramContext().getRegister("codec_ce_loop_end");
            if (nested == null || ceEnd == null)
                throw new IllegalStateException("Required CE context fields missing");
            long[] nestedWords = twoCalls ?
                new long[]{0x301,0x302,0x305,0x309,0x30a,0x30d,0x30e,0x30f,0x310} :
                new long[]{0x301,0x302,0x305,0x309,0x30a,0x30b,0x30c};
            for(long w:nestedWords)
                currentProgram.getProgramContext().setValue(nested,pm(w),pm(w),BigInteger.ONE);
            disassemble(pm(0x300));
            for(long w=0x300;w<=(twoCalls?0x310:0x30c);w++) {
                if(currentProgram.getListing().getInstructionAt(pm(w))==null)
                    disassemble(pm(w));
                if(currentProgram.getListing().getInstructionAt(pm(w))==null)
                    throw new IllegalStateException("Missing fixture instruction at " + pm(w));
            }
            for(long w:new long[]{0x305,twoCalls?0x30f:0x30b}) {
                clearListing(pm(w),pm(w));
                currentProgram.getProgramContext().setValue(ceEnd,pm(w),pm(w),BigInteger.ONE);
                if(!disassemble(pm(w))) throw new IllegalStateException("CE end decode failed");
                int dec=0,cb=0,ind=0;
                for(PcodeOp op:currentProgram.getListing().getInstructionAt(pm(w)).getPcode()) {
                    if(op.getOpcode()==PcodeOp.INT_SUB)dec++;
                    if(op.getOpcode()==PcodeOp.CBRANCH)cb++;
                    if(op.getOpcode()==PcodeOp.BRANCHIND)ind++;
                }
                if(dec==0 || cb==0 || ind==0)
                    throw new IllegalStateException("CE end lacks expected P-code at "+pm(w));
            }
            Instruction call=currentProgram.getListing().getInstructionAt(pm(0x302));
            Instruction ret=currentProgram.getListing().getInstructionAt(pm(twoCalls?0x310:0x30c));
            Instruction secondCall = twoCalls?currentProgram.getListing().getInstructionAt(pm(0x309)):null;
            if(!call.toString().contains("CALL 0x0309") || !"RTS".equals(ret.getMnemonicString()) ||
               (twoCalls && !secondCall.toString().contains("CALL 0x030d")))
                throw new IllegalStateException("Native interprocedural flow not decoded");
            EmulatorHelper emulator=new EmulatorHelper(currentProgram);
            try {
                emulator.writeRegister("PC",0x300);
                // No seeded return address: nested-mode CALL must push and RTS must pop.
                emulator.writeRegister("DSP_CALL_DEPTH",0);
                emulator.writeRegister("PCSTACKTOP",0);
                emulator.writeRegister("CNTR",0);
                emulator.writeRegister("DSP_LOOP_DEPTH",0);
                emulator.writeRegister("DSP_COUNT_DEPTH",0);
                emulator.writeRegister("DSP_LOOP_START",0);
                int calls=0,childCalls=0,returns=0,childReturns=0,inner=0,outer=0,steps=0;
                while(steps<85) {
                    Address at=emulator.getExecutionAddress();
                    if(at==null)throw new IllegalStateException("Null PC");
                    if(at.equals(pm(0x302)))calls++;
                    if(twoCalls && at.equals(pm(0x309)))childCalls++;
                    if(twoCalls && at.equals(pm(0x30a))) {
                        childReturns++;
                        if(emulator.readRegister("DSP_CALL_DEPTH").intValue()!=1)
                            throw new IllegalStateException("Nested call return did not pop one frame");
                    }
                    if(at.equals(pm(0x303))) {
                        returns++;
                        int expected=returns==1?2:1;
                        int actual=emulator.readRegister("CNTR").intValue();
                        if(actual!=expected)
                            throw new IllegalStateException("CNTR restored wrong across CALL: "+
                                actual+" vs "+expected);
                        if(emulator.readRegister("DSP_LOOP_DEPTH").intValue()!=1 ||
                           emulator.readRegister("DSP_COUNT_DEPTH").intValue()!=0)
                            throw new IllegalStateException("Nested stacks did not unwind at return");
                    }
                    if(at.equals(pm(twoCalls?0x30f:0x30b)))inner++;
                    if(at.equals(pm(0x305)))outer++;
                    if(at.equals(pm(0x306)))break;
                    emulator.setContextRegister(nested, BigInteger.ONE);
                    if(!emulator.step(monitor))
                        throw new IllegalStateException("Emulator failed: "+emulator.getLastError());
                    steps++;
                }
                int depth=emulator.readRegister("DSP_LOOP_DEPTH").intValue();
                int countDepth=emulator.readRegister("DSP_COUNT_DEPTH").intValue();
                int callDepth=emulator.readRegister("DSP_CALL_DEPTH").intValue();
                println("CROSS_CALL_CE_RESULTS fixture="+currentProgram.getName()+
                    " calls="+calls+" nestedCalls="+childCalls+" returns="+returns+
                    " nestedReturns="+childReturns+" inner="+inner+" outer="+outer+" steps="+steps+
                    " loopDepth="+depth+" countDepth="+countDepth+" callDepth="+callDepth);
                if(calls!=2||returns!=2||inner!=6||outer!=2||
                   (twoCalls && (childCalls!=2||childReturns!=2))||
                   depth!=0||countDepth!=0||callDepth!=0||steps>=85)
                    throw new IllegalStateException("Cross-CALL CE contract failed");
                println("CROSS_CALL_CE_PCODE_RETURN_ACCEPTANCE=PASS "+currentProgram.getName());
            } finally {emulator.dispose();}
        } finally {currentProgram.endTransaction(tx,false);}
    }
}
