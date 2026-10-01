// Runtime decode acceptance for SunplusSPHEAudioDSP.
// The imported fixture contains, in order:
//   0x19820F -> JUMP $1820
//   0x0A000F -> RTS
//   0x80023A -> AR = DM($0023)
//   0x80021A -> AR = DM($0021)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class SunplusDSPDecodeSmoke extends GhidraScript {
    private Instruction decode(long wordAddress) throws Exception {
        var pm = currentProgram.getAddressFactory().getAddressSpace("PM");
        Address address = pm.getAddress(wordAddress * pm.getAddressableUnitSize());
        if (!disassemble(address)) {
            throw new AssertionError("Disassembly failed at " + address);
        }
        Instruction instruction = currentProgram.getListing().getInstructionAt(address);
        if (instruction == null) {
            throw new AssertionError("No instruction created at " + address);
        }
        println(address + " " + instruction);
        return instruction;
    }

    private void requireMnemonic(Instruction instruction, String expected) {
        String actual = instruction.getMnemonicString();
        if (!expected.equals(actual)) {
            throw new AssertionError(
                "Expected " + expected + " at " + instruction.getAddress() +
                ", got " + actual + " (" + instruction + ")");
        }
    }

    private void requireDmRead(Instruction instruction, long expectedAddress) {
        requireMnemonic(instruction, "DMREAD");
        String text = instruction.toString();
        if (!text.contains("AR")) {
            throw new AssertionError("Expected AR destination, got: " + text);
        }
        Scalar scalar = instruction.getScalar(1);
        if (scalar == null || scalar.getUnsignedValue() != expectedAddress) {
            throw new AssertionError(
                "Expected DM address 0x" + Long.toHexString(expectedAddress) +
                ", got: " + text);
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new AssertionError("No current program");
        }
        if (!"SunplusSPHEAudioDSP:BE:16:default".equals(
                currentProgram.getLanguageID().getIdAsString())) {
            throw new AssertionError("Unexpected language: " + currentProgram.getLanguageID());
        }

        Instruction jump = decode(0);
        requireMnemonic(jump, "JUMP");
        Address[] flows = jump.getFlows();
        long unitSize = flows.length == 0 ? 1 : flows[0].getAddressSpace().getAddressableUnitSize();
        long targetWordAddress = flows.length == 0 ? -1 : flows[0].getOffset() / unitSize;
        if (flows.length != 1 || targetWordAddress != 0x1820L) {
            throw new AssertionError("Expected JUMP target PM:1820, got: " + jump +
                " rawFlow=" + (flows.length == 0 ? "<none>" : flows[0]));
        }

        requireMnemonic(decode(1), "RTS");
        requireDmRead(decode(2), 0x23L);
        requireDmRead(decode(3), 0x21L);

        println("SUNPLUS_DSP_DECODE_SMOKE=PASS");
    }
}
