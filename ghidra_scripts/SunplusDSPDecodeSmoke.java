// Runtime decode acceptance for SunplusSPHEAudioDSP.
// The imported fixture contains, in order:
//   0x19820F -> JUMP $1820
//   0x0A000F -> RTS
//   0x80023A -> AR = DM($0023)
//   0x80021A -> AR = DM($0021)
//   0x0A001F -> RTI
//   0x180250 -> IF EQ JUMP $0025
//   0x22E21F -> AR = AR - 1
//   0x0F02F6 -> SR = LSHIFT AR BY -10 (HI)
//   0x0D00AF -> AR = SR1
//   0x18036F -> JUMP $0036 (must stay generic outside srvdsp context)

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

    private void requireText(Instruction instruction, String expectedFragment) {
        String actual = instruction.toString();
        if (!actual.contains(expectedFragment)) {
            throw new AssertionError(
                "Expected text containing '" + expectedFragment + "' at " +
                instruction.getAddress() + ", got: " + actual);
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
        requireMnemonic(decode(4), "RTI");
        requireText(decode(5), "IF EQ JUMP");
        requireText(decode(6), "AR - 1");
        requireText(decode(7), "LSHIFT AR BY -10 (HI)");
        requireText(decode(8), "AR = SR1");

        Instruction genericResidentCollision = decode(9);
        requireMnemonic(genericResidentCollision, "JUMP");
        Address[] genericFlows = genericResidentCollision.getFlows();
        long genericUnitSize = genericFlows.length == 0 ? 1 :
            genericFlows[0].getAddressSpace().getAddressableUnitSize();
        long genericTarget = genericFlows.length == 0 ? -1 :
            genericFlows[0].getOffset() / genericUnitSize;
        if (genericFlows.length != 1 || genericTarget != 0x36L) {
            throw new AssertionError(
                "Expected generic local JUMP target PM:0036, got: " + genericResidentCollision);
        }

        println("SUNPLUS_DSP_DECODE_SMOKE=PASS");
    }
}
